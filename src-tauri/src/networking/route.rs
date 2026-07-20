use std::{collections::HashMap, net::IpAddr};

use serde::{Deserialize, Serialize};

use super::NetworkErrorCode;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSpec {
    pub destination: String,
    pub interface: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingRoute {
    pub destination: String,
    pub interface: String,
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTransactionState {
    Prepared,
    Applied,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteJournalEntry {
    pub transaction_id: String,
    pub profile_id: String,
    pub desired_routes: Vec<RouteSpec>,
    pub applied_routes: Vec<RouteSpec>,
    pub previous_routes: Vec<ExistingRoute>,
    pub state: RouteTransactionState,
}

pub trait RoutePlatform {
    fn list_routes(&mut self) -> Result<Vec<ExistingRoute>, NetworkErrorCode>;
    fn add_route(&mut self, route: &RouteSpec) -> Result<(), NetworkErrorCode>;
    fn remove_route(&mut self, route: &RouteSpec) -> Result<(), NetworkErrorCode>;
}

pub trait RouteJournal {
    fn entries(&self) -> Result<Vec<RouteJournalEntry>, NetworkErrorCode>;
    fn save(&mut self, entry: &RouteJournalEntry) -> Result<(), NetworkErrorCode>;
}

pub struct RouteOrchestrator<P, J> {
    platform: P,
    journal: J,
}

impl<P: RoutePlatform, J: RouteJournal> RouteOrchestrator<P, J> {
    pub const fn new(platform: P, journal: J) -> Self {
        Self { platform, journal }
    }

    pub fn apply(
        &mut self,
        transaction_id: String,
        profile_id: String,
        desired_routes: Vec<RouteSpec>,
    ) -> Result<(), NetworkErrorCode> {
        validate_plan(&transaction_id, &profile_id, &desired_routes)?;
        if let Some(existing) = self
            .journal
            .entries()?
            .into_iter()
            .find(|entry| entry.transaction_id == transaction_id)
        {
            return if existing.profile_id == profile_id
                && existing.desired_routes == desired_routes
                && existing.state == RouteTransactionState::Applied
            {
                Ok(())
            } else {
                Err(NetworkErrorCode::InvalidStateTransition)
            };
        }

        let previous_routes = self.platform.list_routes()?;
        reject_conflicts(&previous_routes, &desired_routes)?;
        let mut entry = RouteJournalEntry {
            transaction_id,
            profile_id,
            desired_routes,
            applied_routes: Vec::new(),
            previous_routes,
            state: RouteTransactionState::Prepared,
        };
        self.journal.save(&entry)?;

        for route in entry.desired_routes.clone() {
            if let Err(error) = self.platform.add_route(&route) {
                return self.rollback_failed_apply(&mut entry, error);
            }
            entry.applied_routes.push(route);
            if self.journal.save(&entry).is_err() {
                return self.rollback_failed_apply(&mut entry, NetworkErrorCode::RouteRollbackFailed);
            }
        }
        entry.state = RouteTransactionState::Applied;
        self.journal.save(&entry)
    }

    pub fn rollback(&mut self, transaction_id: &str) -> Result<(), NetworkErrorCode> {
        let Some(mut entry) = self
            .journal
            .entries()?
            .into_iter()
            .find(|entry| entry.transaction_id == transaction_id)
        else {
            return Ok(());
        };
        if entry.state == RouteTransactionState::RolledBack {
            return Ok(());
        }
        self.rollback_entry(&mut entry)
    }

    pub fn recover_stale(&mut self) -> Result<(), NetworkErrorCode> {
        for mut entry in self.journal.entries()?.into_iter().filter(|entry| {
            matches!(
                entry.state,
                RouteTransactionState::Prepared | RouteTransactionState::Applied
            )
        }) {
            self.rollback_entry(&mut entry)?;
        }
        Ok(())
    }

    fn rollback_failed_apply(
        &mut self,
        entry: &mut RouteJournalEntry,
        original_error: NetworkErrorCode,
    ) -> Result<(), NetworkErrorCode> {
        match self.rollback_entry(entry) {
            Ok(()) => Err(original_error),
            Err(_) => Err(NetworkErrorCode::RouteRollbackFailed),
        }
    }

    fn rollback_entry(&mut self, entry: &mut RouteJournalEntry) -> Result<(), NetworkErrorCode> {
        while let Some(route) = entry.applied_routes.last().cloned() {
            self.platform
                .remove_route(&route)
                .map_err(|_| NetworkErrorCode::RouteRollbackFailed)?;
            entry.applied_routes.pop();
            self.journal
                .save(entry)
                .map_err(|_| NetworkErrorCode::RouteRollbackFailed)?;
        }
        entry.state = RouteTransactionState::RolledBack;
        self.journal
            .save(entry)
            .map_err(|_| NetworkErrorCode::RouteRollbackFailed)
    }
}

fn validate_plan(transaction_id: &str, profile_id: &str, routes: &[RouteSpec]) -> Result<(), NetworkErrorCode> {
    if transaction_id.is_empty() || profile_id.is_empty() || routes.is_empty() {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    let mut parsed = Vec::with_capacity(routes.len());
    for route in routes {
        if route.interface.is_empty() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let network = IpNetwork::parse(&route.destination)?;
        if parsed.iter().any(|existing: &IpNetwork| existing.overlaps(network)) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        parsed.push(network);
    }
    Ok(())
}

fn reject_conflicts(existing: &[ExistingRoute], desired: &[RouteSpec]) -> Result<(), NetworkErrorCode> {
    let desired = desired
        .iter()
        .map(|route| IpNetwork::parse(&route.destination))
        .collect::<Result<Vec<_>, _>>()?;
    for route in existing {
        let existing = IpNetwork::parse(&route.destination)?;
        // A default route is the expected underlay and does not compete with a
        // more-specific KyClash private route.
        if existing.prefix == 0 {
            continue;
        }
        if desired.iter().any(|candidate| candidate.overlaps(existing)) {
            return Err(NetworkErrorCode::RouteConflict);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct IpNetwork {
    bits: u8,
    network: u128,
    prefix: u8,
}

impl IpNetwork {
    fn parse(value: &str) -> Result<Self, NetworkErrorCode> {
        let (address, prefix) = value.rsplit_once('/').ok_or(NetworkErrorCode::InvalidConfiguration)?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        let (bits, value) = match address {
            IpAddr::V4(address) => (32, u128::from(u32::from(address))),
            IpAddr::V6(address) => (128, u128::from(address)),
        };
        if prefix > bits {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (u32::from(bits - prefix))
        };
        Ok(Self {
            bits,
            network: value & mask,
            prefix,
        })
    }

    const fn overlaps(self, other: Self) -> bool {
        if self.bits != other.bits {
            return false;
        }
        let prefix = if self.prefix < other.prefix {
            self.prefix
        } else {
            other.prefix
        };
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << ((self.bits - prefix) as u32)
        };
        self.network & mask == other.network & mask
    }
}

#[derive(Default)]
pub struct MemoryRouteJournal {
    entries: HashMap<String, RouteJournalEntry>,
}

impl RouteJournal for MemoryRouteJournal {
    fn entries(&self) -> Result<Vec<RouteJournalEntry>, NetworkErrorCode> {
        Ok(self.entries.values().cloned().collect())
    }

    fn save(&mut self, entry: &RouteJournalEntry) -> Result<(), NetworkErrorCode> {
        self.entries.insert(entry.transaction_id.clone(), entry.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakePlatform {
        existing: Vec<ExistingRoute>,
        added: Vec<RouteSpec>,
        fail_add_at: Option<usize>,
        fail_remove: bool,
    }

    impl RoutePlatform for FakePlatform {
        fn list_routes(&mut self) -> Result<Vec<ExistingRoute>, NetworkErrorCode> {
            Ok(self.existing.clone())
        }

        fn add_route(&mut self, route: &RouteSpec) -> Result<(), NetworkErrorCode> {
            if self.fail_add_at == Some(self.added.len()) {
                return Err(NetworkErrorCode::PermissionDenied);
            }
            self.added.push(route.clone());
            Ok(())
        }

        fn remove_route(&mut self, route: &RouteSpec) -> Result<(), NetworkErrorCode> {
            if self.fail_remove {
                return Err(NetworkErrorCode::PermissionDenied);
            }
            if let Some(index) = self.added.iter().position(|candidate| candidate == route) {
                self.added.remove(index);
            }
            Ok(())
        }
    }

    fn route(destination: &str) -> RouteSpec {
        RouteSpec {
            destination: destination.into(),
            interface: "utun.test".into(),
        }
    }

    #[test]
    fn applies_and_rolls_back_idempotently() -> Result<(), NetworkErrorCode> {
        let platform = FakePlatform::default();
        let journal = MemoryRouteJournal::default();
        let mut orchestrator = RouteOrchestrator::new(platform, journal);
        let routes = vec![route("10.64.0.0/16"), route("10.127.0.0/16")];
        orchestrator.apply("tx.1".into(), "profile.1".into(), routes.clone())?;
        orchestrator.apply("tx.1".into(), "profile.1".into(), routes)?;
        orchestrator.rollback("tx.1")?;
        orchestrator.rollback("tx.1")?;
        assert!(orchestrator.platform.added.is_empty());
        Ok(())
    }

    #[test]
    fn refuses_overlapping_unowned_route_before_mutation() {
        let platform = FakePlatform {
            existing: vec![ExistingRoute {
                destination: "10.64.1.0/24".into(),
                interface: "other-vpn".into(),
                gateway: None,
            }],
            ..FakePlatform::default()
        };
        let mut orchestrator = RouteOrchestrator::new(platform, MemoryRouteJournal::default());
        assert_eq!(
            orchestrator.apply("tx.1".into(), "profile.1".into(), vec![route("10.64.0.0/16")]),
            Err(NetworkErrorCode::RouteConflict)
        );
        assert!(orchestrator.platform.added.is_empty());
    }

    #[test]
    fn default_underlay_routes_do_not_conflict() -> Result<(), NetworkErrorCode> {
        let platform = FakePlatform {
            existing: vec![
                ExistingRoute {
                    destination: "0.0.0.0/0".into(),
                    interface: "en0".into(),
                    gateway: Some("192.0.2.1".into()),
                },
                ExistingRoute {
                    destination: "::/0".into(),
                    interface: "en0".into(),
                    gateway: Some("fe80::1".into()),
                },
            ],
            ..FakePlatform::default()
        };
        let mut orchestrator = RouteOrchestrator::new(platform, MemoryRouteJournal::default());
        orchestrator.apply(
            "tx.1".into(),
            "profile.1".into(),
            vec![route("10.64.0.0/16"), route("fd00:64::/48")],
        )?;
        Ok(())
    }

    #[test]
    fn failed_apply_removes_only_routes_recorded_as_owned() {
        let platform = FakePlatform {
            fail_add_at: Some(1),
            ..FakePlatform::default()
        };
        let mut orchestrator = RouteOrchestrator::new(platform, MemoryRouteJournal::default());
        assert_eq!(
            orchestrator.apply(
                "tx.1".into(),
                "profile.1".into(),
                vec![route("10.64.0.0/16"), route("10.127.0.0/16")],
            ),
            Err(NetworkErrorCode::PermissionDenied)
        );
        assert!(orchestrator.platform.added.is_empty());
    }

    #[test]
    fn rollback_failure_is_not_hidden() {
        let platform = FakePlatform {
            fail_add_at: Some(1),
            fail_remove: true,
            ..FakePlatform::default()
        };
        let mut orchestrator = RouteOrchestrator::new(platform, MemoryRouteJournal::default());
        assert_eq!(
            orchestrator.apply(
                "tx.1".into(),
                "profile.1".into(),
                vec![route("10.64.0.0/16"), route("10.127.0.0/16")],
            ),
            Err(NetworkErrorCode::RouteRollbackFailed)
        );
    }

    #[test]
    fn recovers_applied_routes_after_restart() -> Result<(), NetworkErrorCode> {
        let mut platform = FakePlatform::default();
        let owned = route("fd00:64::/48");
        platform.added.push(owned.clone());
        let mut journal = MemoryRouteJournal::default();
        journal.save(&RouteJournalEntry {
            transaction_id: "tx.stale".into(),
            profile_id: "profile.1".into(),
            desired_routes: vec![owned.clone()],
            applied_routes: vec![owned],
            previous_routes: Vec::new(),
            state: RouteTransactionState::Applied,
        })?;
        let mut orchestrator = RouteOrchestrator::new(platform, journal);
        orchestrator.recover_stale()?;
        assert!(orchestrator.platform.added.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_overlapping_desired_routes_and_invalid_prefixes() {
        let mut orchestrator = RouteOrchestrator::new(FakePlatform::default(), MemoryRouteJournal::default());
        assert_eq!(
            orchestrator.apply(
                "tx.1".into(),
                "profile.1".into(),
                vec![route("10.0.0.0/8"), route("10.64.0.0/16")],
            ),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
        assert_eq!(
            orchestrator.apply("tx.2".into(), "profile.1".into(), vec![route("10.0.0.0/33")]),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
    }
}
