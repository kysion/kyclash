use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write as _,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

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
    #[serde(default)]
    pub pending_route: Option<RouteSpec>,
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

#[derive(Debug, Clone, Default)]
pub struct RouteConflictPolicy {
    mihomo_tun_interfaces: HashSet<String>,
}

impl RouteConflictPolicy {
    /// Trust only interface names obtained from the active Mihomo TUN
    /// configuration. Interface-name patterns such as `utun*` are deliberately
    /// not inferred because another VPN may own an interface with that shape.
    pub fn with_mihomo_tun_interfaces(interfaces: impl IntoIterator<Item = String>) -> Result<Self, NetworkErrorCode> {
        let interfaces = interfaces.into_iter().collect::<HashSet<_>>();
        if interfaces.iter().any(String::is_empty) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self {
            mihomo_tun_interfaces: interfaces,
        })
    }

    fn permits_more_specific_route(
        &self,
        existing: &ExistingRoute,
        existing_network: IpNetwork,
        desired: IpNetwork,
    ) -> bool {
        self.mihomo_tun_interfaces.contains(&existing.interface) && existing_network.prefix < desired.prefix
    }
}

const ROUTE_JOURNAL_VERSION: u8 = 1;
static ROUTE_JOURNAL_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteJournalDocument {
    version: u8,
    entries: Vec<RouteJournalEntry>,
}

pub struct FileRouteJournal {
    path: PathBuf,
}

impl FileRouteJournal {
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn read_document(&self) -> Result<RouteJournalDocument, NetworkErrorCode> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(NetworkErrorCode::RouteJournalUnavailable);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RouteJournalDocument {
                    version: ROUTE_JOURNAL_VERSION,
                    entries: Vec::new(),
                });
            }
            Err(_) => return Err(NetworkErrorCode::RouteJournalUnavailable),
        }
        let bytes = fs::read(&self.path).map_err(|_| NetworkErrorCode::RouteJournalUnavailable)?;
        let document: RouteJournalDocument =
            serde_json::from_slice(&bytes).map_err(|_| NetworkErrorCode::RouteJournalCorrupted)?;
        if document.version != ROUTE_JOURNAL_VERSION {
            return Err(NetworkErrorCode::RouteJournalCorrupted);
        }
        Ok(document)
    }

    fn write_document(&self, document: &RouteJournalDocument) -> Result<(), NetworkErrorCode> {
        let parent = self.path.parent().ok_or(NetworkErrorCode::RouteJournalUnavailable)?;
        ensure_private_directory(parent)?;
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
            return Err(NetworkErrorCode::RouteJournalUnavailable);
        }

        let temp_path = temporary_journal_path(&self.path);
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp_path)
                .map_err(|_| NetworkErrorCode::RouteJournalUnavailable)?;
            let bytes = serde_json::to_vec_pretty(document).map_err(|_| NetworkErrorCode::RouteJournalUnavailable)?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| NetworkErrorCode::RouteJournalUnavailable)?;
            fs::rename(&temp_path, &self.path).map_err(|_| NetworkErrorCode::RouteJournalUnavailable)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp_path);
        }
        result
    }
}

impl RouteJournal for FileRouteJournal {
    fn entries(&self) -> Result<Vec<RouteJournalEntry>, NetworkErrorCode> {
        Ok(self.read_document()?.entries)
    }

    fn save(&mut self, entry: &RouteJournalEntry) -> Result<(), NetworkErrorCode> {
        let mut document = self.read_document()?;
        if let Some(existing) = document
            .entries
            .iter_mut()
            .find(|candidate| candidate.transaction_id == entry.transaction_id)
        {
            *existing = entry.clone();
        } else {
            document.entries.push(entry.clone());
        }
        document
            .entries
            .sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));
        self.write_document(&document)
    }
}

fn temporary_journal_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    let sequence = ROUTE_JOURNAL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    name.push(format!(".tmp.{}.{sequence}", std::process::id()));
    PathBuf::from(name)
}

fn ensure_private_directory(path: &Path) -> Result<(), NetworkErrorCode> {
    fs::create_dir_all(path).map_err(|_| NetworkErrorCode::RouteJournalUnavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| NetworkErrorCode::RouteJournalUnavailable)?;
    }
    Ok(())
}

pub struct RouteOrchestrator<P, J> {
    platform: P,
    journal: J,
    conflict_policy: RouteConflictPolicy,
}

impl<P: RoutePlatform, J: RouteJournal> RouteOrchestrator<P, J> {
    pub fn new(platform: P, journal: J) -> Self {
        Self {
            platform,
            journal,
            conflict_policy: RouteConflictPolicy {
                mihomo_tun_interfaces: HashSet::new(),
            },
        }
    }

    pub const fn with_conflict_policy(platform: P, journal: J, conflict_policy: RouteConflictPolicy) -> Self {
        Self {
            platform,
            journal,
            conflict_policy,
        }
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
        reject_conflicts(&previous_routes, &desired_routes, &self.conflict_policy)?;
        let mut entry = RouteJournalEntry {
            transaction_id,
            profile_id,
            desired_routes,
            applied_routes: Vec::new(),
            pending_route: None,
            previous_routes,
            state: RouteTransactionState::Prepared,
        };
        self.journal.save(&entry)?;

        for route in entry.desired_routes.clone() {
            entry.pending_route = Some(route.clone());
            if self.journal.save(&entry).is_err() {
                entry.pending_route = None;
                return self.rollback_failed_apply(&mut entry, NetworkErrorCode::RouteJournalUnavailable);
            }
            if let Err(error) = self.platform.add_route(&route) {
                entry.pending_route = None;
                if self.journal.save(&entry).is_err() {
                    return self.rollback_failed_apply(&mut entry, NetworkErrorCode::RouteJournalUnavailable);
                }
                return self.rollback_failed_apply(&mut entry, error);
            }
            entry.applied_routes.push(route);
            entry.pending_route = None;
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
        if let Some(route) = entry.pending_route.take() {
            self.platform
                .remove_route(&route)
                .map_err(|_| NetworkErrorCode::RouteRollbackFailed)?;
            self.journal
                .save(entry)
                .map_err(|_| NetworkErrorCode::RouteRollbackFailed)?;
        }
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

fn reject_conflicts(
    existing: &[ExistingRoute],
    desired: &[RouteSpec],
    policy: &RouteConflictPolicy,
) -> Result<(), NetworkErrorCode> {
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
        for candidate in &desired {
            if candidate.overlaps(existing) && !policy.permits_more_specific_route(route, existing, *candidate) {
                return Err(NetworkErrorCode::RouteConflict);
            }
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

    fn journal_entry(transaction_id: &str, state: RouteTransactionState) -> RouteJournalEntry {
        RouteJournalEntry {
            transaction_id: transaction_id.into(),
            profile_id: "profile.1".into(),
            desired_routes: vec![route("10.64.0.0/16")],
            applied_routes: Vec::new(),
            pending_route: None,
            previous_routes: Vec::new(),
            state,
        }
    }

    #[derive(Default)]
    struct FakePlatform {
        existing: Vec<ExistingRoute>,
        added: Vec<RouteSpec>,
        fail_add_at: Option<usize>,
        fail_remove: bool,
    }

    struct FailingJournal {
        inner: MemoryRouteJournal,
        save_count: usize,
        fail_once_at: usize,
    }

    impl RouteJournal for FailingJournal {
        fn entries(&self) -> Result<Vec<RouteJournalEntry>, NetworkErrorCode> {
            self.inner.entries()
        }

        fn save(&mut self, entry: &RouteJournalEntry) -> Result<(), NetworkErrorCode> {
            let current = self.save_count;
            self.save_count += 1;
            if current == self.fail_once_at {
                return Err(NetworkErrorCode::RouteJournalUnavailable);
            }
            self.inner.save(entry)
        }
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
    fn permits_only_explicit_mihomo_broad_routes_to_coexist() -> Result<(), NetworkErrorCode> {
        let platform = FakePlatform {
            existing: vec![
                ExistingRoute {
                    destination: "8.0.0.0/5".into(),
                    interface: "utun.mihomo".into(),
                    gateway: None,
                },
                ExistingRoute {
                    destination: "fc00::/7".into(),
                    interface: "utun.mihomo".into(),
                    gateway: None,
                },
            ],
            ..FakePlatform::default()
        };
        let policy = RouteConflictPolicy::with_mihomo_tun_interfaces(["utun.mihomo".into()])?;
        let mut orchestrator = RouteOrchestrator::with_conflict_policy(platform, MemoryRouteJournal::default(), policy);
        orchestrator.apply(
            "tx.1".into(),
            "profile.1".into(),
            vec![route("10.64.0.0/16"), route("fd00:64::/48")],
        )?;
        Ok(())
    }

    #[test]
    fn unknown_vpn_broad_route_still_conflicts() -> Result<(), NetworkErrorCode> {
        let platform = FakePlatform {
            existing: vec![ExistingRoute {
                destination: "8.0.0.0/5".into(),
                interface: "utun.other-vpn".into(),
                gateway: None,
            }],
            ..FakePlatform::default()
        };
        let policy = RouteConflictPolicy::with_mihomo_tun_interfaces(["utun.mihomo".into()])?;
        let mut orchestrator = RouteOrchestrator::with_conflict_policy(platform, MemoryRouteJournal::default(), policy);
        assert_eq!(
            orchestrator.apply("tx.1".into(), "profile.1".into(), vec![route("10.64.0.0/16")]),
            Err(NetworkErrorCode::RouteConflict)
        );
        Ok(())
    }

    #[test]
    fn exact_or_more_specific_mihomo_route_still_conflicts() -> Result<(), NetworkErrorCode> {
        for destination in ["10.64.0.0/16", "10.64.1.0/24"] {
            let platform = FakePlatform {
                existing: vec![ExistingRoute {
                    destination: destination.into(),
                    interface: "utun.mihomo".into(),
                    gateway: None,
                }],
                ..FakePlatform::default()
            };
            let policy = RouteConflictPolicy::with_mihomo_tun_interfaces(["utun.mihomo".into()])?;
            let mut orchestrator =
                RouteOrchestrator::with_conflict_policy(platform, MemoryRouteJournal::default(), policy);
            assert_eq!(
                orchestrator.apply("tx.1".into(), "profile.1".into(), vec![route("10.64.0.0/16")]),
                Err(NetworkErrorCode::RouteConflict)
            );
        }
        Ok(())
    }

    #[test]
    fn interface_name_shape_never_implies_mihomo_ownership() {
        let platform = FakePlatform {
            existing: vec![ExistingRoute {
                destination: "8.0.0.0/5".into(),
                interface: "utun1024".into(),
                gateway: None,
            }],
            ..FakePlatform::default()
        };
        let mut orchestrator = RouteOrchestrator::new(platform, MemoryRouteJournal::default());
        assert_eq!(
            orchestrator.apply("tx.1".into(), "profile.1".into(), vec![route("10.64.0.0/16")]),
            Err(NetworkErrorCode::RouteConflict)
        );
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
    fn journal_failure_before_next_mutation_rolls_back_prior_routes() {
        let journal = FailingJournal {
            inner: MemoryRouteJournal::default(),
            save_count: 0,
            fail_once_at: 3,
        };
        let mut orchestrator = RouteOrchestrator::new(FakePlatform::default(), journal);
        assert_eq!(
            orchestrator.apply(
                "tx.1".into(),
                "profile.1".into(),
                vec![route("10.64.0.0/16"), route("10.127.0.0/16")],
            ),
            Err(NetworkErrorCode::RouteJournalUnavailable)
        );
        assert!(orchestrator.platform.added.is_empty());
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
            pending_route: None,
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

    #[test]
    fn recovers_a_durable_pending_mutation_after_crash() -> Result<(), NetworkErrorCode> {
        let pending = route("10.64.0.0/16");
        let mut platform = FakePlatform::default();
        platform.added.push(pending.clone());
        let mut journal = MemoryRouteJournal::default();
        journal.save(&RouteJournalEntry {
            transaction_id: "tx.pending".into(),
            profile_id: "profile.1".into(),
            desired_routes: vec![pending.clone()],
            applied_routes: Vec::new(),
            pending_route: Some(pending),
            previous_routes: Vec::new(),
            state: RouteTransactionState::Prepared,
        })?;
        let mut orchestrator = RouteOrchestrator::new(platform, journal);
        orchestrator.recover_stale()?;
        assert!(orchestrator.platform.added.is_empty());
        Ok(())
    }

    #[test]
    fn file_journal_persists_deterministically_and_reloads() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("route-journal.json");
        let mut journal = FileRouteJournal::new(path.clone());
        journal
            .save(&journal_entry("tx.2", RouteTransactionState::Prepared))
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        journal
            .save(&journal_entry("tx.1", RouteTransactionState::Applied))
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        let reloaded = FileRouteJournal::new(path.clone())
            .entries()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(
            reloaded
                .iter()
                .map(|entry| entry.transaction_id.as_str())
                .collect::<Vec<_>>(),
            ["tx.1", "tx.2"]
        );
        let encoded = fs::read_to_string(path)?;
        assert!(encoded.contains("\"version\": 1"));
        Ok(())
    }

    #[test]
    fn file_journal_fails_closed_on_corruption_and_unknown_version() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("route-journal.json");
        fs::write(&path, b"not-json")?;
        assert_eq!(
            FileRouteJournal::new(path.clone()).entries(),
            Err(NetworkErrorCode::RouteJournalCorrupted)
        );
        fs::write(&path, br#"{"version":2,"entries":[]}"#)?;
        assert_eq!(
            FileRouteJournal::new(path).entries(),
            Err(NetworkErrorCode::RouteJournalCorrupted)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn file_journal_is_private_and_refuses_symlink_target() -> anyhow::Result<()> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        let state_directory = directory.path().join("state");
        let path = state_directory.join("route-journal.json");
        let mut journal = FileRouteJournal::new(path.clone());
        journal
            .save(&journal_entry("tx.1", RouteTransactionState::Prepared))
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(fs::metadata(state_directory)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);

        let protected = directory.path().join("protected.json");
        fs::write(&protected, b"do-not-touch")?;
        let link = directory.path().join("journal-link.json");
        symlink(&protected, &link)?;
        let mut journal = FileRouteJournal::new(link);
        assert_eq!(
            journal.save(&journal_entry("tx.2", RouteTransactionState::Prepared)),
            Err(NetworkErrorCode::RouteJournalUnavailable)
        );
        assert_eq!(fs::read(protected)?, b"do-not-touch");
        Ok(())
    }
}
