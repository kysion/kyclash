//! Pure broker-bound route lifecycle for route-helper protocol v3.
//!
//! This module is intentionally source/test-only composition. It does not
//! select the production controller or native helper. Its adapters make the
//! durable ordering and the exact broker/lease tuple independently testable
//! before the production factory is allowed to use it.

use super::{
    BrokerRouteAuthorization, NetworkErrorCode, ROUTE_HELPER_V3_PROTOCOL_VERSION, RouteLeaseBinding,
    RouteLeaseContractError, RouteLeaseJournalRecord, RouteLeaseJournalState, RouteLeaseOwnerV3, RouteLeaseReferenceV3,
};

/// Broker acknowledgement for one exact full-tuple operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerRouteConfirmation {
    binding: RouteLeaseBinding,
    disposition: BrokerRouteDisposition,
}

impl BrokerRouteConfirmation {
    #[must_use]
    pub const fn held(binding: RouteLeaseBinding) -> Self {
        Self {
            binding,
            disposition: BrokerRouteDisposition::Held,
        }
    }

    #[must_use]
    pub const fn released(binding: RouteLeaseBinding) -> Self {
        Self {
            binding,
            disposition: BrokerRouteDisposition::Released,
        }
    }

    fn require(
        &self,
        expected: &RouteLeaseBinding,
        disposition: BrokerRouteDisposition,
    ) -> Result<(), RouteLeaseContractError> {
        self.binding.validate()?;
        if !self.binding.matches(expected) || self.disposition != disposition {
            return Err(RouteLeaseContractError::OwnershipMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerRouteDisposition {
    Held,
    Released,
}

/// Positive route-absence proof echoed for the exact lease reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAbsenceProofV3 {
    reference: RouteLeaseReferenceV3,
}

impl RouteAbsenceProofV3 {
    #[must_use]
    pub const fn new(reference: RouteLeaseReferenceV3) -> Self {
        Self { reference }
    }

    fn require(&self, expected: &RouteLeaseReferenceV3) -> Result<(), RouteLeaseContractError> {
        self.reference.validate()?;
        if &self.reference != expected {
            return Err(RouteLeaseContractError::OwnershipMismatch);
        }
        Ok(())
    }
}

/// The implementation must return only after the complete record has reached
/// durable storage (including the directory durability required by its atomic
/// replacement scheme).
pub trait ProductionRouteV3Journal {
    fn persist_durable(&mut self, record: &RouteLeaseJournalRecord) -> Result<(), NetworkErrorCode>;
}

/// Fixed broker operations. Implementations must call only typed hold/release
/// methods and return the full tuple echoed by the broker.
pub trait ProductionRouteV3Broker {
    fn hold_exact(&mut self, binding: &RouteLeaseBinding) -> Result<BrokerRouteConfirmation, NetworkErrorCode>;

    fn release_exact(&mut self, binding: &RouteLeaseBinding) -> Result<BrokerRouteConfirmation, NetworkErrorCode>;
}

/// Exact route mutation and rollback/absence proof boundary.
pub trait ProductionRouteV3Mutation {
    fn apply_exact(&mut self, owner: &RouteLeaseOwnerV3) -> Result<(), NetworkErrorCode>;

    fn rollback_and_prove_absent(
        &mut self,
        reference: &RouteLeaseReferenceV3,
    ) -> Result<RouteAbsenceProofV3, NetworkErrorCode>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionRouteV3Error {
    Contract(RouteLeaseContractError),
    Journal(NetworkErrorCode),
    Broker(NetworkErrorCode),
    RouteApply(NetworkErrorCode),
    RouteRollback(NetworkErrorCode),
}

/// A non-cloneable lifecycle retaining the sealed start-to-route authority.
/// All helper calls derive their tuple from `authorization`; no caller-supplied
/// reference can redirect a retry to another broker generation or lease.
pub struct ProductionRouteV3Session {
    authorization: BrokerRouteAuthorization,
    owner: RouteLeaseOwnerV3,
    reference: RouteLeaseReferenceV3,
    record: Option<RouteLeaseJournalRecord>,
}

impl ProductionRouteV3Session {
    pub fn new(
        authorization: BrokerRouteAuthorization,
        profile_revision: u64,
        active_mihomo_tun_interfaces: Vec<String>,
        private_cidrs: Vec<String>,
    ) -> Result<Self, ProductionRouteV3Error> {
        let owner = owner_from_authorization(
            &authorization,
            profile_revision,
            active_mihomo_tun_interfaces,
            private_cidrs,
        );
        owner.validate().map_err(ProductionRouteV3Error::Contract)?;
        let reference = RouteLeaseReferenceV3::from_owner(&owner);
        Ok(Self {
            authorization,
            owner,
            reference,
            record: None,
        })
    }

    /// Resume only an already-authenticated v3 record for this exact sealed
    /// authority. Historical v2 records remain recovery-only and cannot be
    /// converted into a current mutation session.
    pub fn resume(
        authorization: BrokerRouteAuthorization,
        record: RouteLeaseJournalRecord,
    ) -> Result<Self, ProductionRouteV3Error> {
        record.validate().map_err(ProductionRouteV3Error::Contract)?;
        require_owner_authority(&record.owner, &authorization)?;
        let reference = RouteLeaseReferenceV3::from_owner(&record.owner);
        Ok(Self {
            authorization,
            owner: record.owner.clone(),
            reference,
            record: Some(record),
        })
    }

    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.authorization.runtime_generation()
    }

    #[must_use]
    pub const fn broker_generation(&self) -> u64 {
        self.authorization.broker_generation()
    }

    #[must_use]
    pub const fn journal_state(&self) -> Option<RouteLeaseJournalState> {
        match &self.record {
            Some(record) => Some(record.state),
            None => None,
        }
    }

    /// Sidecar stop is forbidden while a hold may still exist. In particular,
    /// rollback or release failure retains both the sealed authority and the
    /// durable state that must be retried with the original tuple.
    #[must_use]
    pub const fn permits_sidecar_stop(&self) -> bool {
        matches!(self.journal_state(), None | Some(RouteLeaseJournalState::Released))
    }

    pub fn connect<J, B, R>(
        &mut self,
        journal: &mut J,
        broker: &mut B,
        routes: &mut R,
    ) -> Result<(), ProductionRouteV3Error>
    where
        J: ProductionRouteV3Journal,
        B: ProductionRouteV3Broker,
        R: ProductionRouteV3Mutation,
    {
        if self.record.is_some() {
            return Err(ProductionRouteV3Error::Contract(
                RouteLeaseContractError::ReplayDetected,
            ));
        }
        self.validate_authority()?;

        let pending =
            RouteLeaseJournalRecord::hold_pending(self.owner.clone()).map_err(ProductionRouteV3Error::Contract)?;
        journal
            .persist_durable(&pending)
            .map_err(ProductionRouteV3Error::Journal)?;
        self.record = Some(pending);

        let confirmation = broker
            .hold_exact(self.authorization.binding())
            .map_err(ProductionRouteV3Error::Broker)?;
        confirmation
            .require(self.authorization.binding(), BrokerRouteDisposition::Held)
            .map_err(ProductionRouteV3Error::Contract)?;

        self.transition_durable(RouteLeaseJournalState::Held, journal)?;
        if let Err(error) = routes.apply_exact(&self.owner) {
            return match self.rollback_then_release(journal, broker, routes) {
                Ok(()) => Err(ProductionRouteV3Error::RouteApply(error)),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }

        if let Err(error) = self.transition_durable(RouteLeaseJournalState::Applied, journal) {
            return match self.rollback_then_release(journal, broker, routes) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
        Ok(())
    }

    pub fn disconnect<J, B, R>(
        &mut self,
        journal: &mut J,
        broker: &mut B,
        routes: &mut R,
    ) -> Result<(), ProductionRouteV3Error>
    where
        J: ProductionRouteV3Journal,
        B: ProductionRouteV3Broker,
        R: ProductionRouteV3Mutation,
    {
        self.validate_authority()?;
        match self.journal_state() {
            Some(RouteLeaseJournalState::Held | RouteLeaseJournalState::Applied) => {
                self.rollback_then_release(journal, broker, routes)
            }
            Some(RouteLeaseJournalState::RetirementPending) => self.release(journal, broker),
            Some(RouteLeaseJournalState::HoldPending) => {
                // A lost hold reply is ambiguous about broker state but proves
                // that route apply was never reached. Persist retirement first
                // and use the broker's exact-tuple idempotent release; route
                // mutation and rollback are both forbidden on this path.
                self.transition_durable(RouteLeaseJournalState::RetirementPending, journal)?;
                self.release(journal, broker)
            }
            Some(RouteLeaseJournalState::Released) => Err(ProductionRouteV3Error::Contract(
                RouteLeaseContractError::ReplayDetected,
            )),
            Some(RouteLeaseJournalState::RecoveryOnly) => {
                Err(ProductionRouteV3Error::Contract(RouteLeaseContractError::RecoveryOnly))
            }
            None => Err(ProductionRouteV3Error::Contract(
                RouteLeaseContractError::InvalidStateTransition,
            )),
        }
    }

    fn validate_authority(&self) -> Result<(), ProductionRouteV3Error> {
        require_owner_authority(&self.owner, &self.authorization)?;
        self.reference
            .matches_owner(&self.owner)
            .map_err(ProductionRouteV3Error::Contract)
    }

    fn transition_durable<J: ProductionRouteV3Journal>(
        &mut self,
        next: RouteLeaseJournalState,
        journal: &mut J,
    ) -> Result<(), ProductionRouteV3Error> {
        let current = self.record.as_ref().ok_or(ProductionRouteV3Error::Contract(
            RouteLeaseContractError::InvalidStateTransition,
        ))?;
        let next_record = current
            .transition(next, &self.reference)
            .map_err(ProductionRouteV3Error::Contract)?;
        journal
            .persist_durable(&next_record)
            .map_err(ProductionRouteV3Error::Journal)?;
        self.record = Some(next_record);
        Ok(())
    }

    fn rollback_then_release<J, B, R>(
        &mut self,
        journal: &mut J,
        broker: &mut B,
        routes: &mut R,
    ) -> Result<(), ProductionRouteV3Error>
    where
        J: ProductionRouteV3Journal,
        B: ProductionRouteV3Broker,
        R: ProductionRouteV3Mutation,
    {
        let proof = routes
            .rollback_and_prove_absent(&self.reference)
            .map_err(ProductionRouteV3Error::RouteRollback)?;
        proof
            .require(&self.reference)
            .map_err(ProductionRouteV3Error::Contract)?;
        self.transition_durable(RouteLeaseJournalState::RetirementPending, journal)?;
        self.release(journal, broker)
    }

    fn release<J, B>(&mut self, journal: &mut J, broker: &mut B) -> Result<(), ProductionRouteV3Error>
    where
        J: ProductionRouteV3Journal,
        B: ProductionRouteV3Broker,
    {
        if self.journal_state() != Some(RouteLeaseJournalState::RetirementPending) {
            return Err(ProductionRouteV3Error::Contract(
                RouteLeaseContractError::InvalidStateTransition,
            ));
        }
        let confirmation = broker
            .release_exact(self.authorization.binding())
            .map_err(ProductionRouteV3Error::Broker)?;
        confirmation
            .require(self.authorization.binding(), BrokerRouteDisposition::Released)
            .map_err(ProductionRouteV3Error::Contract)?;
        self.transition_durable(RouteLeaseJournalState::Released, journal)
    }
}

fn owner_from_authorization(
    authorization: &BrokerRouteAuthorization,
    profile_revision: u64,
    active_mihomo_tun_interfaces: Vec<String>,
    private_cidrs: Vec<String>,
) -> RouteLeaseOwnerV3 {
    let binding = authorization.binding();
    RouteLeaseOwnerV3 {
        protocol_version: ROUTE_HELPER_V3_PROTOCOL_VERSION,
        broker_protocol_version: binding.broker_protocol_version,
        broker_generation: binding.broker_generation,
        sidecar_instance_id: binding.sidecar_instance_id.clone(),
        lease_id: binding.lease_id.clone(),
        operation_id: binding.operation_id.clone(),
        profile_revision,
        tunnel: authorization.tunnel().clone(),
        active_mihomo_tun_interfaces,
        private_cidrs,
    }
}

fn require_owner_authority(
    owner: &RouteLeaseOwnerV3,
    authorization: &BrokerRouteAuthorization,
) -> Result<(), ProductionRouteV3Error> {
    owner.validate().map_err(ProductionRouteV3Error::Contract)?;
    if !owner.binding().matches(authorization.binding()) || &owner.tunnel != authorization.tunnel() {
        return Err(ProductionRouteV3Error::Contract(
            RouteLeaseContractError::OwnershipMismatch,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::networking::{
        ControllerStartReceipt, NETWORK_IPC_PROTOCOL_VERSION, SidecarHandshake, TUNNEL_BROKER_PROTOCOL_VERSION,
        TunnelBrokerSessionReference, TunnelDeviceFacts,
    };

    type Events = Arc<Mutex<Vec<&'static str>>>;

    struct FakeJournal {
        events: Events,
    }

    impl ProductionRouteV3Journal for FakeJournal {
        fn persist_durable(&mut self, record: &RouteLeaseJournalRecord) -> Result<(), NetworkErrorCode> {
            self.events
                .lock()
                .map_err(|_| NetworkErrorCode::RouteJournalUnavailable)?
                .push(match record.state {
                    RouteLeaseJournalState::HoldPending => "journal:hold_pending",
                    RouteLeaseJournalState::Held => "journal:held",
                    RouteLeaseJournalState::Applied => "journal:applied",
                    RouteLeaseJournalState::RetirementPending => "journal:retirement_pending",
                    RouteLeaseJournalState::Released => "journal:released",
                    RouteLeaseJournalState::RecoveryOnly => "journal:recovery_only",
                });
            Ok(())
        }
    }

    struct FakeBroker {
        events: Events,
        hold_error: Option<NetworkErrorCode>,
        release_failures: usize,
        wrong_hold_tuple: bool,
        wrong_release_tuple: bool,
        calls: Vec<RouteLeaseBinding>,
    }

    impl ProductionRouteV3Broker for FakeBroker {
        fn hold_exact(&mut self, binding: &RouteLeaseBinding) -> Result<BrokerRouteConfirmation, NetworkErrorCode> {
            self.events
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .push("broker:hold");
            self.calls.push(binding.clone());
            if let Some(error) = self.hold_error {
                return Err(error);
            }
            let mut echoed = binding.clone();
            if self.wrong_hold_tuple {
                echoed.operation_id = "operation.wrong".into();
            }
            Ok(BrokerRouteConfirmation::held(echoed))
        }

        fn release_exact(&mut self, binding: &RouteLeaseBinding) -> Result<BrokerRouteConfirmation, NetworkErrorCode> {
            self.events
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .push("broker:release");
            self.calls.push(binding.clone());
            if self.release_failures != 0 {
                self.release_failures -= 1;
                return Err(NetworkErrorCode::OperationTimedOut);
            }
            let mut echoed = binding.clone();
            if self.wrong_release_tuple {
                echoed.lease_id = "lease.wrong".into();
            }
            Ok(BrokerRouteConfirmation::released(echoed))
        }
    }

    struct FakeRoutes {
        events: Events,
        apply_error: Option<NetworkErrorCode>,
        rollback_error: Option<NetworkErrorCode>,
        apply_calls: usize,
        rollback_calls: usize,
    }

    impl ProductionRouteV3Mutation for FakeRoutes {
        fn apply_exact(&mut self, _owner: &RouteLeaseOwnerV3) -> Result<(), NetworkErrorCode> {
            self.events
                .lock()
                .map_err(|_| NetworkErrorCode::RouteJournalUnavailable)?
                .push("routes:apply");
            self.apply_calls += 1;
            self.apply_error.map_or(Ok(()), Err)
        }

        fn rollback_and_prove_absent(
            &mut self,
            reference: &RouteLeaseReferenceV3,
        ) -> Result<RouteAbsenceProofV3, NetworkErrorCode> {
            self.events
                .lock()
                .map_err(|_| NetworkErrorCode::RouteJournalUnavailable)?
                .push("routes:rollback");
            self.rollback_calls += 1;
            if let Some(error) = self.rollback_error {
                return Err(error);
            }
            Ok(RouteAbsenceProofV3::new(reference.clone()))
        }
    }

    fn authorization(
        runtime_generation: u64,
        broker_generation: u64,
    ) -> Result<BrokerRouteAuthorization, NetworkErrorCode> {
        let instance_id = "broker.route.session.91";
        let broker_reference = TunnelBrokerSessionReference {
            protocol_version: TUNNEL_BROKER_PROTOCOL_VERSION,
            generation: broker_generation,
            sidecar_instance_id: instance_id.into(),
        };
        let handshake = SidecarHandshake {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            instance_id: instance_id.into(),
            auth_proof: "proof.test".into(),
        };
        let receipt =
            ControllerStartReceipt::issue(runtime_generation, broker_reference, &handshake, "proof.test", None)?;
        receipt.authorize_routes(
            TunnelDeviceFacts {
                interface_name: "utun42".into(),
                mtu: 1420,
                has_ipv4: true,
                has_ipv6: true,
                instance_id: instance_id.into(),
                operation_id: "operation.route.91.prepare".into(),
            },
            "lease.route.91".into(),
            "operation.route.91".into(),
        )
    }

    fn session() -> Result<ProductionRouteV3Session, ProductionRouteV3Error> {
        ProductionRouteV3Session::new(
            authorization(7, 91).map_err(ProductionRouteV3Error::Journal)?,
            1,
            vec!["utun1024".into()],
            vec!["10.127.0.0/16".into(), "fd00:127::/48".into()],
        )
    }

    fn adapters(events: &Events) -> (FakeJournal, FakeBroker, FakeRoutes) {
        (
            FakeJournal {
                events: Arc::clone(events),
            },
            FakeBroker {
                events: Arc::clone(events),
                hold_error: None,
                release_failures: 0,
                wrong_hold_tuple: false,
                wrong_release_tuple: false,
                calls: Vec::new(),
            },
            FakeRoutes {
                events: Arc::clone(events),
                apply_error: None,
                rollback_error: None,
                apply_calls: 0,
                rollback_calls: 0,
            },
        )
    }

    fn recorded_events(events: &Events) -> Result<Vec<&'static str>, ProductionRouteV3Error> {
        events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| ProductionRouteV3Error::Journal(NetworkErrorCode::RouteJournalUnavailable))
    }

    #[test]
    fn exact_durable_connect_and_disconnect_order_is_enforced() -> Result<(), ProductionRouteV3Error> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut journal, mut broker, mut routes) = adapters(&events);
        let mut session = session()?;
        assert_eq!(session.runtime_generation(), 7);
        assert_eq!(session.broker_generation(), 91);

        session.connect(&mut journal, &mut broker, &mut routes)?;
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::Applied));
        assert!(!session.permits_sidecar_stop());
        session.disconnect(&mut journal, &mut broker, &mut routes)?;
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::Released));
        assert!(session.permits_sidecar_stop());
        assert_eq!(
            recorded_events(&events)?,
            [
                "journal:hold_pending",
                "broker:hold",
                "journal:held",
                "routes:apply",
                "journal:applied",
                "routes:rollback",
                "journal:retirement_pending",
                "broker:release",
                "journal:released",
            ]
        );
        assert!(broker.calls.windows(2).all(|calls| calls[0] == calls[1]));
        Ok(())
    }

    #[test]
    fn ambiguous_hold_retires_without_route_mutation_and_retries_exact_release() -> Result<(), ProductionRouteV3Error> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut journal, mut broker, mut routes) = adapters(&events);
        broker.hold_error = Some(NetworkErrorCode::OperationTimedOut);
        let mut session = session()?;

        assert_eq!(
            session.connect(&mut journal, &mut broker, &mut routes),
            Err(ProductionRouteV3Error::Broker(NetworkErrorCode::OperationTimedOut))
        );
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::HoldPending));
        assert_eq!(routes.apply_calls, 0);
        assert!(!session.permits_sidecar_stop());
        assert_eq!(
            session.connect(&mut journal, &mut broker, &mut routes),
            Err(ProductionRouteV3Error::Contract(
                RouteLeaseContractError::ReplayDetected
            ))
        );
        broker.release_failures = 1;
        assert_eq!(
            session.disconnect(&mut journal, &mut broker, &mut routes),
            Err(ProductionRouteV3Error::Broker(NetworkErrorCode::OperationTimedOut))
        );
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::RetirementPending));
        assert_eq!(routes.apply_calls, 0);
        assert_eq!(routes.rollback_calls, 0);
        assert!(!session.permits_sidecar_stop());
        session.disconnect(&mut journal, &mut broker, &mut routes)?;
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::Released));
        assert!(session.permits_sidecar_stop());
        assert!(broker.calls.windows(2).all(|calls| calls[0] == calls[1]));
        assert_eq!(
            recorded_events(&events)?,
            [
                "journal:hold_pending",
                "broker:hold",
                "journal:retirement_pending",
                "broker:release",
                "broker:release",
                "journal:released",
            ]
        );
        Ok(())
    }

    #[test]
    fn apply_failure_rolls_back_proves_absence_and_releases() -> Result<(), ProductionRouteV3Error> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut journal, mut broker, mut routes) = adapters(&events);
        routes.apply_error = Some(NetworkErrorCode::RouteConflict);
        let mut session = session()?;

        assert_eq!(
            session.connect(&mut journal, &mut broker, &mut routes),
            Err(ProductionRouteV3Error::RouteApply(NetworkErrorCode::RouteConflict))
        );
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::Released));
        assert!(session.permits_sidecar_stop());
        assert_eq!(routes.rollback_calls, 1);
        assert_eq!(
            recorded_events(&events)?,
            [
                "journal:hold_pending",
                "broker:hold",
                "journal:held",
                "routes:apply",
                "routes:rollback",
                "journal:retirement_pending",
                "broker:release",
                "journal:released",
            ]
        );
        Ok(())
    }

    #[test]
    fn rollback_failure_retains_hold_and_blocks_sidecar_stop() -> Result<(), ProductionRouteV3Error> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut journal, mut broker, mut routes) = adapters(&events);
        let mut session = session()?;
        session.connect(&mut journal, &mut broker, &mut routes)?;
        routes.rollback_error = Some(NetworkErrorCode::RouteRollbackFailed);

        assert_eq!(
            session.disconnect(&mut journal, &mut broker, &mut routes),
            Err(ProductionRouteV3Error::RouteRollback(
                NetworkErrorCode::RouteRollbackFailed
            ))
        );
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::Applied));
        assert!(!session.permits_sidecar_stop());
        assert_eq!(broker.calls.len(), 1);
        Ok(())
    }

    #[test]
    fn release_transport_failure_retries_only_the_original_tuple() -> Result<(), ProductionRouteV3Error> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut journal, mut broker, mut routes) = adapters(&events);
        broker.release_failures = 1;
        let mut session = session()?;
        session.connect(&mut journal, &mut broker, &mut routes)?;

        assert_eq!(
            session.disconnect(&mut journal, &mut broker, &mut routes),
            Err(ProductionRouteV3Error::Broker(NetworkErrorCode::OperationTimedOut))
        );
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::RetirementPending));
        assert!(!session.permits_sidecar_stop());
        session.disconnect(&mut journal, &mut broker, &mut routes)?;
        assert_eq!(routes.rollback_calls, 1);
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::Released));
        assert!(broker.calls.windows(2).all(|calls| calls[0] == calls[1]));
        Ok(())
    }

    #[test]
    fn wrong_tuple_and_replay_are_rejected_before_route_mutation() -> Result<(), ProductionRouteV3Error> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut journal, mut broker, mut routes) = adapters(&events);
        broker.wrong_hold_tuple = true;
        let mut session = session()?;
        assert_eq!(
            session.connect(&mut journal, &mut broker, &mut routes),
            Err(ProductionRouteV3Error::Contract(
                RouteLeaseContractError::OwnershipMismatch
            ))
        );
        assert_eq!(routes.apply_calls, 0);
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::HoldPending));
        Ok(())
    }

    #[test]
    fn wrong_release_tuple_retains_retirement_pending_for_exact_retry() -> Result<(), ProductionRouteV3Error> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut journal, mut broker, mut routes) = adapters(&events);
        broker.hold_error = Some(NetworkErrorCode::OperationTimedOut);
        broker.wrong_release_tuple = true;
        let mut session = session()?;
        assert_eq!(
            session.connect(&mut journal, &mut broker, &mut routes),
            Err(ProductionRouteV3Error::Broker(NetworkErrorCode::OperationTimedOut))
        );
        assert_eq!(
            session.disconnect(&mut journal, &mut broker, &mut routes),
            Err(ProductionRouteV3Error::Contract(
                RouteLeaseContractError::OwnershipMismatch
            ))
        );
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::RetirementPending));
        assert!(!session.permits_sidecar_stop());
        assert_eq!(routes.apply_calls, 0);
        assert_eq!(routes.rollback_calls, 0);

        broker.wrong_release_tuple = false;
        session.disconnect(&mut journal, &mut broker, &mut routes)?;
        assert_eq!(session.journal_state(), Some(RouteLeaseJournalState::Released));
        assert!(broker.calls.windows(2).all(|calls| calls[0] == calls[1]));
        Ok(())
    }

    #[test]
    fn v2_record_is_recovery_only_and_cannot_be_resumed_as_v3() -> Result<(), ProductionRouteV3Error> {
        let current = session()?;
        let mut record =
            RouteLeaseJournalRecord::hold_pending(current.owner).map_err(ProductionRouteV3Error::Contract)?;
        record.protocol_version = super::super::ROUTE_HELPER_V2_PROTOCOL_VERSION;
        record.owner.protocol_version = super::super::ROUTE_HELPER_V2_PROTOCOL_VERSION;
        let result =
            ProductionRouteV3Session::resume(authorization(8, 92).map_err(ProductionRouteV3Error::Journal)?, record);
        assert_eq!(
            result.err(),
            Some(ProductionRouteV3Error::Contract(RouteLeaseContractError::RecoveryOnly))
        );
        Ok(())
    }
}
