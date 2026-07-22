//! Pure Rust contract for the route-helper v3 tunnel/route interlock.
//!
//! The existing [`super::route_helper`] module is the protocol-v2 route-only
//! client.  v3 deliberately lives beside it until the privileged XPC and
//! durable journal have been upgraded.  Keeping this contract independent
//! means that callers cannot accidentally send a v3 owner to the v2 bridge.
//! In particular, a v2 owner is recovery input only; it can never acquire a
//! broker hold or authorize a route mutation.

use serde::{Deserialize, Serialize};

use super::{NetworkErrorCode, RouteLeaseOwner, TunnelDeviceFacts};

/// Route-helper protocol used by the broker-bound owner/journal envelope.
pub const ROUTE_HELPER_V3_PROTOCOL_VERSION: u8 = 3;
/// Protocol used by the fixed root-only tunnel broker hold/release surface.
pub const ROUTE_BROKER_PROTOCOL_VERSION: u8 = 1;
/// Historical route-helper protocol.  It is intentionally not accepted for a
/// v3 mutation, but is retained as an explicit recovery-only classification.
pub const ROUTE_HELPER_V2_PROTOCOL_VERSION: u8 = 2;

/// A broker-assigned session identity.  The broker generation and sidecar ID
/// are independent of the Rust runtime generation and must be copied from the
/// same broker start receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteBrokerSessionReference {
    pub broker_protocol_version: u8,
    pub broker_generation: u64,
    pub sidecar_instance_id: String,
}

impl RouteBrokerSessionReference {
    pub fn validate(&self) -> Result<(), RouteLeaseContractError> {
        if self.broker_protocol_version != ROUTE_BROKER_PROTOCOL_VERSION
            || self.broker_generation == 0
            || self.broker_generation > i64::MAX as u64
            || !super::valid_ipc_id(&self.sidecar_instance_id)
        {
            return Err(RouteLeaseContractError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// The complete ownership tuple persisted and authenticated by the helper.
/// Route lease and operation IDs are intentionally part of the tuple: a
/// request from an older lease or operation must not affect a newer session
/// that happens to use the same sidecar instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLeaseBinding {
    pub broker_protocol_version: u8,
    pub broker_generation: u64,
    pub sidecar_instance_id: String,
    pub lease_id: String,
    pub operation_id: String,
}

impl RouteLeaseBinding {
    pub fn from_broker(broker: &RouteBrokerSessionReference, lease_id: String, operation_id: String) -> Self {
        Self {
            broker_protocol_version: broker.broker_protocol_version,
            broker_generation: broker.broker_generation,
            sidecar_instance_id: broker.sidecar_instance_id.clone(),
            lease_id,
            operation_id,
        }
    }

    pub fn validate(&self) -> Result<(), RouteLeaseContractError> {
        RouteBrokerSessionReference {
            broker_protocol_version: self.broker_protocol_version,
            broker_generation: self.broker_generation,
            sidecar_instance_id: self.sidecar_instance_id.clone(),
        }
        .validate()?;
        if !super::valid_ipc_id(&self.lease_id) || !super::valid_ipc_id(&self.operation_id) {
            return Err(RouteLeaseContractError::InvalidConfiguration);
        }
        Ok(())
    }

    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

/// v3 owner envelope.  The route facts intentionally remain explicit rather
/// than accepting a generic map or command-shaped value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLeaseOwnerV3 {
    pub protocol_version: u8,
    pub broker_protocol_version: u8,
    pub broker_generation: u64,
    pub sidecar_instance_id: String,
    pub lease_id: String,
    pub operation_id: String,
    pub profile_revision: u64,
    pub tunnel: TunnelDeviceFacts,
    pub active_mihomo_tun_interfaces: Vec<String>,
    pub private_cidrs: Vec<String>,
}

impl RouteLeaseOwnerV3 {
    #[must_use]
    pub fn binding(&self) -> RouteLeaseBinding {
        RouteLeaseBinding {
            broker_protocol_version: self.broker_protocol_version,
            broker_generation: self.broker_generation,
            sidecar_instance_id: self.sidecar_instance_id.clone(),
            lease_id: self.lease_id.clone(),
            operation_id: self.operation_id.clone(),
        }
    }

    /// Validate both the new broker tuple and all of the old route-owner
    /// invariants.  The v2 validator is reused only for the route payload; its
    /// protocol number is never accepted as the v3 envelope version.
    pub fn validate(&self) -> Result<(), RouteLeaseContractError> {
        if self.protocol_version != ROUTE_HELPER_V3_PROTOCOL_VERSION {
            return Err(if self.protocol_version == ROUTE_HELPER_V2_PROTOCOL_VERSION {
                RouteLeaseContractError::RecoveryOnly
            } else {
                RouteLeaseContractError::UnsupportedProtocolVersion
            });
        }
        self.binding().validate()?;
        let legacy_owner = RouteLeaseOwner {
            protocol_version: super::ROUTE_HELPER_PROTOCOL_VERSION,
            lease_id: self.lease_id.clone(),
            operation_id: self.operation_id.clone(),
            sidecar_instance_id: self.sidecar_instance_id.clone(),
            profile_revision: self.profile_revision,
            tunnel: self.tunnel.clone(),
            active_mihomo_tun_interfaces: self.active_mihomo_tun_interfaces.clone(),
            private_cidrs: self.private_cidrs.clone(),
        };
        legacy_owner
            .validate()
            .map_err(RouteLeaseContractError::from_network_error)?;
        if self.tunnel.instance_id != self.sidecar_instance_id {
            return Err(RouteLeaseContractError::OwnershipMismatch);
        }
        Ok(())
    }
}

/// Reference used for every v3 helper operation.  It carries the same full
/// tuple as the owner; a lease ID alone is not an authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLeaseReferenceV3 {
    pub protocol_version: u8,
    pub broker_protocol_version: u8,
    pub broker_generation: u64,
    pub sidecar_instance_id: String,
    pub lease_id: String,
    pub operation_id: String,
}

impl RouteLeaseReferenceV3 {
    #[must_use]
    pub fn from_owner(owner: &RouteLeaseOwnerV3) -> Self {
        Self {
            protocol_version: owner.protocol_version,
            broker_protocol_version: owner.broker_protocol_version,
            broker_generation: owner.broker_generation,
            sidecar_instance_id: owner.sidecar_instance_id.clone(),
            lease_id: owner.lease_id.clone(),
            operation_id: owner.operation_id.clone(),
        }
    }

    #[must_use]
    pub fn binding(&self) -> RouteLeaseBinding {
        RouteLeaseBinding {
            broker_protocol_version: self.broker_protocol_version,
            broker_generation: self.broker_generation,
            sidecar_instance_id: self.sidecar_instance_id.clone(),
            lease_id: self.lease_id.clone(),
            operation_id: self.operation_id.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), RouteLeaseContractError> {
        if self.protocol_version != ROUTE_HELPER_V3_PROTOCOL_VERSION {
            return Err(if self.protocol_version == ROUTE_HELPER_V2_PROTOCOL_VERSION {
                RouteLeaseContractError::RecoveryOnly
            } else {
                RouteLeaseContractError::UnsupportedProtocolVersion
            });
        }
        self.binding().validate()
    }

    pub fn matches_owner(&self, owner: &RouteLeaseOwnerV3) -> Result<(), RouteLeaseContractError> {
        self.validate()?;
        owner.validate()?;
        if self != &Self::from_owner(owner) {
            return Err(RouteLeaseContractError::OwnershipMismatch);
        }
        Ok(())
    }
}

/// Durable helper state.  Only `Held` authorizes a first route mutation;
/// `Applied` records that the mutation already happened and is still held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLeaseJournalState {
    HoldPending,
    Held,
    Applied,
    RetirementPending,
    Released,
    RecoveryOnly,
}

impl RouteLeaseJournalState {
    #[must_use]
    pub const fn is_recovery_only(self) -> bool {
        matches!(self, Self::RecoveryOnly)
    }

    #[must_use]
    pub const fn permits_route_mutation(self) -> bool {
        matches!(self, Self::Held)
    }
}

/// A compact, fsync-able v3 owner record.  `transition` is monotonic and
/// prevents replaying a previous hold/release response after the record has
/// advanced to a newer state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLeaseJournalRecord {
    pub protocol_version: u8,
    pub state: RouteLeaseJournalState,
    pub transition: u64,
    pub owner: RouteLeaseOwnerV3,
}

/// A serialized transition acknowledgement.  Persisting the expected source
/// state and exact sequence makes a delayed XPC reply distinguishable from a
/// current operation; a replay cannot be applied merely because its target
/// state is otherwise legal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLeaseTransition {
    pub protocol_version: u8,
    pub from_state: RouteLeaseJournalState,
    pub to_state: RouteLeaseJournalState,
    pub transition: u64,
    pub reference: RouteLeaseReferenceV3,
}

impl RouteLeaseJournalRecord {
    pub fn hold_pending(owner: RouteLeaseOwnerV3) -> Result<Self, RouteLeaseContractError> {
        owner.validate()?;
        Ok(Self {
            protocol_version: ROUTE_HELPER_V3_PROTOCOL_VERSION,
            state: RouteLeaseJournalState::HoldPending,
            transition: 1,
            owner,
        })
    }

    pub fn validate(&self) -> Result<(), RouteLeaseContractError> {
        if self.protocol_version != ROUTE_HELPER_V3_PROTOCOL_VERSION {
            return Err(if self.protocol_version == ROUTE_HELPER_V2_PROTOCOL_VERSION {
                RouteLeaseContractError::RecoveryOnly
            } else {
                RouteLeaseContractError::UnsupportedProtocolVersion
            });
        }
        if self.transition == 0 {
            return Err(RouteLeaseContractError::InvalidConfiguration);
        }
        if self.state == RouteLeaseJournalState::RecoveryOnly {
            return Err(RouteLeaseContractError::RecoveryOnly);
        }
        let transition_shape_is_valid = match self.state {
            RouteLeaseJournalState::HoldPending => self.transition == 1,
            RouteLeaseJournalState::Held => self.transition == 2,
            RouteLeaseJournalState::Applied => self.transition == 3,
            // A route may be cleaned up before the first add completes, so
            // Held -> RetirementPending is a valid three-step path; the
            // ordinary Applied path reaches it at transition four.
            RouteLeaseJournalState::RetirementPending => (3..=4).contains(&self.transition),
            RouteLeaseJournalState::Released => (4..=5).contains(&self.transition),
            RouteLeaseJournalState::RecoveryOnly => false,
        };
        if !transition_shape_is_valid {
            return Err(RouteLeaseContractError::ReplayDetected);
        }
        self.owner.validate()
    }

    pub fn require_reference(&self, reference: &RouteLeaseReferenceV3) -> Result<(), RouteLeaseContractError> {
        self.validate()?;
        reference.matches_owner(&self.owner)
    }

    /// Advance the journal only along the reviewed interlock ordering.
    pub fn transition(
        &self,
        next: RouteLeaseJournalState,
        reference: &RouteLeaseReferenceV3,
    ) -> Result<Self, RouteLeaseContractError> {
        let transition = self
            .transition
            .checked_add(1)
            .ok_or(RouteLeaseContractError::InvalidStateTransition)?;
        self.apply_transition(&RouteLeaseTransition {
            protocol_version: self.protocol_version,
            from_state: self.state,
            to_state: next,
            transition,
            reference: reference.clone(),
        })
    }

    /// Apply a serialized acknowledgement only when it describes this exact
    /// record version. Old or duplicated replies are recovery-only/replay
    /// errors and cannot mutate the journal state.
    pub fn apply_transition(&self, event: &RouteLeaseTransition) -> Result<Self, RouteLeaseContractError> {
        self.require_reference(&event.reference)?;
        if event.protocol_version != ROUTE_HELPER_V3_PROTOCOL_VERSION
            || event.from_state != self.state
            || event.transition != self.transition.saturating_add(1)
        {
            return Err(RouteLeaseContractError::ReplayDetected);
        }
        if !valid_transition(self.state, event.to_state) {
            return Err(if self.state == event.to_state {
                RouteLeaseContractError::ReplayDetected
            } else {
                RouteLeaseContractError::InvalidStateTransition
            });
        }
        Ok(Self {
            protocol_version: self.protocol_version,
            state: event.to_state,
            transition: event.transition,
            owner: self.owner.clone(),
        })
    }

    /// Decode a historical v2 owner as recovery-only input.  No v2 value is
    /// upgraded into a v3 hold or route authorization.
    pub fn classify_legacy_v2(owner: &RouteLeaseOwner) -> Result<RouteLeaseCompatibility, RouteLeaseContractError> {
        owner.validate().map_err(RouteLeaseContractError::from_network_error)?;
        classify_route_helper_protocol(owner.protocol_version)
    }
}

/// Classify an on-disk protocol before attempting to decode a mutation
/// envelope. Historical v2 input is recoverable, but never a v3 authority.
pub const fn classify_route_helper_protocol(
    protocol_version: u8,
) -> Result<RouteLeaseCompatibility, RouteLeaseContractError> {
    match protocol_version {
        ROUTE_HELPER_V3_PROTOCOL_VERSION => Ok(RouteLeaseCompatibility::CurrentV3),
        ROUTE_HELPER_V2_PROTOCOL_VERSION => Ok(RouteLeaseCompatibility::RecoveryOnlyV2),
        _ => Err(RouteLeaseContractError::UnsupportedProtocolVersion),
    }
}

const fn valid_transition(current: RouteLeaseJournalState, next: RouteLeaseJournalState) -> bool {
    matches!(
        (current, next),
        (RouteLeaseJournalState::HoldPending, RouteLeaseJournalState::Held)
            | (RouteLeaseJournalState::Held, RouteLeaseJournalState::Applied)
            | (RouteLeaseJournalState::Held, RouteLeaseJournalState::RetirementPending)
            | (
                RouteLeaseJournalState::Applied,
                RouteLeaseJournalState::RetirementPending
            )
            | (
                RouteLeaseJournalState::RetirementPending,
                RouteLeaseJournalState::Released
            )
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteLeaseCompatibility {
    CurrentV3,
    RecoveryOnlyV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteLeaseContractError {
    UnsupportedProtocolVersion,
    InvalidConfiguration,
    OwnershipMismatch,
    RecoveryOnly,
    ReplayDetected,
    InvalidStateTransition,
}

impl RouteLeaseContractError {
    #[must_use]
    pub const fn network_code(self) -> NetworkErrorCode {
        match self {
            Self::UnsupportedProtocolVersion | Self::RecoveryOnly => NetworkErrorCode::UnsupportedProtocolVersion,
            Self::InvalidConfiguration => NetworkErrorCode::InvalidConfiguration,
            Self::OwnershipMismatch | Self::ReplayDetected => NetworkErrorCode::AuthenticationFailed,
            Self::InvalidStateTransition => NetworkErrorCode::InvalidStateTransition,
        }
    }

    const fn from_network_error(error: NetworkErrorCode) -> Self {
        match error {
            NetworkErrorCode::UnsupportedProtocolVersion => Self::UnsupportedProtocolVersion,
            NetworkErrorCode::AuthenticationFailed | NetworkErrorCode::PolicySignatureInvalid => {
                Self::OwnershipMismatch
            }
            NetworkErrorCode::InvalidStateTransition => Self::InvalidStateTransition,
            _ => Self::InvalidConfiguration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> RouteLeaseOwnerV3 {
        RouteLeaseOwnerV3 {
            protocol_version: ROUTE_HELPER_V3_PROTOCOL_VERSION,
            broker_protocol_version: ROUTE_BROKER_PROTOCOL_VERSION,
            broker_generation: 17,
            sidecar_instance_id: "instance.v3.test".into(),
            lease_id: "lease.v3.test".into(),
            operation_id: "operation.v3.test".into(),
            profile_revision: 7,
            tunnel: TunnelDeviceFacts {
                interface_name: "utun42".into(),
                mtu: 1420,
                has_ipv4: true,
                has_ipv6: true,
                instance_id: "instance.v3.test".into(),
                operation_id: "operation.v3.test.prepare".into(),
            },
            active_mihomo_tun_interfaces: vec!["utun1024".into()],
            private_cidrs: vec!["10.127.0.0/16".into(), "fd00:127::/48".into()],
        }
    }

    #[test]
    fn exact_tuple_round_trips_and_mismatches_fail_closed() -> anyhow::Result<()> {
        let owner = owner();
        assert_eq!(owner.validate(), Ok(()));
        let encoded = serde_json::to_vec(&owner)?;
        let decoded: RouteLeaseOwnerV3 = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, owner);
        let reference = RouteLeaseReferenceV3::from_owner(&owner);
        assert_eq!(reference.matches_owner(&owner), Ok(()));
        let mut stale_generation = reference.clone();
        stale_generation.broker_generation -= 1;
        assert_eq!(
            stale_generation.matches_owner(&owner),
            Err(RouteLeaseContractError::OwnershipMismatch)
        );
        let mut wrong_lease = reference;
        wrong_lease.lease_id = "lease.other".into();
        assert_eq!(
            wrong_lease.matches_owner(&owner),
            Err(RouteLeaseContractError::OwnershipMismatch)
        );
        Ok(())
    }

    #[test]
    fn unknown_wire_fields_and_injection_are_rejected() -> anyhow::Result<()> {
        let owner = owner();
        let mut value = serde_json::to_value(&owner)?;
        value["command"] = serde_json::json!("/sbin/route delete default");
        assert!(serde_json::from_value::<RouteLeaseOwnerV3>(value).is_err());

        let mut malformed = owner;
        malformed.sidecar_instance_id = "instance;route".into();
        assert_eq!(malformed.validate(), Err(RouteLeaseContractError::InvalidConfiguration));
        Ok(())
    }

    #[test]
    fn hold_route_retirement_order_is_monotonic_and_replay_safe() -> anyhow::Result<()> {
        let owner = owner();
        let reference = RouteLeaseReferenceV3::from_owner(&owner);
        let pending = RouteLeaseJournalRecord::hold_pending(owner)
            .map_err(|error| anyhow::anyhow!("valid owner rejected: {error:?}"))?;
        assert!(!pending.state.permits_route_mutation());
        let held = pending
            .transition(RouteLeaseJournalState::Held, &reference)
            .map_err(|error| anyhow::anyhow!("hold rejected: {error:?}"))?;
        assert!(held.state.permits_route_mutation());
        let applied = held
            .transition(RouteLeaseJournalState::Applied, &reference)
            .map_err(|error| anyhow::anyhow!("route apply transition rejected: {error:?}"))?;
        let retirement = applied
            .transition(RouteLeaseJournalState::RetirementPending, &reference)
            .map_err(|error| anyhow::anyhow!("retirement transition rejected: {error:?}"))?;
        let released = retirement
            .transition(RouteLeaseJournalState::Released, &reference)
            .map_err(|error| anyhow::anyhow!("release transition rejected: {error:?}"))?;
        assert!(!released.state.permits_route_mutation());
        assert_eq!(
            released.transition(RouteLeaseJournalState::Released, &reference),
            Err(RouteLeaseContractError::ReplayDetected)
        );
        assert_eq!(
            pending.transition(RouteLeaseJournalState::RetirementPending, &reference),
            Err(RouteLeaseContractError::InvalidStateTransition)
        );
        Ok(())
    }

    #[test]
    fn journal_record_serialization_preserves_state_and_rejects_replayed_wire() -> anyhow::Result<()> {
        let owner = owner();
        let reference = RouteLeaseReferenceV3::from_owner(&owner);
        let pending = RouteLeaseJournalRecord::hold_pending(owner)
            .map_err(|error| anyhow::anyhow!("valid owner rejected: {error:?}"))?;
        let encoded = serde_json::to_vec(&pending)?;
        let decoded: RouteLeaseJournalRecord = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, pending);
        let held = decoded
            .transition(RouteLeaseJournalState::Held, &reference)
            .map_err(|error| anyhow::anyhow!("hold rejected: {error:?}"))?;
        let mut replay = serde_json::to_value(&held)?;
        replay["state"] = serde_json::json!("hold_pending");
        let replayed: RouteLeaseJournalRecord = serde_json::from_value(replay)?;
        assert_eq!(
            replayed.transition(RouteLeaseJournalState::Held, &reference),
            Err(RouteLeaseContractError::ReplayDetected)
        );
        Ok(())
    }

    #[test]
    fn v2_owner_is_explicitly_recovery_only() {
        let owner = RouteLeaseOwner {
            protocol_version: super::super::ROUTE_HELPER_PROTOCOL_VERSION,
            lease_id: "lease.v2.test".into(),
            operation_id: "operation.v2.test".into(),
            sidecar_instance_id: "instance.v2.test".into(),
            profile_revision: 1,
            tunnel: TunnelDeviceFacts {
                interface_name: "utun41".into(),
                mtu: 1420,
                has_ipv4: true,
                has_ipv6: true,
                instance_id: "instance.v2.test".into(),
                operation_id: "operation.v2.test.prepare".into(),
            },
            active_mihomo_tun_interfaces: vec!["utun1024".into()],
            private_cidrs: vec!["10.127.0.0/16".into()],
        };
        assert_eq!(
            RouteLeaseJournalRecord::classify_legacy_v2(&owner),
            Ok(RouteLeaseCompatibility::RecoveryOnlyV2)
        );
    }

    #[test]
    fn recovery_only_record_cannot_become_a_mutation_authority() {
        let mut owner = owner();
        owner.protocol_version = ROUTE_HELPER_V2_PROTOCOL_VERSION;
        assert_eq!(owner.validate(), Err(RouteLeaseContractError::RecoveryOnly));
        let reference = RouteLeaseReferenceV3::from_owner(&owner);
        assert_eq!(reference.validate(), Err(RouteLeaseContractError::RecoveryOnly));
        assert_eq!(
            classify_route_helper_protocol(ROUTE_HELPER_V2_PROTOCOL_VERSION),
            Ok(RouteLeaseCompatibility::RecoveryOnlyV2)
        );
        assert_eq!(
            classify_route_helper_protocol(99),
            Err(RouteLeaseContractError::UnsupportedProtocolVersion)
        );
    }
}
