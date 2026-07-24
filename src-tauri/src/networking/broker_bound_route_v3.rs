//! Isolated broker-bound route-helper v3 composition seam.
//!
//! This adapter deliberately is **not** the legacy [`ProductionRouteBoundary`]
//! implementation.  That trait predates the broker generation and cannot
//! safely manufacture the full v3 ownership tuple.  The seam below accepts
//! only a sealed [`BrokerRouteAuthorization`] issued after the controller
//! handshake and tunnel identity have been checked.  The production factory
//! remains responsible for deciding when (and whether) to construct it.

use super::route_helper_client::RouteRetirementIssuer;
use super::{
    BrokerRouteAuthorization, ControllerStartReceipt, MihomoTunSnapshot, NetworkErrorCode, NetworkProfile,
    ProductionRouteBoundary, ProductionRouteDisposition, ProductionRouteRetirementReceipt,
    ProductionRouteRetirementResult, ROUTE_HELPER_V3_PROTOCOL_VERSION, RouteHelperV3Client, RouteHelperV3State,
    RouteHelperV3Status, RouteLeaseOwnerV3, RouteLeaseReferenceV3, TunnelDeviceFacts,
};

/// The small operation surface needed by the broker-bound adapter.  Keeping
/// the native client behind this trait makes identity/ordering tests runnable
/// without an XPC service or a macOS privileged helper.
pub trait RouteHelperV3Operations: Send + Sync {
    fn discover(&self) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn begin(&self, owner: &RouteLeaseOwnerV3) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn recover(&self, owner: &RouteLeaseOwnerV3) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn apply(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn rollback(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn heartbeat(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn status(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode>;
}

impl RouteHelperV3Operations for RouteHelperV3Client {
    fn discover(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::discover(self)
    }

    fn begin(&self, owner: &RouteLeaseOwnerV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::begin(self, owner)
    }

    fn recover(&self, owner: &RouteLeaseOwnerV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::recover(self, owner)
    }

    fn apply(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::apply(self, reference)
    }

    fn rollback(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::rollback(self, reference)
    }

    fn heartbeat(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::heartbeat(self, reference)
    }

    fn status(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::status(self, reference)
    }
}

/// A typed owner/reference pair derived from one controller start receipt.
///
/// No constructor accepts a free-form sidecar instance, broker generation,
/// lease, or operation tuple.  Those values are copied from the sealed
/// authorization and the tunnel facts it carries.
pub struct BrokerBoundRouteHelperV3<C> {
    client: C,
    /// Retain the non-cloneable proof for the entire native-client lifetime;
    /// deriving an owner once must not discard the controller/tunnel
    /// authority that made the tuple valid.
    authorization: BrokerRouteAuthorization,
    owner: RouteLeaseOwnerV3,
    reference: RouteLeaseReferenceV3,
    runtime_generation: u64,
}

impl<C> std::fmt::Debug for BrokerBoundRouteHelperV3<C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerBoundRouteHelperV3")
            .field("runtime_generation", &self.runtime_generation)
            .field("broker_generation", &self.reference.broker_generation)
            .field("sidecar_instance_id", &self.reference.sidecar_instance_id)
            .field("lease_id", &self.reference.lease_id)
            .field("operation_id", &self.reference.operation_id)
            .finish_non_exhaustive()
    }
}

impl<C> BrokerBoundRouteHelperV3<C>
where
    C: RouteHelperV3Operations,
{
    /// Construct the seam only from a controller-issued route authorization.
    /// Validation is repeated here immediately before any native call so a
    /// future caller cannot bypass the route-owner identity chain.
    pub fn new(
        client: C,
        authorization: BrokerRouteAuthorization,
        profile_revision: u64,
        active_mihomo_tun_interfaces: Vec<String>,
        private_cidrs: Vec<String>,
    ) -> Result<Self, NetworkErrorCode> {
        let binding = authorization.binding();
        let owner = RouteLeaseOwnerV3 {
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
        };
        owner.validate().map_err(|error| error.network_code())?;
        let reference = RouteLeaseReferenceV3::from_owner(&owner);
        reference.validate().map_err(|error| error.network_code())?;
        let runtime_generation = authorization.runtime_generation();
        Ok(Self {
            client,
            authorization,
            owner,
            reference,
            runtime_generation,
        })
    }

    #[must_use]
    pub const fn owner(&self) -> &RouteLeaseOwnerV3 {
        &self.owner
    }

    #[must_use]
    pub const fn reference(&self) -> &RouteLeaseReferenceV3 {
        &self.reference
    }

    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Begin the helper's durable hold.  The returned status must be checked
    /// by the caller before it attempts `apply`.
    pub fn begin(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.validate_authority()?;
        self.client.begin(&self.owner)
    }

    pub fn recover(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.validate_authority()?;
        self.client.recover(&self.owner)
    }

    pub fn apply(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.validate_authority()?;
        self.client.apply(&self.reference)
    }

    /// Rollback is intentionally one native operation: the v3 helper removes
    /// exact routes and releases the matching broker hold before it replies.
    /// This is why this seam does not implement the older split broker/route
    /// traits, whose call order would otherwise double-release the lease.
    pub fn rollback(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.validate_authority()?;
        self.client.rollback(&self.reference)
    }

    pub fn heartbeat(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.validate_authority()?;
        self.client.heartbeat(&self.reference)
    }

    pub fn status(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.validate_authority()?;
        self.client.status(&self.reference)
    }

    /// A small readiness check used by a future production factory.  It does
    /// not mutate routes or acquire a hold.
    pub fn is_idle(&self) -> Result<bool, NetworkErrorCode> {
        self.validate_authority()?;
        let status = self.client.discover();
        match status {
            Ok(status) => Ok(matches!(
                status.state,
                RouteHelperV3State::Idle | RouteHelperV3State::Released
            )),
            Err(error) => Err(error),
        }
    }

    fn validate_authority(&self) -> Result<(), NetworkErrorCode> {
        self.owner.validate().map_err(|error| error.network_code())?;
        if self.owner.binding() != *self.authorization.binding() || self.owner.tunnel != *self.authorization.tunnel() {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        self.reference
            .matches_owner(&self.owner)
            .map_err(|error| error.network_code())
    }
}

/// Default-off native factory seam.  It intentionally takes the sealed
/// authorization as an argument instead of discovering or inventing one.
pub struct BrokerBoundRouteHelperV3Factory;

impl BrokerBoundRouteHelperV3Factory {
    pub fn connect(
        authorization: BrokerRouteAuthorization,
        profile_revision: u64,
        active_mihomo_tun_interfaces: Vec<String>,
        private_cidrs: Vec<String>,
    ) -> Result<BrokerBoundRouteHelperV3<RouteHelperV3Client>, NetworkErrorCode> {
        let client = RouteHelperV3Client::connect()?;
        BrokerBoundRouteHelperV3::new(
            client,
            authorization,
            profile_revision,
            active_mihomo_tun_interfaces,
            private_cidrs,
        )
    }
}

trait BoundRouteHelperV3Session: Send {
    fn reference(&self) -> &RouteLeaseReferenceV3;
    fn discover(&self) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn begin(&self) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn apply(&self) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn heartbeat(&self) -> Result<RouteHelperV3Status, NetworkErrorCode>;
    fn rollback(&self) -> Result<RouteHelperV3Status, NetworkErrorCode>;
}

impl<C> BoundRouteHelperV3Session for BrokerBoundRouteHelperV3<C>
where
    C: RouteHelperV3Operations,
{
    fn reference(&self) -> &RouteLeaseReferenceV3 {
        Self::reference(self)
    }

    fn discover(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.validate_authority()?;
        self.client.discover()
    }

    fn begin(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::begin(self)
    }

    fn apply(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::apply(self)
    }

    fn heartbeat(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::heartbeat(self)
    }

    fn rollback(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        Self::rollback(self)
    }
}

trait BoundRouteHelperV3SessionFactory: Send {
    fn create(
        &mut self,
        authorization: BrokerRouteAuthorization,
        profile_revision: u64,
        active_mihomo_tun_interfaces: Vec<String>,
        private_cidrs: Vec<String>,
    ) -> Result<Box<dyn BoundRouteHelperV3Session>, NetworkErrorCode>;
}

struct NativeBoundRouteHelperV3SessionFactory;

impl BoundRouteHelperV3SessionFactory for NativeBoundRouteHelperV3SessionFactory {
    fn create(
        &mut self,
        authorization: BrokerRouteAuthorization,
        profile_revision: u64,
        active_mihomo_tun_interfaces: Vec<String>,
        private_cidrs: Vec<String>,
    ) -> Result<Box<dyn BoundRouteHelperV3Session>, NetworkErrorCode> {
        BrokerBoundRouteHelperV3Factory::connect(
            authorization,
            profile_revision,
            active_mihomo_tun_interfaces,
            private_cidrs,
        )
        .map(|session| Box::new(session) as Box<dyn BoundRouteHelperV3Session>)
    }
}

/// Deferred production route boundary for the one-shot broker controller.
///
/// Construction opens no XPC connection and owns no route tuple. Only
/// `apply_broker_bound`, after carrier health, tunnel facts and the Mihomo
/// snapshot are available, may consume the controller receipt and construct
/// the exact v3 session. Rollback is the helper's combined route removal and
/// broker release operation.
pub struct DeferredV3ProductionRouteBoundary {
    factory: Box<dyn BoundRouteHelperV3SessionFactory>,
    active: Option<Box<dyn BoundRouteHelperV3Session>>,
    active_operation_id: Option<String>,
    retirement_issuer: RouteRetirementIssuer,
    native_generation: u64,
    recovery_required: bool,
    retired: bool,
}

impl std::fmt::Debug for DeferredV3ProductionRouteBoundary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeferredV3ProductionRouteBoundary")
            .field("active", &self.active.is_some())
            .field("native_generation", &self.native_generation)
            .field("recovery_required", &self.recovery_required)
            .field("retired", &self.retired)
            .finish_non_exhaustive()
    }
}

impl DeferredV3ProductionRouteBoundary {
    pub fn new() -> Result<Self, NetworkErrorCode> {
        Self::with_factory(Box::new(NativeBoundRouteHelperV3SessionFactory))
    }

    fn with_factory(factory: Box<dyn BoundRouteHelperV3SessionFactory>) -> Result<Self, NetworkErrorCode> {
        Ok(Self {
            factory,
            active: None,
            active_operation_id: None,
            retirement_issuer: RouteRetirementIssuer::allocate()?,
            native_generation: 1,
            recovery_required: false,
            retired: false,
        })
    }

    const fn require_live(&self) -> Result<(), NetworkErrorCode> {
        if self.retired {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        Ok(())
    }

    fn validate_active_status(
        &self,
        status: &RouteHelperV3Status,
        expected: RouteHelperV3State,
        expected_transition: u64,
    ) -> Result<(), NetworkErrorCode> {
        if status.protocol_version != ROUTE_HELPER_V3_PROTOCOL_VERSION {
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        if let Some(error) = status.error_code {
            return Err(error);
        }
        let reference = self
            .active
            .as_ref()
            .map(|active| active.reference())
            .ok_or(NetworkErrorCode::InvalidStateTransition)?;
        if status.state != expected
            || status.reference.as_ref() != Some(reference)
            || status.transition != expected_transition
        {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        Ok(())
    }

    fn validate_discover_status(&self, status: &RouteHelperV3Status) -> Result<(), NetworkErrorCode> {
        if status.protocol_version != ROUTE_HELPER_V3_PROTOCOL_VERSION {
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        if let Some(error) = status.error_code {
            return Err(error);
        }
        if status.state != RouteHelperV3State::Idle || status.reference.is_some() || status.transition != 0 {
            // A stale/recovery-only journal, failed-closed helper, or any
            // tuple-bearing discover reply is not a clean new-lease
            // boundary. Its exact old owner must be reconciled by the helper
            // startup/recovery path; never guess it from a fresh receipt.
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        Ok(())
    }

    fn validate_rollback_status(&self, status: &RouteHelperV3Status) -> Result<(), NetworkErrorCode> {
        if status.protocol_version != ROUTE_HELPER_V3_PROTOCOL_VERSION {
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        if let Some(error) = status.error_code {
            return Err(error);
        }
        let reference = self
            .active
            .as_ref()
            .map(|active| active.reference())
            .ok_or(NetworkErrorCode::InvalidStateTransition)?;
        match status.state {
            RouteHelperV3State::Released if status.reference.as_ref() == Some(reference) && status.transition > 0 => {
                Ok(())
            }
            RouteHelperV3State::Idle if status.reference.is_none() && status.transition == 0 => Ok(()),
            _ => Err(NetworkErrorCode::AuthenticationFailed),
        }
    }

    const fn freeze(&mut self, error: NetworkErrorCode) -> NetworkErrorCode {
        self.recovery_required = true;
        error
    }
}

impl ProductionRouteBoundary for DeferredV3ProductionRouteBoundary {
    fn disposition(&self) -> ProductionRouteDisposition {
        if self.retired {
            ProductionRouteDisposition::Retired
        } else if self.recovery_required {
            ProductionRouteDisposition::RecoveryOnly
        } else if self.active.is_some() || self.active_operation_id.is_some() {
            ProductionRouteDisposition::Busy
        } else {
            ProductionRouteDisposition::Reusable
        }
    }

    fn try_retire(&mut self) -> ProductionRouteRetirementResult {
        match self.disposition() {
            ProductionRouteDisposition::Busy => ProductionRouteRetirementResult::Busy,
            ProductionRouteDisposition::RecoveryOnly => ProductionRouteRetirementResult::RecoveryOnly,
            ProductionRouteDisposition::Retired => ProductionRouteRetirementResult::AlreadyRetired,
            ProductionRouteDisposition::Reusable => {
                self.retired = true;
                ProductionRouteRetirementResult::Retired(ProductionRouteRetirementReceipt::issued(
                    &self.retirement_issuer,
                    self.native_generation,
                ))
            }
        }
    }

    fn apply(
        &mut self,
        _profile: &NetworkProfile,
        _operation_id: &str,
        _tunnel: &TunnelDeviceFacts,
        _profile_revision: u64,
        _mihomo: &MihomoTunSnapshot,
    ) -> Result<(), NetworkErrorCode> {
        Err(NetworkErrorCode::InvalidStateTransition)
    }

    fn apply_broker_bound(
        &mut self,
        profile: &NetworkProfile,
        operation_id: &str,
        tunnel: &TunnelDeviceFacts,
        profile_revision: u64,
        mihomo: &MihomoTunSnapshot,
        receipt: ControllerStartReceipt,
    ) -> Result<(), NetworkErrorCode> {
        self.require_live()?;
        if self.active.is_some() || self.active_operation_id.is_some() || self.recovery_required {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        profile.validate()?;
        mihomo.validate_for(&tunnel.interface_name)?;
        let authorization =
            receipt.authorize_routes(tunnel.clone(), operation_id.to_owned(), operation_id.to_owned())?;
        let session = self.factory.create(
            authorization,
            profile_revision,
            mihomo.interfaces().to_vec(),
            profile.site.private_cidrs.clone(),
        )?;
        self.active_operation_id = Some(operation_id.to_owned());
        self.active = Some(session);

        let discovered = match self.active.as_ref() {
            Some(active) => active.discover(),
            None => Err(NetworkErrorCode::InvalidStateTransition),
        };
        let discovered = match discovered {
            Ok(status) => status,
            Err(error) => return Err(self.freeze(error)),
        };
        if let Err(error) = self.validate_discover_status(&discovered) {
            return Err(self.freeze(error));
        }

        let begin = match self.active.as_ref() {
            Some(active) => active.begin(),
            None => Err(NetworkErrorCode::InvalidStateTransition),
        };
        let begin = match begin {
            Ok(status) => status,
            Err(error) => return Err(self.freeze(error)),
        };
        if let Err(error) = self.validate_active_status(&begin, RouteHelperV3State::Held, 2) {
            return Err(self.freeze(error));
        }
        let applied = match self.active.as_ref() {
            Some(active) => active.apply(),
            None => Err(NetworkErrorCode::InvalidStateTransition),
        };
        let applied = match applied {
            Ok(status) => status,
            Err(error) => return Err(self.freeze(error)),
        };
        if let Err(error) = self.validate_active_status(&applied, RouteHelperV3State::Applied, 3) {
            return Err(self.freeze(error));
        }
        self.recovery_required = false;
        Ok(())
    }

    fn heartbeat(&mut self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        self.require_live()?;
        if self.active_operation_id.as_deref() != Some(operation_id) {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let heartbeat = match self.active.as_ref() {
            Some(active) => active.heartbeat(),
            None => Err(NetworkErrorCode::InvalidStateTransition),
        };
        let heartbeat = match heartbeat {
            Ok(status) => status,
            Err(error) => return Err(self.freeze(error)),
        };
        if let Err(error) = self.validate_active_status(&heartbeat, RouteHelperV3State::Applied, 3) {
            return Err(self.freeze(error));
        }
        Ok(())
    }

    fn rollback(&mut self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        self.require_live()?;
        let Some(active_operation_id) = self.active_operation_id.as_deref() else {
            return if self.active.is_none() {
                Ok(())
            } else {
                Err(self.freeze(NetworkErrorCode::InvalidStateTransition))
            };
        };
        if active_operation_id != operation_id {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let rollback = match self.active.as_ref() {
            Some(active) => active.rollback(),
            None => Err(NetworkErrorCode::InvalidStateTransition),
        };
        let rollback = match rollback {
            Ok(status) => status,
            Err(error) => return Err(self.freeze(error)),
        };
        if let Err(error) = self.validate_rollback_status(&rollback) {
            return Err(self.freeze(error));
        }
        self.active.take();
        self.active_operation_id.take();
        self.recovery_required = false;
        Ok(())
    }
}

impl Drop for DeferredV3ProductionRouteBoundary {
    fn drop(&mut self) {
        if !self.retired
            && let Some(active) = self.active.as_ref()
        {
            let _ = active.rollback();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::networking::{
        ControllerStartReceipt, NETWORK_IPC_PROTOCOL_VERSION, SidecarHandshake, TUNNEL_BROKER_PROTOCOL_VERSION,
        TunnelBrokerSessionReference, TunnelDeviceFacts,
    };

    #[derive(Clone)]
    struct FakeClient {
        calls: Arc<Mutex<Vec<&'static str>>>,
        discovery: Option<RouteHelperV3Status>,
    }

    impl Default for FakeClient {
        fn default() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                discovery: None,
            }
        }
    }

    impl FakeClient {
        fn mark(
            &self,
            call: &'static str,
            state: RouteHelperV3State,
            transition: u64,
            reference: Option<RouteLeaseReferenceV3>,
        ) -> Result<RouteHelperV3Status, NetworkErrorCode> {
            self.calls
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .push(call);
            Ok(RouteHelperV3Status {
                protocol_version: ROUTE_HELPER_V3_PROTOCOL_VERSION,
                state,
                transition,
                reference,
                error_code: None,
            })
        }
    }

    impl RouteHelperV3Operations for FakeClient {
        fn discover(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
            self.calls
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .push("discover");
            Ok(self.discovery.clone().unwrap_or(RouteHelperV3Status {
                protocol_version: ROUTE_HELPER_V3_PROTOCOL_VERSION,
                state: RouteHelperV3State::Idle,
                transition: 0,
                reference: None,
                error_code: None,
            }))
        }

        fn begin(&self, owner: &RouteLeaseOwnerV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
            self.mark(
                "begin",
                RouteHelperV3State::Held,
                2,
                Some(RouteLeaseReferenceV3::from_owner(owner)),
            )
        }
        fn recover(&self, owner: &RouteLeaseOwnerV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
            self.mark(
                "recover",
                RouteHelperV3State::Held,
                2,
                Some(RouteLeaseReferenceV3::from_owner(owner)),
            )
        }
        fn apply(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
            self.mark("apply", RouteHelperV3State::Applied, 3, Some(reference.clone()))
        }
        fn rollback(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
            self.mark("rollback", RouteHelperV3State::Released, 5, Some(reference.clone()))
        }
        fn heartbeat(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
            self.mark("heartbeat", RouteHelperV3State::Applied, 3, Some(reference.clone()))
        }
        fn status(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
            self.mark("status", RouteHelperV3State::Applied, 3, Some(reference.clone()))
        }
    }

    struct FakeSessionFactory {
        client: FakeClient,
    }

    impl BoundRouteHelperV3SessionFactory for FakeSessionFactory {
        fn create(
            &mut self,
            authorization: BrokerRouteAuthorization,
            profile_revision: u64,
            active_mihomo_tun_interfaces: Vec<String>,
            private_cidrs: Vec<String>,
        ) -> Result<Box<dyn BoundRouteHelperV3Session>, NetworkErrorCode> {
            BrokerBoundRouteHelperV3::new(
                self.client.clone(),
                authorization,
                profile_revision,
                active_mihomo_tun_interfaces,
                private_cidrs,
            )
            .map(|session| Box::new(session) as Box<dyn BoundRouteHelperV3Session>)
        }
    }

    fn receipt() -> Result<ControllerStartReceipt, NetworkErrorCode> {
        let instance = "broker.route.seam.91";
        let broker = TunnelBrokerSessionReference {
            protocol_version: TUNNEL_BROKER_PROTOCOL_VERSION,
            generation: 91,
            sidecar_instance_id: instance.into(),
        };
        let handshake = SidecarHandshake {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            instance_id: instance.into(),
            auth_proof: "proof.seam".into(),
        };
        ControllerStartReceipt::issue(7, broker, &handshake, "proof.seam", None)
    }

    fn tunnel() -> TunnelDeviceFacts {
        TunnelDeviceFacts {
            interface_name: "utun42".into(),
            mtu: 1420,
            has_ipv4: true,
            has_ipv6: true,
            instance_id: "broker.route.seam.91".into(),
            operation_id: "operation.seam.91.prepare".into(),
        }
    }

    fn authorization() -> Result<BrokerRouteAuthorization, NetworkErrorCode> {
        receipt()?.authorize_routes(tunnel(), "lease.seam.91".into(), "operation.seam.91".into())
    }

    #[test]
    fn seam_derives_every_identity_from_sealed_authorization() -> Result<(), NetworkErrorCode> {
        let client = FakeClient::default();
        let seam = BrokerBoundRouteHelperV3::new(
            client.clone(),
            authorization()?,
            7,
            vec!["utun1024".into()],
            vec!["10.127.0.0/16".into(), "fd00:127::/48".into()],
        )?;
        assert_eq!(seam.runtime_generation(), 7);
        assert_eq!(seam.reference().broker_generation, 91);
        assert_eq!(seam.reference().sidecar_instance_id, "broker.route.seam.91");
        assert_eq!(seam.reference().lease_id, "lease.seam.91");
        assert_eq!(seam.reference().operation_id, "operation.seam.91");
        assert_eq!(seam.owner().tunnel.interface_name, "utun42");
        assert_eq!(seam.begin()?.state, RouteHelperV3State::Held);
        assert_eq!(seam.apply()?.state, RouteHelperV3State::Applied);
        assert_eq!(seam.heartbeat()?.state, RouteHelperV3State::Applied);
        assert_eq!(seam.rollback()?.state, RouteHelperV3State::Released);
        assert_eq!(seam.status()?.state, RouteHelperV3State::Applied);
        assert_eq!(
            client
                .calls
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .as_slice(),
            ["begin", "apply", "heartbeat", "rollback", "status"]
        );
        Ok(())
    }

    #[test]
    fn malformed_route_facts_are_rejected_before_client_call() -> Result<(), NetworkErrorCode> {
        let client = FakeClient::default();
        let result = BrokerBoundRouteHelperV3::new(
            client.clone(),
            authorization()?,
            7,
            vec!["utun1024".into()],
            vec!["10.127.0.0/16".into(), "10.127.0.0/16".into()],
        );
        assert!(matches!(result, Err(NetworkErrorCode::InvalidConfiguration)));
        assert!(
            client
                .calls
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn deferred_boundary_consumes_receipt_after_route_facts_and_combines_rollback() -> Result<(), NetworkErrorCode> {
        let client = FakeClient::default();
        let mut boundary =
            DeferredV3ProductionRouteBoundary::with_factory(Box::new(FakeSessionFactory { client: client.clone() }))?;
        let profile: NetworkProfile =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))
                .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        let tunnel = tunnel();
        let mihomo = MihomoTunSnapshot::inactive();
        boundary.apply_broker_bound(&profile, "operation.seam.91", &tunnel, 7, &mihomo, receipt()?)?;
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Busy);
        boundary.heartbeat("operation.seam.91")?;
        boundary.rollback("operation.seam.91")?;
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Reusable);
        assert_eq!(
            client
                .calls
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .as_slice(),
            ["discover", "begin", "apply", "heartbeat", "rollback"]
        );
        assert!(matches!(
            boundary.try_retire(),
            ProductionRouteRetirementResult::Retired(_)
        ));
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Retired);
        Ok(())
    }

    #[test]
    fn mismatched_tunnel_is_rejected_before_v3_client_creation() -> Result<(), NetworkErrorCode> {
        let client = FakeClient::default();
        let mut boundary =
            DeferredV3ProductionRouteBoundary::with_factory(Box::new(FakeSessionFactory { client: client.clone() }))?;
        let profile: NetworkProfile =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))
                .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        let mut wrong_tunnel = tunnel();
        wrong_tunnel.instance_id = "broker.route.other.92".into();
        assert_eq!(
            boundary.apply_broker_bound(
                &profile,
                "operation.seam.91",
                &wrong_tunnel,
                7,
                &MihomoTunSnapshot::inactive(),
                receipt()?,
            ),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
        assert!(
            client
                .calls
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .is_empty()
        );
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Reusable);
        Ok(())
    }

    #[test]
    fn stale_or_recovery_discovery_fails_closed_before_begin() -> Result<(), NetworkErrorCode> {
        let client = FakeClient {
            calls: Arc::new(Mutex::new(Vec::new())),
            discovery: Some(RouteHelperV3Status {
                protocol_version: ROUTE_HELPER_V3_PROTOCOL_VERSION,
                state: RouteHelperV3State::RecoveryOnly,
                transition: 0,
                reference: None,
                error_code: None,
            }),
        };
        let mut boundary =
            DeferredV3ProductionRouteBoundary::with_factory(Box::new(FakeSessionFactory { client: client.clone() }))?;
        let profile: NetworkProfile =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))
                .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        assert_eq!(
            boundary.apply_broker_bound(
                &profile,
                "operation.seam.91",
                &tunnel(),
                7,
                &MihomoTunSnapshot::inactive(),
                receipt()?,
            ),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        assert_eq!(
            client
                .calls
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .as_slice(),
            ["discover"]
        );
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::RecoveryOnly);
        Ok(())
    }
}
