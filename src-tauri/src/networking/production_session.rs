//! Broker-bound production session material and start receipts.
//!
//! This module is intentionally independent of the native XPC composition.
//! It provides the linear identity boundary that must be satisfied before a
//! controller can publish a production start: a fresh broker reference owns
//! the sidecar instance ID, launch material is consumed once, and the receipt
//! pins the runtime generation to that exact reference.  The production
//! factory remains unwired until the route-helper v3 native interlock is
//! available.

use zeroize::Zeroizing;

use super::{
    NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode, ROUTE_BROKER_PROTOCOL_VERSION, RouteLeaseBinding, SidecarHandshake,
    SidecarLaunchContext, TunnelBrokerSessionReference, TunnelDeviceFacts, sidecar_auth_proof,
};

mod authorization_seal {
    pub(super) struct Seal;
}

/// Ephemeral authentication and WireGuard material for one sidecar attempt.
///
/// A value is consumed by [`Self::bind`] and must never be reused for a
/// restart.  Both buffers are zeroized when the value or its bound context is
/// dropped.
pub struct SidecarLaunchMaterial {
    auth_token: Zeroizing<Vec<u8>>,
    private_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SidecarLaunchMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SidecarLaunchMaterial([REDACTED])")
    }
}

impl SidecarLaunchMaterial {
    pub fn new(auth_token: Vec<u8>, private_key: Vec<u8>) -> Result<Self, NetworkErrorCode> {
        if auth_token.len() != 32 || private_key.len() != 32 {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self {
            auth_token: Zeroizing::new(auth_token),
            private_key: Zeroizing::new(private_key),
        })
    }

    /// Bind this one-shot material to the broker-assigned reference.  The
    /// caller cannot select or override the sidecar instance ID.
    pub fn bind(self, reference: TunnelBrokerSessionReference) -> Result<BoundSidecarLaunch, NetworkErrorCode> {
        reference.validate()?;
        let Self {
            auth_token,
            private_key,
        } = self;
        let instance_id = reference.sidecar_instance_id.clone();
        let expected_auth_proof = Zeroizing::new(sidecar_auth_proof(&auth_token, &instance_id));
        let context =
            SidecarLaunchContext::new(instance_id, auth_token.to_vec()).with_private_key(private_key.to_vec());
        Ok(BoundSidecarLaunch {
            reference,
            context,
            expected_auth_proof,
        })
    }
}

/// A one-shot context/proof pair bound to one broker session reference.
pub struct BoundSidecarLaunch {
    reference: TunnelBrokerSessionReference,
    context: SidecarLaunchContext,
    expected_auth_proof: Zeroizing<String>,
}

impl std::fmt::Debug for BoundSidecarLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundSidecarLaunch")
            .field("reference", &self.reference)
            .field("context", &self.context)
            .field("expected_auth_proof", &"<redacted>")
            .finish()
    }
}

impl BoundSidecarLaunch {
    #[must_use]
    pub const fn reference(&self) -> &TunnelBrokerSessionReference {
        &self.reference
    }

    #[must_use]
    pub const fn context(&self) -> &SidecarLaunchContext {
        &self.context
    }

    /// Consume the bound launch at the controller start boundary.
    pub fn into_parts(self) -> (TunnelBrokerSessionReference, SidecarLaunchContext, String) {
        let Self {
            reference,
            context,
            mut expected_auth_proof,
        } = self;
        let proof = std::mem::take(&mut *expected_auth_proof);
        (reference, context, proof)
    }
}

/// Non-copyable proof that a controller handshake was accepted for one exact
/// runtime generation and broker session.  Route code may retain this receipt
/// but cannot manufacture it from mutable launcher state.
#[derive(Debug, PartialEq, Eq)]
pub struct ControllerStartReceipt {
    runtime_generation: u64,
    broker_reference: TunnelBrokerSessionReference,
}

impl ControllerStartReceipt {
    pub(super) fn issue(
        runtime_generation: u64,
        broker_reference: TunnelBrokerSessionReference,
        handshake: &SidecarHandshake,
        expected_auth_proof: &str,
        tunnel: Option<&TunnelDeviceFacts>,
    ) -> Result<Self, NetworkErrorCode> {
        broker_reference.validate()?;
        if runtime_generation == 0
            || handshake.protocol_version != NETWORK_IPC_PROTOCOL_VERSION
            || handshake.instance_id != broker_reference.sidecar_instance_id
            || handshake.auth_proof != expected_auth_proof
            || tunnel.is_some_and(|facts| facts.instance_id != broker_reference.sidecar_instance_id)
        {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        Ok(Self {
            runtime_generation,
            broker_reference,
        })
    }

    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    #[must_use]
    pub const fn broker_reference(&self) -> &TunnelBrokerSessionReference {
        &self.broker_reference
    }

    /// Consume this exact accepted-start receipt and bind it to one verified
    /// tunnel plus one route lease/operation tuple.
    ///
    /// `TunnelDeviceFacts.operation_id` must be the prepare request belonging
    /// to `operation_id`. This check closes the bootstrap/handshake/tunnel/
    /// route-owner identity chain before a journal, broker, or route-helper
    /// adapter can be called.
    pub fn authorize_routes(
        self,
        tunnel: TunnelDeviceFacts,
        lease_id: String,
        operation_id: String,
    ) -> Result<BrokerRouteAuthorization, NetworkErrorCode> {
        let Self {
            runtime_generation,
            broker_reference,
        } = self;
        broker_reference.validate()?;
        if broker_reference.protocol_version != ROUTE_BROKER_PROTOCOL_VERSION {
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        let binding = RouteLeaseBinding {
            broker_protocol_version: broker_reference.protocol_version,
            broker_generation: broker_reference.generation,
            sidecar_instance_id: broker_reference.sidecar_instance_id,
            lease_id,
            operation_id,
        };
        binding.validate().map_err(|error| error.network_code())?;
        tunnel.validate(
            &binding.sidecar_instance_id,
            &format!("{}.prepare", binding.operation_id),
        )?;
        Ok(BrokerRouteAuthorization {
            _seal: authorization_seal::Seal,
            runtime_generation,
            binding,
            tunnel,
        })
    }
}

/// Sealed, linear authority for one controller generation and one exact v3
/// route tuple.
///
/// This type deliberately implements neither `Clone` nor serialization and
/// exposes no constructor or public fields. Code can obtain it only by
/// consuming a [`ControllerStartReceipt`] after the tunnel identity and
/// prepare-operation correlation have been verified.
pub struct BrokerRouteAuthorization {
    _seal: authorization_seal::Seal,
    runtime_generation: u64,
    binding: RouteLeaseBinding,
    tunnel: TunnelDeviceFacts,
}

impl BrokerRouteAuthorization {
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    #[must_use]
    pub const fn broker_generation(&self) -> u64 {
        self.binding.broker_generation
    }

    pub(super) const fn binding(&self) -> &RouteLeaseBinding {
        &self.binding
    }

    pub(super) const fn tunnel(&self) -> &TunnelDeviceFacts {
        &self.tunnel
    }
}

/// Validate the identity equality required before any route mutation.
pub fn validate_start_identity(
    reference: &TunnelBrokerSessionReference,
    handshake: &SidecarHandshake,
    tunnel: &TunnelDeviceFacts,
) -> Result<(), NetworkErrorCode> {
    reference.validate()?;
    if handshake.instance_id != reference.sidecar_instance_id || tunnel.instance_id != reference.sidecar_instance_id {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::TUNNEL_BROKER_PROTOCOL_VERSION;

    fn reference(generation: u64, instance: &str) -> TunnelBrokerSessionReference {
        TunnelBrokerSessionReference {
            protocol_version: TUNNEL_BROKER_PROTOCOL_VERSION,
            generation,
            sidecar_instance_id: instance.into(),
        }
    }

    fn handshake(instance: &str) -> SidecarHandshake {
        SidecarHandshake {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            instance_id: instance.into(),
            auth_proof: "proof.redacted".into(),
        }
    }

    #[test]
    fn material_binds_only_the_broker_instance_and_consumes_once() -> Result<(), NetworkErrorCode> {
        let bound =
            SidecarLaunchMaterial::new(vec![0x11; 32], vec![0x22; 32])?.bind(reference(7, "broker.instance.7"))?;
        assert_eq!(bound.context().instance_id, "broker.instance.7");
        assert_eq!(bound.context().private_key(), &[0x22; 32]);
        assert!(!format!("{bound:?}").contains("11"));
        let (reference, context, proof) = bound.into_parts();
        assert_eq!(reference.generation, 7);
        assert_eq!(context.instance_id, "broker.instance.7");
        assert_eq!(proof.len(), 64);
        Ok(())
    }

    #[test]
    fn start_receipt_requires_handshake_and_tunnel_identity_equality() -> Result<(), NetworkErrorCode> {
        let reference = reference(9, "broker.instance.9");
        let handshake = handshake("broker.instance.9");
        let tunnel = TunnelDeviceFacts {
            interface_name: "utun42".into(),
            mtu: 1420,
            has_ipv4: true,
            has_ipv6: true,
            instance_id: "broker.instance.9".into(),
            operation_id: "operation.prepare".into(),
        };
        let receipt = ControllerStartReceipt::issue(3, reference.clone(), &handshake, "proof.redacted", Some(&tunnel))?;
        assert_eq!(receipt.runtime_generation(), 3);
        assert_eq!(receipt.broker_reference(), &reference);
        let mut wrong = tunnel;
        wrong.instance_id = "broker.other".into();
        assert_eq!(
            ControllerStartReceipt::issue(3, reference, &handshake, "proof.redacted", Some(&wrong)).err(),
            Some(NetworkErrorCode::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn stale_or_zero_generation_cannot_issue_a_receipt() {
        let reference = reference(1, "broker.instance.1");
        let handshake = handshake("broker.instance.1");
        assert_eq!(
            ControllerStartReceipt::issue(0, reference.clone(), &handshake, "proof.redacted", None).err(),
            Some(NetworkErrorCode::AuthenticationFailed)
        );
        let mut wrong = handshake;
        wrong.instance_id = "broker.other".into();
        assert_eq!(
            ControllerStartReceipt::issue(1, reference, &wrong, "proof.redacted", None).err(),
            Some(NetworkErrorCode::AuthenticationFailed)
        );
    }

    #[test]
    fn receipt_consumption_preserves_independent_generations_and_rejects_tunnel_mismatch()
    -> Result<(), NetworkErrorCode> {
        let broker = reference(91, "broker.instance.91");
        let handshake = handshake("broker.instance.91");
        let receipt = ControllerStartReceipt::issue(7, broker.clone(), &handshake, "proof.redacted", None)?;
        let tunnel = TunnelDeviceFacts {
            interface_name: "utun42".into(),
            mtu: 1420,
            has_ipv4: true,
            has_ipv6: true,
            instance_id: "broker.instance.91".into(),
            operation_id: "operation.route.91.prepare".into(),
        };
        let authorization =
            receipt.authorize_routes(tunnel.clone(), "lease.route.91".into(), "operation.route.91".into())?;
        assert_eq!(authorization.runtime_generation(), 7);
        assert_eq!(authorization.broker_generation(), 91);
        assert_eq!(authorization.binding().broker_generation, 91);

        let second_receipt = ControllerStartReceipt::issue(8, broker, &handshake, "proof.redacted", None)?;
        let mut wrong_tunnel = tunnel;
        wrong_tunnel.instance_id = "broker.other.91".into();
        assert_eq!(
            second_receipt
                .authorize_routes(wrong_tunnel, "lease.route.91".into(), "operation.route.91".into(),)
                .err(),
            Some(NetworkErrorCode::AuthenticationFailed)
        );
        Ok(())
    }
}
