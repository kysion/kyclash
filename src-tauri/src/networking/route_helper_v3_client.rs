//! Typed Rust boundary for the production route-helper protocol v3.
//!
//! This module is deliberately separate from [`super::route_helper_client`].
//! The latter speaks the legacy v2 listener; mixing the two would allow a
//! broker-bound lease to lose its generation and sidecar identity.  The
//! Objective-C bridge used here accepts only the fixed route-helper Mach
//! service and v3 selectors. The production factory constructs this client
//! only after explicit Connect and a broker-bound receipt; the signed helper
//! must expose the matching v3 listener or the call fails closed.

use std::{
    ffi::{CStr, CString, c_char, c_void},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use super::{
    NetworkErrorCode, ROUTE_BROKER_PROTOCOL_VERSION, ROUTE_HELPER_V3_PROTOCOL_VERSION, RouteLeaseOwnerV3,
    RouteLeaseReferenceV3,
};

const MAX_NATIVE_TEXT: usize = 65;

/// The POD returned by `macos/route-helper/client-v3.m`.
///
/// Keep this layout in lockstep with `KCRV3ClientReply` in the C header.  The
/// bridge returns bounded UTF-8 identity fields rather than Objective-C
/// objects so Rust can perform a second, independent echo check.
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeReplyV3 {
    transport_status: i32,
    protocol_version: i32,
    state: i32,
    error_code: i32,
    transition: u64,
    broker_generation: u64,
    sidecar_instance_id: [u8; MAX_NATIVE_TEXT],
    route_lease_id: [u8; MAX_NATIVE_TEXT],
    operation_id: [u8; MAX_NATIVE_TEXT],
}

/// State values returned by the native v3 helper.  `Idle` and `FailedClosed`
/// are observations, not durable journal states; keeping them distinct avoids
/// silently treating an unowned helper as a released lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteHelperV3State {
    Idle,
    HoldPending,
    Held,
    Applied,
    RetirementPending,
    Released,
    RecoveryOnly,
    FailedClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHelperV3Status {
    pub protocol_version: u8,
    pub state: RouteHelperV3State,
    pub transition: u64,
    pub reference: Option<RouteLeaseReferenceV3>,
    pub error_code: Option<NetworkErrorCode>,
}

#[cfg(target_os = "macos")]
mod native {
    use super::{NativeReplyV3, c_char, c_void};

    unsafe extern "C" {
        pub fn kyclash_route_helper_v3_client_create() -> *mut c_void;
        pub fn kyclash_route_helper_v3_client_destroy(client: *mut c_void);
        pub fn kyclash_route_helper_v3_client_discover(client: *mut c_void) -> NativeReplyV3;
        pub fn kyclash_route_helper_v3_client_owner(
            client: *mut c_void,
            method: i32,
            route_version: u8,
            broker_version: u8,
            broker_generation: u64,
            sidecar_instance_id: *const c_char,
            route_lease_id: *const c_char,
            operation_id: *const c_char,
            interface_name: *const c_char,
            tunnel_operation_id: *const c_char,
            mtu: u16,
            profile_revision: u64,
            has_ipv4: u8,
            has_ipv6: u8,
            mihomo_interfaces: *const *const c_char,
            mihomo_count: usize,
            private_cidrs: *const *const c_char,
            cidr_count: usize,
        ) -> NativeReplyV3;
        pub fn kyclash_route_helper_v3_client_reference(
            client: *mut c_void,
            method: i32,
            route_version: u8,
            broker_version: u8,
            broker_generation: u64,
            sidecar_instance_id: *const c_char,
            route_lease_id: *const c_char,
            operation_id: *const c_char,
        ) -> NativeReplyV3;
    }
}

/// A single v3 XPC generation.  The pointer is only constructed by the
/// fixed native bridge and is never exposed to application code.
pub struct RouteHelperV3Client {
    native: usize,
    request_lock: Mutex<()>,
}

impl std::fmt::Debug for RouteHelperV3Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteHelperV3Client")
            .field("connected", &(self.native != 0))
            .finish_non_exhaustive()
    }
}

impl RouteHelperV3Client {
    pub fn connect() -> Result<Self, NetworkErrorCode> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: the bridge returns one retained client generation.  Its
            // lifetime is closed exactly once by Drop below.
            let native = unsafe { native::kyclash_route_helper_v3_client_create() } as usize;
            if native == 0 {
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            Ok(Self {
                native,
                request_lock: Mutex::new(()),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }

    pub fn discover(&self) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        let _guard = self
            .request_lock
            .lock()
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `native` is retained for this client and the call is
            // synchronous; no caller memory crosses this invocation.
            decode_native_reply(
                unsafe { native::kyclash_route_helper_v3_client_discover(self.native as *mut _) },
                None,
                false,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }

    pub fn begin(&self, owner: &RouteLeaseOwnerV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.owner_call(0, owner)
    }

    pub fn recover(&self, owner: &RouteLeaseOwnerV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.owner_call(1, owner)
    }

    pub fn apply(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.reference_call(0, reference)
    }

    pub fn rollback(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.reference_call(1, reference)
    }

    pub fn heartbeat(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.reference_call(2, reference)
    }

    pub fn status(&self, reference: &RouteLeaseReferenceV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        self.reference_call(3, reference)
    }

    fn owner_call(&self, method: i32, owner: &RouteLeaseOwnerV3) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        owner.validate().map_err(|error| error.network_code())?;
        if method != 0 && method != 1 {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let reference = owner_reference(owner);
        let sidecar = c_string(&owner.sidecar_instance_id)?;
        let lease = c_string(&owner.lease_id)?;
        let operation = c_string(&owner.operation_id)?;
        let interface_name = c_string(&owner.tunnel.interface_name)?;
        let tunnel_operation = c_string(&owner.tunnel.operation_id)?;
        let mihomo = owner
            .active_mihomo_tun_interfaces
            .iter()
            .map(|value| c_string(value))
            .collect::<Result<Vec<_>, _>>()?;
        let mihomo_ptrs = mihomo.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
        let cidrs = owner
            .private_cidrs
            .iter()
            .map(|value| c_string(value))
            .collect::<Result<Vec<_>, _>>()?;
        let cidr_ptrs = cidrs.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
        let _guard = self
            .request_lock
            .lock()
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        #[cfg(target_os = "macos")]
        {
            // SAFETY: every pointer references a CString retained for the
            // complete synchronous bridge call. Counts exactly match vectors.
            decode_native_reply(
                unsafe {
                    native::kyclash_route_helper_v3_client_owner(
                        self.native as *mut _,
                        method,
                        owner.protocol_version,
                        owner.broker_protocol_version,
                        owner.broker_generation,
                        sidecar.as_ptr(),
                        lease.as_ptr(),
                        operation.as_ptr(),
                        interface_name.as_ptr(),
                        tunnel_operation.as_ptr(),
                        owner.tunnel.mtu,
                        owner.profile_revision,
                        u8::from(owner.tunnel.has_ipv4),
                        u8::from(owner.tunnel.has_ipv6),
                        mihomo_ptrs.as_ptr(),
                        mihomo_ptrs.len(),
                        cidr_ptrs.as_ptr(),
                        cidr_ptrs.len(),
                    )
                },
                Some(&reference),
                false,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                sidecar,
                lease,
                operation,
                interface_name,
                tunnel_operation,
                mihomo_ptrs,
                cidr_ptrs,
            );
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }

    fn reference_call(
        &self,
        method: i32,
        reference: &RouteLeaseReferenceV3,
    ) -> Result<RouteHelperV3Status, NetworkErrorCode> {
        reference.validate().map_err(|error| error.network_code())?;
        if !(0..=3).contains(&method) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let sidecar = c_string(&reference.sidecar_instance_id)?;
        let lease = c_string(&reference.lease_id)?;
        let operation = c_string(&reference.operation_id)?;
        let _guard = self
            .request_lock
            .lock()
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        #[cfg(target_os = "macos")]
        {
            // SAFETY: the three CStrings stay alive through the synchronous
            // native call and the client owns the bridge pointer.
            decode_native_reply(
                unsafe {
                    native::kyclash_route_helper_v3_client_reference(
                        self.native as *mut _,
                        method,
                        reference.protocol_version,
                        reference.broker_protocol_version,
                        reference.broker_generation,
                        sidecar.as_ptr(),
                        lease.as_ptr(),
                        operation.as_ptr(),
                    )
                },
                Some(reference),
                method == 1,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (sidecar, lease, operation);
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }
}

impl Drop for RouteHelperV3Client {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.native != 0 {
            // SAFETY: `native` was returned retained by create and is released
            // exactly once. No request can be active because the client owns
            // the final Rust handle during Drop.
            unsafe { native::kyclash_route_helper_v3_client_destroy(self.native as *mut _) };
            self.native = 0;
        }
    }
}

fn owner_reference(owner: &RouteLeaseOwnerV3) -> RouteLeaseReferenceV3 {
    RouteLeaseReferenceV3::from_owner(owner)
}

fn c_string(value: &str) -> Result<CString, NetworkErrorCode> {
    CString::new(value).map_err(|_| NetworkErrorCode::InvalidConfiguration)
}

fn decode_native_reply(
    reply: NativeReplyV3,
    expected: Option<&RouteLeaseReferenceV3>,
    allow_idle_without_reference: bool,
) -> Result<RouteHelperV3Status, NetworkErrorCode> {
    match reply.transport_status {
        0 => {}
        1 => return Err(NetworkErrorCode::OperationTimedOut),
        2 | 4 | 6 => return Err(NetworkErrorCode::SidecarUnavailable),
        3 => return Err(NetworkErrorCode::OperationCancelled),
        5 => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
        7 => return Err(NetworkErrorCode::InvalidConfiguration),
        _ => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
    }
    if reply.protocol_version != i32::from(ROUTE_HELPER_V3_PROTOCOL_VERSION) {
        return Err(NetworkErrorCode::UnsupportedProtocolVersion);
    }
    let state = match reply.state {
        0 => RouteHelperV3State::Idle,
        1 => RouteHelperV3State::HoldPending,
        2 => RouteHelperV3State::Held,
        3 => RouteHelperV3State::Applied,
        4 => RouteHelperV3State::RetirementPending,
        5 => RouteHelperV3State::Released,
        6 => RouteHelperV3State::RecoveryOnly,
        7 => RouteHelperV3State::FailedClosed,
        _ => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
    };
    let raw_idle = reply.state == 0;
    let error_code = match reply.error_code {
        0 => None,
        1 => Some(NetworkErrorCode::SidecarUnavailable),
        2 => Some(NetworkErrorCode::InvalidConfiguration),
        3 => Some(NetworkErrorCode::PermissionDenied),
        4 => Some(NetworkErrorCode::RouteJournalUnavailable),
        5 => Some(NetworkErrorCode::RouteJournalCorrupted),
        6 | 7 => Some(NetworkErrorCode::RouteRollbackFailed),
        8 => Some(NetworkErrorCode::RouteConflict),
        9 => Some(NetworkErrorCode::InvalidStateTransition),
        10 => Some(NetworkErrorCode::AuthenticationFailed),
        11 | 12 => Some(NetworkErrorCode::SidecarUnavailable),
        _ => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
    };
    let sidecar = bounded_text(&reply.sidecar_instance_id)?;
    let lease = bounded_text(&reply.route_lease_id)?;
    let operation = bounded_text(&reply.operation_id)?;
    let has_any_identity = sidecar.is_some() || lease.is_some() || operation.is_some() || reply.broker_generation != 0;
    let echoed = if has_any_identity {
        let (Some(sidecar), Some(lease), Some(operation)) = (sidecar, lease, operation) else {
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        };
        let reference = RouteLeaseReferenceV3 {
            protocol_version: ROUTE_HELPER_V3_PROTOCOL_VERSION,
            broker_protocol_version: ROUTE_BROKER_PROTOCOL_VERSION,
            broker_generation: reply.broker_generation,
            sidecar_instance_id: sidecar,
            lease_id: lease,
            operation_id: operation,
        };
        reference.validate().map_err(|error| error.network_code())?;
        Some(reference)
    } else {
        None
    };
    match expected {
        None => {
            if echoed.is_some() || reply.transition != 0 || (!raw_idle && reply.state != 6 && reply.state != 7) {
                return Err(NetworkErrorCode::AuthenticationFailed);
            }
        }
        Some(expected) => match echoed.as_ref() {
            Some(actual) if actual == expected => {}
            None if allow_idle_without_reference && raw_idle && error_code.is_none() => {}
            _ => return Err(NetworkErrorCode::AuthenticationFailed),
        },
    }
    if echoed.is_some() && reply.transition == 0 {
        return Err(NetworkErrorCode::UnsupportedProtocolVersion);
    }
    Ok(RouteHelperV3Status {
        protocol_version: ROUTE_HELPER_V3_PROTOCOL_VERSION,
        state,
        transition: reply.transition,
        reference: echoed,
        error_code,
    })
}

fn bounded_text(value: &[u8; MAX_NATIVE_TEXT]) -> Result<Option<String>, NetworkErrorCode> {
    let Some(end) = value.iter().position(|byte| *byte == 0) else {
        return Err(NetworkErrorCode::UnsupportedProtocolVersion);
    };
    if value[end + 1..].iter().any(|byte| *byte != 0) {
        return Err(NetworkErrorCode::UnsupportedProtocolVersion);
    }
    if end == 0 {
        return Ok(None);
    }
    let text = CStr::from_bytes_with_nul(&value[..=end])
        .map_err(|_| NetworkErrorCode::UnsupportedProtocolVersion)?
        .to_str()
        .map_err(|_| NetworkErrorCode::UnsupportedProtocolVersion)?
        .to_owned();
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    fn reference() -> RouteLeaseReferenceV3 {
        RouteLeaseReferenceV3 {
            protocol_version: ROUTE_HELPER_V3_PROTOCOL_VERSION,
            broker_protocol_version: ROUTE_BROKER_PROTOCOL_VERSION,
            broker_generation: 17,
            sidecar_instance_id: "instance.v3.test".into(),
            lease_id: "lease.v3.test".into(),
            operation_id: "operation.v3.test".into(),
        }
    }

    fn bytes(value: &str) -> [u8; MAX_NATIVE_TEXT] {
        let mut result = [0; MAX_NATIVE_TEXT];
        result[..value.len()].copy_from_slice(value.as_bytes());
        result
    }

    fn reply(state: i32, transition: u64, reference: Option<&RouteLeaseReferenceV3>) -> NativeReplyV3 {
        let mut value = NativeReplyV3 {
            transport_status: 0,
            protocol_version: i32::from(ROUTE_HELPER_V3_PROTOCOL_VERSION),
            state,
            error_code: 0,
            transition,
            broker_generation: 0,
            sidecar_instance_id: [0; MAX_NATIVE_TEXT],
            route_lease_id: [0; MAX_NATIVE_TEXT],
            operation_id: [0; MAX_NATIVE_TEXT],
        };
        if let Some(reference) = reference {
            value.broker_generation = reference.broker_generation;
            value.sidecar_instance_id = bytes(&reference.sidecar_instance_id);
            value.route_lease_id = bytes(&reference.lease_id);
            value.operation_id = bytes(&reference.operation_id);
        }
        value
    }

    #[test]
    fn abi_layout_is_pinned_and_exact_tuple_is_decoded() -> Result<(), NetworkErrorCode> {
        assert_eq!(size_of::<NativeReplyV3>(), 232);
        let reference = reference();
        let decoded = decode_native_reply(reply(2, 2, Some(&reference)), Some(&reference), false)?;
        assert_eq!(decoded.state, RouteHelperV3State::Held);
        assert_eq!(decoded.reference, Some(reference));
        assert_eq!(decoded.transition, 2);
        Ok(())
    }

    #[test]
    fn stale_or_partial_echo_fails_closed() {
        let expected = reference();
        let mut stale = expected.clone();
        stale.broker_generation += 1;
        assert_eq!(
            decode_native_reply(reply(2, 2, Some(&stale)), Some(&expected), false),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
        let mut partial = reply(2, 2, Some(&expected));
        partial.operation_id = [0; MAX_NATIVE_TEXT];
        assert_eq!(
            decode_native_reply(partial, Some(&expected), false),
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        );
    }

    #[test]
    fn discover_and_idempotent_rollback_allow_only_unowned_idle() -> Result<(), NetworkErrorCode> {
        let idle = reply(0, 0, None);
        let discovered = decode_native_reply(idle, None, false)?;
        assert_eq!(discovered.reference, None);

        let expected = reference();
        assert!(decode_native_reply(reply(0, 0, None), Some(&expected), true).is_ok());
        assert_eq!(
            decode_native_reply(reply(0, 0, None), Some(&expected), false),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
        Ok(())
    }
}
