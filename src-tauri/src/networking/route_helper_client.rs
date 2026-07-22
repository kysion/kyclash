use std::{ffi::CString, sync::Mutex};

use super::{
    NetworkErrorCode, NetworkProfile, ProductionRouteBoundary, ROUTE_HELPER_PROTOCOL_VERSION, RouteHelperState,
    RouteHelperStatus, RouteLeaseOwner, RouteLeaseReference, TunnelDeviceFacts,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeReply {
    transport_status: i32,
    state: i32,
    error_code: i32,
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::{c_char, c_void};

    use super::NativeReply;

    unsafe extern "C" {
        pub fn kyclash_route_helper_client_create() -> *mut c_void;
        pub fn kyclash_route_helper_client_destroy(client: *mut c_void);
        pub fn kyclash_route_helper_client_discover(client: *mut c_void) -> NativeReply;
        pub fn kyclash_route_helper_client_owner(
            client: *mut c_void,
            method: i32,
            version: u8,
            lease: *const c_char,
            operation: *const c_char,
            instance: *const c_char,
            interface_name: *const c_char,
            tunnel_operation: *const c_char,
            mtu: u16,
            revision: u64,
            cidrs: *const *const c_char,
            cidr_count: usize,
        ) -> NativeReply;
        pub fn kyclash_route_helper_client_reference(
            client: *mut c_void,
            method: i32,
            version: u8,
            lease: *const c_char,
            operation: *const c_char,
        ) -> NativeReply;
    }
}

pub struct RouteHelperClient {
    native: usize,
    request_lock: Mutex<()>,
}

impl RouteHelperClient {
    pub fn connect() -> Result<Self, NetworkErrorCode> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: The fixed bridge creates one retained NSXPC client and returns ownership.
            let native = unsafe { platform::kyclash_route_helper_client_create() } as usize;
            if native == 0 {
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            Ok(Self {
                native,
                request_lock: Mutex::new(()),
            })
        }
        #[cfg(not(target_os = "macos"))]
        Err(NetworkErrorCode::SidecarUnavailable)
    }

    pub fn discover(&self) -> Result<RouteHelperStatus, NetworkErrorCode> {
        let _guard = self
            .request_lock
            .lock()
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `native` owns a live bridge client until Drop and takes no caller data.
            native_status(
                unsafe { platform::kyclash_route_helper_client_discover(self.native as *mut _) },
                None,
            )
        }
        #[cfg(not(target_os = "macos"))]
        Err(NetworkErrorCode::SidecarUnavailable)
    }

    pub fn begin(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.owner_request(0, owner)
    }

    pub fn recover(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.owner_request(1, owner)
    }

    pub fn apply(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.reference_request(0, reference)
    }

    pub fn rollback(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.reference_request(1, reference)
    }

    pub fn heartbeat(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.reference_request(2, reference)
    }

    pub fn status(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.reference_request(3, reference)
    }

    fn owner_request(&self, method: i32, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, NetworkErrorCode> {
        owner.validate()?;
        let _guard = self
            .request_lock
            .lock()
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        let lease = c_string(&owner.lease_id)?;
        let operation = c_string(&owner.operation_id)?;
        let instance = c_string(&owner.sidecar_instance_id)?;
        let interface_name = c_string(&owner.tunnel.interface_name)?;
        let tunnel_operation = c_string(&owner.tunnel.operation_id)?;
        let cidrs = owner
            .private_cidrs
            .iter()
            .map(|value| c_string(value))
            .collect::<Result<Vec<_>, _>>()?;
        let cidr_pointers = cidrs.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
        #[cfg(target_os = "macos")]
        {
            // SAFETY: Every pointer references a validated CString retained for the entire
            // synchronous bridge call. The CIDR pointer/count pair exactly matches `cidrs`.
            native_status(
                unsafe {
                    platform::kyclash_route_helper_client_owner(
                        self.native as *mut _,
                        method,
                        owner.protocol_version,
                        lease.as_ptr(),
                        operation.as_ptr(),
                        instance.as_ptr(),
                        interface_name.as_ptr(),
                        tunnel_operation.as_ptr(),
                        owner.tunnel.mtu,
                        owner.profile_revision,
                        cidr_pointers.as_ptr(),
                        cidr_pointers.len(),
                    )
                },
                Some(owner.operation_id.clone()),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                method,
                lease,
                operation,
                instance,
                interface_name,
                tunnel_operation,
                cidr_pointers,
            );
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }

    fn reference_request(
        &self,
        method: i32,
        reference: &RouteLeaseReference,
    ) -> Result<RouteHelperStatus, NetworkErrorCode> {
        reference.validate()?;
        let _guard = self
            .request_lock
            .lock()
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        let lease = c_string(&reference.lease_id)?;
        let operation = c_string(&reference.operation_id)?;
        #[cfg(target_os = "macos")]
        {
            // SAFETY: Both pointers reference validated CStrings retained for the entire
            // synchronous bridge call, and method is selected only by fixed Rust methods.
            native_status(
                unsafe {
                    platform::kyclash_route_helper_client_reference(
                        self.native as *mut _,
                        method,
                        reference.protocol_version,
                        lease.as_ptr(),
                        operation.as_ptr(),
                    )
                },
                Some(reference.operation_id.clone()),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (method, lease, operation);
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }
}

impl Drop for RouteHelperClient {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.native != 0 {
            // SAFETY: `native` was returned retained by create and is released exactly once.
            unsafe { platform::kyclash_route_helper_client_destroy(self.native as *mut _) };
            self.native = 0;
        }
    }
}

pub struct XpcProductionRouteBoundary {
    client: RouteHelperClient,
    active: Option<RouteLeaseReference>,
}

impl XpcProductionRouteBoundary {
    pub fn connect() -> Result<Self, NetworkErrorCode> {
        let client = RouteHelperClient::connect()?;
        let discovered = client.discover()?;
        require_helper_status(&discovered, RouteHelperState::Idle)?;
        Ok(Self { client, active: None })
    }
}

impl ProductionRouteBoundary for XpcProductionRouteBoundary {
    fn apply(
        &mut self,
        profile: &NetworkProfile,
        operation_id: &str,
        tunnel: &TunnelDeviceFacts,
        profile_revision: u64,
    ) -> Result<(), NetworkErrorCode> {
        if self.active.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let owner = RouteLeaseOwner {
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
            lease_id: operation_id.to_owned(),
            operation_id: operation_id.to_owned(),
            sidecar_instance_id: tunnel.instance_id.clone(),
            profile_revision,
            tunnel: tunnel.clone(),
            private_cidrs: profile.site.private_cidrs.clone(),
        };
        owner.validate()?;
        let reference = RouteLeaseReference {
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
            lease_id: owner.lease_id.clone(),
            operation_id: owner.operation_id.clone(),
        };
        self.active = Some(reference.clone());
        let begin = match self.client.begin(&owner) {
            Ok(status) => status,
            Err(error) => {
                let _ = self.client.rollback(&reference);
                self.active = None;
                return Err(error);
            }
        };
        if let Err(error) = require_helper_status(&begin, RouteHelperState::Prepared) {
            let _ = self.client.rollback(&reference);
            self.active = None;
            return Err(error);
        }
        let applied = match self.client.apply(&reference) {
            Ok(status) => status,
            Err(error) => {
                let _ = self.client.rollback(&reference);
                self.active = None;
                return Err(error);
            }
        };
        if let Err(error) = require_helper_status(&applied, RouteHelperState::Applied) {
            let _ = self.client.rollback(&reference);
            self.active = None;
            return Err(error);
        }
        Ok(())
    }

    fn rollback(&mut self, _operation_id: &str) -> Result<(), NetworkErrorCode> {
        let Some(reference) = self.active.take() else {
            return Ok(());
        };
        let status = self.client.rollback(&reference)?;
        require_helper_status(&status, RouteHelperState::Idle)
    }
}

impl Drop for XpcProductionRouteBoundary {
    fn drop(&mut self) {
        if let Some(reference) = self.active.take() {
            let _ = self.client.rollback(&reference);
        }
    }
}

fn c_string(value: &str) -> Result<CString, NetworkErrorCode> {
    CString::new(value).map_err(|_| NetworkErrorCode::InvalidConfiguration)
}

fn native_status(reply: NativeReply, operation_id: Option<String>) -> Result<RouteHelperStatus, NetworkErrorCode> {
    if reply.transport_status != 0 {
        return Err(NetworkErrorCode::SidecarUnavailable);
    }
    let state = match reply.state {
        0 => RouteHelperState::Idle,
        1 => RouteHelperState::Prepared,
        2 => RouteHelperState::Applied,
        3 => RouteHelperState::RollingBack,
        4 => RouteHelperState::FailedClosed,
        _ => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
    };
    let error_code = match reply.error_code {
        0 => None,
        1 => Some(NetworkErrorCode::SidecarUnavailable),
        2 => Some(NetworkErrorCode::InvalidConfiguration),
        3 => Some(NetworkErrorCode::PermissionDenied),
        4..=6 => Some(NetworkErrorCode::PermissionDenied),
        7..=8 => Some(NetworkErrorCode::InvalidStateTransition),
        9 => Some(NetworkErrorCode::RouteConflict),
        _ => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
    };
    Ok(RouteHelperStatus {
        protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
        state,
        operation_id,
        error_code,
    })
}

fn require_helper_status(status: &RouteHelperStatus, expected: RouteHelperState) -> Result<(), NetworkErrorCode> {
    if let Some(error) = status.error_code {
        return Err(error);
    }
    if status.protocol_version != ROUTE_HELPER_PROTOCOL_VERSION || status.state != expected {
        return Err(NetworkErrorCode::InvalidStateTransition);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_reply_mapping_fails_closed_on_unknown_values() {
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 0,
                    state: 99,
                    error_code: 0,
                },
                None,
            ),
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: -1,
                    state: 0,
                    error_code: 0,
                },
                None,
            ),
            Err(NetworkErrorCode::SidecarUnavailable)
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 0,
                    state: 4,
                    error_code: 8,
                },
                None,
            )
            .map(|status| status.error_code),
            Ok(Some(NetworkErrorCode::InvalidStateTransition))
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 0,
                    state: 4,
                    error_code: 9,
                },
                None,
            )
            .map(|status| status.error_code),
            Ok(Some(NetworkErrorCode::RouteConflict))
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 0,
                    state: 4,
                    error_code: 99,
                },
                None,
            ),
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        );
    }

    #[test]
    fn helper_status_requires_exact_state_and_no_embedded_error() {
        let status = RouteHelperStatus {
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
            state: RouteHelperState::Prepared,
            operation_id: Some("operation.test".into()),
            error_code: None,
        };
        assert_eq!(require_helper_status(&status, RouteHelperState::Prepared), Ok(()));
        assert_eq!(
            require_helper_status(&status, RouteHelperState::Applied),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        let failed = RouteHelperStatus {
            error_code: Some(NetworkErrorCode::PermissionDenied),
            ..status
        };
        assert_eq!(
            require_helper_status(&failed, RouteHelperState::Prepared),
            Err(NetworkErrorCode::PermissionDenied)
        );
    }
}
