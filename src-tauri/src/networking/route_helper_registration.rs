use super::NetworkErrorCode;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteHelperRegistrationStatus {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
    Unknown,
}

#[cfg(target_os = "macos")]
mod platform {
    unsafe extern "C" {
        fn kyclash_route_helper_status() -> i32;
        fn kyclash_route_helper_register() -> i32;
        fn kyclash_route_helper_unregister() -> i32;
        fn kyclash_route_helper_open_settings();
        fn kyclash_tunnel_broker_status() -> i32;
        fn kyclash_tunnel_broker_register() -> i32;
        fn kyclash_tunnel_broker_unregister() -> i32;
        fn kyclash_privileged_networking_verify_bundled_requirements() -> i32;
    }

    pub fn status() -> i32 {
        // SAFETY: The fixed C bridge takes no pointers or caller-controlled data.
        unsafe { kyclash_route_helper_status() }
    }

    pub fn register() -> i32 {
        // SAFETY: Registration targets only the compile-time fixed bundled plist.
        unsafe { kyclash_route_helper_register() }
    }

    pub fn unregister() -> i32 {
        // SAFETY: Unregistration targets only the compile-time fixed bundled plist.
        unsafe { kyclash_route_helper_unregister() }
    }

    pub fn open_settings() {
        // SAFETY: The bridge only opens Apple's Login Items settings pane.
        unsafe { kyclash_route_helper_open_settings() }
    }

    pub fn broker_status() -> i32 {
        // SAFETY: The bridge reads only the fixed broker SMAppService status.
        unsafe { kyclash_tunnel_broker_status() }
    }

    pub fn broker_register() -> i32 {
        // SAFETY: Registration targets only the compile-time fixed broker plist.
        unsafe { kyclash_tunnel_broker_register() }
    }

    pub fn broker_unregister() -> i32 {
        // SAFETY: Unregistration targets only the compile-time fixed broker plist.
        unsafe { kyclash_tunnel_broker_unregister() }
    }

    pub fn verify_bundled_requirements() -> bool {
        // SAFETY: the bridge reads only fixed bundle resources and validates
        // their designated requirements; it accepts no caller-provided data.
        unsafe { kyclash_privileged_networking_verify_bundled_requirements() == 0 }
    }
}

pub fn route_helper_registration_status() -> RouteHelperRegistrationStatus {
    #[cfg(target_os = "macos")]
    let raw = platform::status();
    #[cfg(not(target_os = "macos"))]
    let raw = 0;
    match raw {
        0 => RouteHelperRegistrationStatus::NotRegistered,
        1 => RouteHelperRegistrationStatus::Enabled,
        2 => RouteHelperRegistrationStatus::RequiresApproval,
        3 => RouteHelperRegistrationStatus::NotFound,
        _ => RouteHelperRegistrationStatus::Unknown,
    }
}

pub fn register_route_helper() -> Result<(), NetworkErrorCode> {
    #[cfg(target_os = "macos")]
    if platform::register() == 0 {
        return Ok(());
    }
    Err(NetworkErrorCode::SidecarUnavailable)
}

pub fn unregister_route_helper() -> Result<(), NetworkErrorCode> {
    #[cfg(target_os = "macos")]
    if platform::unregister() == 0 {
        return Ok(());
    }
    Err(NetworkErrorCode::SidecarUnavailable)
}

pub fn open_route_helper_settings() {
    #[cfg(target_os = "macos")]
    platform::open_settings();
}

pub fn tunnel_broker_registration_status() -> RouteHelperRegistrationStatus {
    #[cfg(target_os = "macos")]
    let raw = platform::broker_status();
    #[cfg(not(target_os = "macos"))]
    let raw = 0;
    map_registration_status(raw)
}

pub fn register_tunnel_broker() -> Result<(), NetworkErrorCode> {
    #[cfg(target_os = "macos")]
    if platform::broker_register() == 0 {
        return Ok(());
    }
    Err(NetworkErrorCode::SidecarUnavailable)
}

pub fn unregister_tunnel_broker() -> Result<(), NetworkErrorCode> {
    #[cfg(target_os = "macos")]
    if platform::broker_unregister() == 0 {
        return Ok(());
    }
    Err(NetworkErrorCode::SidecarUnavailable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PrivilegedNetworkingServicesStatus {
    pub route_helper: RouteHelperRegistrationStatus,
    pub tunnel_broker: RouteHelperRegistrationStatus,
    pub ready: bool,
}

pub fn privileged_networking_services_status() -> PrivilegedNetworkingServicesStatus {
    let route_helper = route_helper_registration_status();
    let tunnel_broker = tunnel_broker_registration_status();
    PrivilegedNetworkingServicesStatus {
        route_helper,
        tunnel_broker,
        ready: route_helper == RouteHelperRegistrationStatus::Enabled
            && tunnel_broker == RouteHelperRegistrationStatus::Enabled,
    }
}

pub fn register_privileged_networking_services() -> Result<PrivilegedNetworkingServicesStatus, NetworkErrorCode> {
    let current = privileged_networking_services_status();
    if current.route_helper != RouteHelperRegistrationStatus::Enabled {
        register_route_helper()?;
    }
    if current.tunnel_broker != RouteHelperRegistrationStatus::Enabled {
        register_tunnel_broker()?;
    }
    Ok(privileged_networking_services_status())
}

pub fn unregister_privileged_networking_services() -> Result<PrivilegedNetworkingServicesStatus, NetworkErrorCode> {
    // Retire the route mutator first; the broker must not outlive a helper
    // that can no longer prove route rollback.
    if route_helper_registration_status() == RouteHelperRegistrationStatus::Enabled {
        unregister_route_helper()?;
    }
    if tunnel_broker_registration_status() == RouteHelperRegistrationStatus::Enabled {
        unregister_tunnel_broker()?;
    }
    Ok(privileged_networking_services_status())
}

pub fn ensure_privileged_networking_services_ready() -> Result<(), NetworkErrorCode> {
    let status = privileged_networking_services_status();
    if status.ready {
        #[cfg(target_os = "macos")]
        if !platform::verify_bundled_requirements() {
            return Err(NetworkErrorCode::PermissionDenied);
        }
        return Ok(());
    }
    if [status.route_helper, status.tunnel_broker].iter().any(|value| {
        matches!(
            value,
            RouteHelperRegistrationStatus::NotRegistered | RouteHelperRegistrationStatus::RequiresApproval
        )
    }) {
        return Err(NetworkErrorCode::PermissionDenied);
    }
    Err(NetworkErrorCode::SidecarUnavailable)
}

const fn map_registration_status(raw: i32) -> RouteHelperRegistrationStatus {
    match raw {
        0 => RouteHelperRegistrationStatus::NotRegistered,
        1 => RouteHelperRegistrationStatus::Enabled,
        2 => RouteHelperRegistrationStatus::RequiresApproval,
        3 => RouteHelperRegistrationStatus::NotFound,
        _ => RouteHelperRegistrationStatus::Unknown,
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platform_never_registers_or_unregisters() {
        assert_eq!(
            route_helper_registration_status(),
            RouteHelperRegistrationStatus::NotRegistered
        );
        assert_eq!(register_route_helper(), Err(NetworkErrorCode::SidecarUnavailable));
        assert_eq!(unregister_route_helper(), Err(NetworkErrorCode::SidecarUnavailable));
        assert_eq!(
            privileged_networking_services_status(),
            PrivilegedNetworkingServicesStatus {
                route_helper: RouteHelperRegistrationStatus::NotRegistered,
                tunnel_broker: RouteHelperRegistrationStatus::NotRegistered,
                ready: false,
            }
        );
        assert_eq!(
            ensure_privileged_networking_services_ready(),
            Err(NetworkErrorCode::PermissionDenied)
        );
    }
}
