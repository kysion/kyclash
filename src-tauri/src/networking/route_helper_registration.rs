use super::NetworkErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    }
}
