#[cfg(all(
    not(feature = "clippy"),
    any(
        all(feature = "networking-vm-network-lab-app", feature = "networking-vm-utun-lab-app"),
        all(feature = "networking-vm-network-lab-app", feature = "networking-production"),
        all(feature = "networking-vm-utun-lab-app", feature = "networking-production"),
        all(
            feature = "networking-vm-external-peer-lab-app",
            feature = "networking-userspace-lab-app"
        ),
        all(
            feature = "networking-vm-external-peer-lab-app",
            feature = "networking-vm-network-lab-app"
        ),
        all(
            feature = "networking-vm-external-peer-lab-app",
            feature = "networking-vm-utun-lab-app"
        ),
        all(feature = "networking-vm-external-peer-lab-app", feature = "networking-production"),
    )
))]
compile_error!("networking App profiles are mutually exclusive with each other and networking-production");

#[cfg(all(feature = "networking-production", unix))]
mod broker_bound_route_v3;
mod config;
mod credentials;
mod data_plane;
mod diagnostics;
mod ipc;
mod macos_route;
mod mihomo_tun_source;
mod mock;
mod mock_control;
mod operation;
mod policy;
#[cfg(any(feature = "networking-production", feature = "networking-system-lab"))]
mod policy_identity_store;
#[cfg(feature = "networking-dev")]
mod process_runtime;
#[cfg(feature = "networking-production")]
mod production_composition;
#[cfg(feature = "networking-production")]
mod production_controller;
#[cfg(feature = "networking-production")]
mod production_policy_catalog;
#[cfg(all(feature = "networking-production", unix))]
mod production_route_v3;
#[cfg(feature = "networking-production")]
mod production_service;
#[cfg(all(feature = "networking-production", unix))]
mod production_session;
mod route;
mod route_helper;
#[cfg(feature = "networking-production")]
mod route_helper_client;
#[cfg(feature = "networking-production")]
mod route_helper_registration;
mod route_helper_v3;
#[cfg(all(feature = "networking-production", unix))]
mod route_helper_v3_client;
mod sidecar;
mod sidecar_trust;
mod state;
mod stdio_runtime;
#[cfg(all(feature = "networking-production", unix))]
mod tunnel_broker_client;
#[cfg(all(feature = "networking-vm-external-peer-lab-app", target_os = "macos"))]
mod vm_external_peer_lab_socket;
#[cfg(all(feature = "networking-vm-network-lab-app", target_os = "macos"))]
mod vm_network_lab_socket;
#[cfg(all(feature = "networking-vm-utun-lab-app", target_os = "macos"))]
mod vm_utun_lab_socket;

#[cfg(all(feature = "networking-production", unix))]
pub use self::broker_bound_route_v3::*;
#[cfg(any(feature = "networking-production", feature = "networking-system-lab"))]
pub use self::policy_identity_store::*;
#[cfg(feature = "networking-dev")]
pub use self::process_runtime::*;
#[cfg(feature = "networking-production")]
pub use self::production_composition::*;
#[cfg(feature = "networking-production")]
pub use self::production_controller::*;
#[cfg(feature = "networking-production")]
pub use self::production_policy_catalog::*;
#[cfg(all(feature = "networking-production", unix))]
pub use self::production_route_v3::*;
#[cfg(feature = "networking-production")]
pub use self::production_service::*;
#[cfg(all(feature = "networking-production", unix))]
pub use self::production_session::*;
#[cfg(feature = "networking-production")]
pub use self::route_helper_client::*;
#[cfg(feature = "networking-production")]
pub use self::route_helper_registration::*;
#[cfg(all(feature = "networking-production", unix))]
pub use self::route_helper_v3_client::*;
#[cfg(all(feature = "networking-production", unix))]
pub use self::tunnel_broker_client::*;
#[cfg(all(feature = "networking-vm-external-peer-lab-app", target_os = "macos"))]
pub use self::vm_external_peer_lab_socket::*;
#[cfg(all(feature = "networking-vm-network-lab-app", target_os = "macos"))]
pub use self::vm_network_lab_socket::*;
#[cfg(all(feature = "networking-vm-utun-lab-app", target_os = "macos"))]
pub use self::vm_utun_lab_socket::*;
pub use self::{
    config::*, credentials::*, data_plane::*, diagnostics::*, ipc::*, macos_route::*, mihomo_tun_source::*, mock::*,
    mock_control::*, operation::*, policy::*, route::*, route_helper::*, route_helper_v3::*, sidecar::*,
    sidecar_trust::*, state::*, stdio_runtime::*,
};
