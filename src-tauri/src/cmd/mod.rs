use anyhow::Result;
use smartstring::alias::String;

pub type CmdResult<T = ()> = Result<T, String>;

// Command modules
pub mod app;
pub mod backup;
pub mod clash;
pub mod lightweight;
pub mod media_unlock_checker;
pub mod network;
#[cfg(feature = "networking-dev")]
pub mod networking;
#[cfg(all(feature = "networking-vm-external-peer-lab-app", target_os = "macos"))]
pub mod networking_external_peer_lab;
#[cfg(feature = "networking-production")]
pub mod networking_production;
#[cfg(feature = "networking-userspace-lab-app")]
pub mod networking_userspace_lab;
pub mod profile;
pub mod proxy;
pub mod runtime;
pub mod save_profile;
pub mod service;
pub mod system;
pub mod uwp;
pub mod validate;
pub mod verge;
pub mod webdav;

// Re-export all command functions for backwards compatibility
pub use app::*;
pub use backup::*;
pub use clash::*;
pub use lightweight::*;
pub use media_unlock_checker::*;
pub use network::*;
#[cfg(feature = "networking-dev")]
pub use networking::*;
#[cfg(all(feature = "networking-vm-external-peer-lab-app", target_os = "macos"))]
pub use networking_external_peer_lab::*;
#[cfg(feature = "networking-production")]
pub use networking_production::*;
#[cfg(feature = "networking-userspace-lab-app")]
pub use networking_userspace_lab::*;
pub use profile::*;
pub use proxy::*;
pub use runtime::*;
pub use save_profile::*;
pub use service::*;
pub use system::*;
pub use uwp::*;
pub use validate::*;
pub use verge::*;
pub use webdav::*;

pub trait StringifyErr<T> {
    fn stringify_err(self) -> CmdResult<T>;
    fn stringify_err_log<F>(self, log_fn: F) -> CmdResult<T>
    where
        F: Fn(&str);
}

impl<T, E: std::fmt::Display> StringifyErr<T> for Result<T, E> {
    fn stringify_err(self) -> CmdResult<T> {
        self.map_err(|e| e.to_string().into())
    }

    fn stringify_err_log<F>(self, log_fn: F) -> CmdResult<T>
    where
        F: Fn(&str),
    {
        self.map_err(|e| {
            let msg = String::from(e.to_string());
            log_fn(&msg);
            msg
        })
    }
}
