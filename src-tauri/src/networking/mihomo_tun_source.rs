//! Typed observation of the TUN interface currently owned by Mihomo.
//!
//! The route helper must never infer ownership from an interface name.  This
//! module is the narrow trust boundary between the managed Mihomo control API
//! and the route lease: a successful observation contains either no active
//! Mihomo interface or exactly one live, canonical Darwin `utunN` interface.
//! The macOS implementation is intentionally kept behind the production
//! feature; the pure observation function and the injectable source trait are
//! available to unit tests on every platform.

use serde::{Deserialize, Serialize};

use super::NetworkErrorCode;

/// KyClash currently supports one active Mihomo TUN in the single-site scope.
pub const MAX_ACTIVE_MIHOMO_TUN_INTERFACES: usize = 1;

/// The frozen, typed result passed to the route-helper boundary.
///
/// An empty vector means that Mihomo is stopped or its TUN is disabled.  A
/// non-empty value always contains exactly one canonical `utunN` name.  The
/// field is deliberately named like the v2 wire field so callers can pass the
/// value through without rebuilding an untyped dictionary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MihomoTunSnapshot {
    pub active_mihomo_tun_interfaces: Vec<String>,
}

impl MihomoTunSnapshot {
    /// Construct the safe inactive state.
    #[must_use]
    pub const fn inactive() -> Self {
        Self {
            active_mihomo_tun_interfaces: Vec::new(),
        }
    }

    /// Construct an active snapshot after validating the interface shape and
    /// ensuring it cannot collide with KyClash's own tunnel.
    pub fn active(interface_name: impl Into<String>, kyclash_interface: &str) -> Result<Self, NetworkErrorCode> {
        let interface_name = interface_name.into();
        let snapshot = Self {
            active_mihomo_tun_interfaces: vec![interface_name],
        };
        snapshot.validate_for(kyclash_interface)?;
        Ok(snapshot)
    }

    /// Return the frozen interface allowlist without exposing mutable state.
    #[must_use]
    pub fn interfaces(&self) -> &[String] {
        &self.active_mihomo_tun_interfaces
    }

    /// Consume the snapshot when constructing a v2 route owner.
    #[must_use]
    pub fn into_interfaces(self) -> Vec<String> {
        self.active_mihomo_tun_interfaces
    }

    /// Validate the complete snapshot against the tunnel owned by KyClash.
    pub fn validate_for(&self, kyclash_interface: &str) -> Result<(), NetworkErrorCode> {
        if !valid_utun_interface(kyclash_interface)
            || self.active_mihomo_tun_interfaces.len() > MAX_ACTIVE_MIHOMO_TUN_INTERFACES
            || !all_unique_and_sorted(&self.active_mihomo_tun_interfaces)
            || self
                .active_mihomo_tun_interfaces
                .iter()
                .any(|interface| !valid_utun_interface(interface))
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        if self
            .active_mihomo_tun_interfaces
            .iter()
            .any(|interface| interface == kyclash_interface)
        {
            return Err(NetworkErrorCode::RouteConflict);
        }
        Ok(())
    }
}

/// Observe the result of Mihomo's live config and the Darwin interface table.
///
/// This function has no application or platform dependencies, which lets the
/// production adapter and deterministic fakes share precisely the same
/// fail-closed rules.  `core_running == false` is intentionally handled before
/// the other fields: a stopped core has no trusted active interface.
pub fn snapshot_from_observation(
    core_running: bool,
    app_tun_enabled: bool,
    mihomo_tun_enabled: bool,
    mihomo_device: &str,
    kyclash_interface: &str,
    interface_exists: bool,
) -> Result<MihomoTunSnapshot, NetworkErrorCode> {
    if !valid_utun_interface(kyclash_interface) {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    if !core_running {
        return Ok(MihomoTunSnapshot::inactive());
    }

    // The managed app preference and the live Mihomo API must agree.  A
    // stale or partially restarted core is not a safe basis for route trust.
    if app_tun_enabled != mihomo_tun_enabled {
        return Err(NetworkErrorCode::RouteDiscoveryFailed);
    }
    if !mihomo_tun_enabled {
        return Ok(MihomoTunSnapshot::inactive());
    }
    if !interface_exists {
        return Err(NetworkErrorCode::RouteDiscoveryFailed);
    }

    MihomoTunSnapshot::active(mihomo_device, kyclash_interface)
}

/// Async source used by the production networking boundary.  Implementations
/// must return a complete snapshot; callers should freeze it for one route
/// lease and never re-interpret an interface name themselves.
#[async_trait::async_trait]
pub trait ActiveMihomoTunSource: Send + Sync {
    async fn snapshot(&self, kyclash_interface: &str) -> Result<MihomoTunSnapshot, NetworkErrorCode>;
}

/// Small deterministic source useful for controller/unit tests.  It also
/// makes the production boundary's dependency injection explicit without
/// granting tests access to a live route table.
#[derive(Debug, Clone)]
pub struct StaticActiveMihomoTunSource {
    result: Result<MihomoTunSnapshot, NetworkErrorCode>,
}

impl StaticActiveMihomoTunSource {
    pub const fn ready(snapshot: MihomoTunSnapshot) -> Self {
        Self { result: Ok(snapshot) }
    }

    pub const fn failed(error: NetworkErrorCode) -> Self {
        Self { result: Err(error) }
    }
}

#[async_trait::async_trait]
impl ActiveMihomoTunSource for StaticActiveMihomoTunSource {
    async fn snapshot(&self, kyclash_interface: &str) -> Result<MihomoTunSnapshot, NetworkErrorCode> {
        let snapshot = self.result.clone()?;
        snapshot.validate_for(kyclash_interface)?;
        Ok(snapshot)
    }
}

/// macOS adapter for the managed Mihomo instance.  It is only implemented in
/// production macOS builds because it needs the initialized Tauri/Mihomo
/// control plugin and the Darwin interface table.
#[cfg(all(target_os = "macos", feature = "networking-production"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacosActiveMihomoTunSource;

#[cfg(all(target_os = "macos", feature = "networking-production"))]
#[async_trait::async_trait]
impl ActiveMihomoTunSource for MacosActiveMihomoTunSource {
    async fn snapshot(&self, kyclash_interface: &str) -> Result<MihomoTunSnapshot, NetworkErrorCode> {
        use std::ffi::CString;

        use crate::{
            config::Config,
            core::{CoreManager, handle::Handle, manager::RunningMode},
        };

        let core_running = !matches!(*CoreManager::global().get_running_mode(), RunningMode::NotRunning);
        if !core_running {
            return snapshot_from_observation(false, false, false, "", kyclash_interface, false);
        }

        // Read the app preference before querying the live API, then drop the
        // config draft guard before any route-helper call can be made.
        let app_tun_enabled = Config::verge().await.latest_arc().enable_tun_mode.unwrap_or(false);
        let base_config = {
            let mihomo = Handle::mihomo().await;
            mihomo
                .get_base_config()
                .await
                .map_err(|_| NetworkErrorCode::RouteDiscoveryFailed)?
        };

        let interface_exists = if base_config.tun.enable {
            let device =
                CString::new(base_config.tun.device.as_str()).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            // SAFETY: `device` is NUL-terminated, contains no interior NUL,
            // and remains alive for the duration of the libc call.
            unsafe { libc::if_nametoindex(device.as_ptr()) != 0 }
        } else {
            false
        };

        snapshot_from_observation(
            true,
            app_tun_enabled,
            base_config.tun.enable,
            &base_config.tun.device,
            kyclash_interface,
            interface_exists,
        )
    }
}

fn all_unique_and_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_utun_interface(value: &str) -> bool {
    super::route_helper::valid_utun_interface(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KYCLASH_UTUN: &str = "utun42";

    #[test]
    fn stopped_or_disabled_core_has_empty_snapshot() -> anyhow::Result<()> {
        let stopped = snapshot_from_observation(false, true, true, "utun7", KYCLASH_UTUN, true)
            .map_err(|error| anyhow::anyhow!("stopped core: {error:?}"))?;
        assert!(stopped.interfaces().is_empty());

        let disabled = snapshot_from_observation(true, false, false, "", KYCLASH_UTUN, false)
            .map_err(|error| anyhow::anyhow!("disabled TUN: {error:?}"))?;
        assert!(disabled.interfaces().is_empty());
        Ok(())
    }

    #[test]
    fn valid_live_observation_is_typed_and_serializable() -> anyhow::Result<()> {
        let snapshot = snapshot_from_observation(true, true, true, "utun7", KYCLASH_UTUN, true)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(snapshot.interfaces(), &[String::from("utun7")]);
        let encoded = serde_json::to_string(&snapshot)?;
        let decoded: MihomoTunSnapshot = serde_json::from_str(&encoded)?;
        assert_eq!(snapshot, decoded);
        Ok(())
    }

    #[test]
    fn malformed_or_untrusted_device_fails_closed() {
        for device in ["", "utun", "utun-other", "Mihomo", "utun123456789012"] {
            assert_eq!(
                snapshot_from_observation(true, true, true, device, KYCLASH_UTUN, true),
                Err(NetworkErrorCode::InvalidConfiguration),
                "device {device:?} must not be trusted"
            );
        }
        assert_eq!(
            snapshot_from_observation(true, true, true, "utun7", KYCLASH_UTUN, false),
            Err(NetworkErrorCode::RouteDiscoveryFailed)
        );
        assert_eq!(
            snapshot_from_observation(true, true, true, KYCLASH_UTUN, KYCLASH_UTUN, true),
            Err(NetworkErrorCode::RouteConflict)
        );
    }

    #[test]
    fn live_and_app_tun_state_must_agree() {
        assert_eq!(
            snapshot_from_observation(true, true, false, "", KYCLASH_UTUN, false),
            Err(NetworkErrorCode::RouteDiscoveryFailed)
        );
        assert_eq!(
            snapshot_from_observation(true, false, true, "utun7", KYCLASH_UTUN, true),
            Err(NetworkErrorCode::RouteDiscoveryFailed)
        );
    }

    #[test]
    fn snapshot_rejects_bad_wire_shape_and_owner_collision() -> anyhow::Result<()> {
        let mut value = serde_json::to_value(MihomoTunSnapshot::inactive())?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("snapshot must encode as object"))?;
        object.insert("unexpected".into(), true.into());
        assert!(serde_json::from_value::<MihomoTunSnapshot>(value).is_err());

        let snapshot = MihomoTunSnapshot {
            active_mihomo_tun_interfaces: vec!["utun7".into(), "utun8".into()],
        };
        assert_eq!(
            snapshot.validate_for(KYCLASH_UTUN),
            Err(NetworkErrorCode::InvalidConfiguration)
        );

        let snapshot = MihomoTunSnapshot {
            active_mihomo_tun_interfaces: vec![KYCLASH_UTUN.into()],
        };
        assert_eq!(
            snapshot.validate_for(KYCLASH_UTUN),
            Err(NetworkErrorCode::RouteConflict)
        );
        Ok(())
    }

    #[tokio::test]
    async fn static_source_is_injectable_and_revalidates_owner() -> anyhow::Result<()> {
        let source = StaticActiveMihomoTunSource::ready(MihomoTunSnapshot {
            active_mihomo_tun_interfaces: vec!["utun7".into()],
        });
        let snapshot = source
            .snapshot(KYCLASH_UTUN)
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(snapshot.interfaces(), &[String::from("utun7")]);

        let collision = source.snapshot("utun7").await;
        assert_eq!(collision, Err(NetworkErrorCode::RouteConflict));
        assert_eq!(
            StaticActiveMihomoTunSource::failed(NetworkErrorCode::RouteDiscoveryFailed)
                .snapshot(KYCLASH_UTUN)
                .await,
            Err(NetworkErrorCode::RouteDiscoveryFailed)
        );
        Ok(())
    }
}
