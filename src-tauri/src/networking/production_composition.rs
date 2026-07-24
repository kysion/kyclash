//! Explicit production-networking composition.
//!
//! The production feature is intentionally default-off and its resources are
//! deliberately lazy.  This module separates three boundaries that must not
//! be conflated:
//!
//! * initialization verifies an app-owned signed policy and the public
//!   sidecar trust metadata, but does not touch Keychain, XPC, a sidecar, a
//!   tunnel, or routes;
//! * materialization happens only after an explicit connect request and creates
//!   the Keychain-backed one-shot launch material, broker session, deferred v3
//!   route boundary, and controller;
//! * the service itself still owns the locked health/utun/route ordering.
//!
//! No endpoint, public key, executable path, or credential is guessed here.
//! The bundle provider uses fixed resource names and fails closed when the
//! explicitly provisioned resources are absent or malformed. On macOS the
//! privileged broker independently selects and verifies its own fixed sidecar
//! immediately before launch; the App never supplies a broker executable path.

use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
#[cfg(any(target_os = "macos", test))]
use ring::rand::{SecureRandom as _, SystemRandom};

use super::{
    ActiveMihomoTunSource, FilePolicyIdentityStore, MihomoTunSnapshot, NetworkErrorCode, NetworkProfile, NetworkState,
    PolicyIdentityCandidate, PolicyTrustStore, PreparedProductionPolicyVariant, ProductionNetworkStatus,
    ProductionNetworkingService, ProductionPolicyCatalogProvider, ProductionSiteSummary, SidecarLifecycleState,
    SidecarTrustManifest, StaticActiveMihomoTunSource, VerifiedProductionPolicyVariant, verify_policy_catalog,
};

#[cfg(target_os = "macos")]
use super::{
    AsyncStdioSidecarRuntime, CredentialReference, DeferredV3ProductionRouteBoundary, MacOsKeychainCredentialStore,
    MacosActiveMihomoTunSource, ProductionRouteBoundary, SidecarLaunchMaterial, StdioSidecarRuntime,
    TunnelBrokerSidecarLauncher, resolve_or_generate_wireguard_material, spawn_broker_bound_production_controller,
};

/// Fixed, app-owned resource names.  They are intentionally not configurable
/// through a frontend command or an environment variable.
pub const POLICY_RESOURCE_NAME: &str = "kyclash-networking-policy-v2.json";
pub const POLICY_TRUST_RESOURCE_NAME: &str = "kyclash-networking-policy-keys.json";
const POLICY_RESOURCE_MAX_BYTES: usize = 64 * 1024;
const POLICY_TRUST_RESOURCE_MAX_BYTES: usize = 64 * 1024;
const SIDECAR_TRUST_RESOURCE_MAX_BYTES: usize = 16 * 1024;

/// Exact compile-time marker for the explicit disposable production-networking
/// candidate.  It is deliberately in a dedicated Mach-O section so package
/// verification can distinguish a feature-enabled executable from a resource
/// directory that merely claims to be one.  The marker contains no endpoint,
/// identity, or credential material.
#[cfg(all(target_os = "macos", feature = "networking-production"))]
#[used]
#[unsafe(link_section = "__TEXT,__kyclash_prod")]
pub static KYCLASH_PRODUCTION_COMPILE_MARKER: [u8; 16] = *b"KYCLASH-PROD-V1\0";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const SIDECAR_TRUST_RESOURCE_NAME: &str = "kyclash-network-sidecar-aarch64-apple-darwin.trust.json";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const SIDECAR_TRUST_RESOURCE_NAME: &str = "kyclash-network-sidecar-x86_64-apple-darwin.trust.json";
#[cfg(not(all(target_os = "macos", any(target_arch = "aarch64", target_arch = "x86_64"))))]
const SIDECAR_TRUST_RESOURCE_NAME: &str = "kyclash-network-sidecar-unsupported.trust.json";

const SIDECAR_RESOURCE_NAME: &str = "kyclash-network-sidecar";

/// The immutable, already-authenticated inputs needed to construct one
/// service. Creating this value is side-effect free; in particular it does
/// not verify executable bytes or read a Keychain item. The broker-bound
/// macOS path retains this app-bundle metadata for composition/package
/// verification, while the privileged broker independently verifies its own
/// fixed nested sidecar immediately before launch.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedProductionConfiguration {
    pub profile: NetworkProfile,
    pub profile_revision: u64,
    pub sidecar_executable: PathBuf,
    pub sidecar_trust: SidecarTrustManifest,
}

impl std::fmt::Debug for VerifiedProductionConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedProductionConfiguration")
            .field("profile", &self.profile)
            .field("profile_revision", &self.profile_revision)
            .field("sidecar_executable", &self.sidecar_executable)
            .field("sidecar_trust", &self.sidecar_trust)
            .finish()
    }
}

impl VerifiedProductionConfiguration {
    pub fn new(
        profile: NetworkProfile,
        profile_revision: u64,
        sidecar_executable: PathBuf,
        sidecar_trust: SidecarTrustManifest,
    ) -> Result<Self, NetworkErrorCode> {
        profile.validate()?;
        super::CredentialReference::parse(&profile.identity_ref)?;
        if profile_revision == 0 || !sidecar_executable.is_absolute() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        validate_trust_metadata(&sidecar_trust)?;
        Ok(Self {
            profile,
            profile_revision,
            sidecar_executable,
            sidecar_trust,
        })
    }
}

fn validate_trust_metadata(manifest: &SidecarTrustManifest) -> Result<(), NetworkErrorCode> {
    if manifest.schema_version != 1
        || manifest.sha256.len() != 64
        || !manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || manifest.architecture.is_empty()
        || manifest.architecture.len() > 16
        || !manifest
            .architecture
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || manifest.team_id.is_empty()
        || manifest.team_id.len() > 64
        || !manifest.team_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || manifest.designated_requirement.is_empty()
        || manifest.designated_requirement.len() > 1024
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    Ok(())
}

/// A factory is registered during explicit initialization and materialized
/// only by `connect_networking`.  The status snapshot is pure and therefore
/// safe to expose before any privileged/resource operation occurs.
#[async_trait]
pub trait ProductionServiceFactory: Send + Sync {
    fn initial_status(&self) -> ProductionNetworkStatus;
    async fn build(&self) -> Result<ProductionNetworkingService, NetworkErrorCode>;
}

/// Provider used by the Tauri initialization command.  It owns only fixed
/// paths into the signed application resource directory and a revision store;
/// it does not hold secrets and has no sidecar/XPC handles.
#[async_trait]
pub trait ProductionInitializationProvider: Send + Sync {
    async fn initialize(&self) -> Result<Arc<dyn ProductionServiceFactory>, NetworkErrorCode>;
}

/// Deferred factory for the real macOS service.  Tests may inject a typed
/// Mihomo source; production uses the live source only when the service is
/// materialized after an explicit connect.
pub struct DeferredProductionServiceFactory {
    configuration: Arc<VerifiedProductionConfiguration>,
    mihomo_source: Arc<dyn ActiveMihomoTunSource>,
}

impl std::fmt::Debug for DeferredProductionServiceFactory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeferredProductionServiceFactory")
            .field("configuration", &self.configuration)
            .finish_non_exhaustive()
    }
}

impl DeferredProductionServiceFactory {
    #[must_use]
    pub fn new(configuration: VerifiedProductionConfiguration) -> Self {
        Self {
            configuration: Arc::new(configuration),
            mihomo_source: Arc::new(StaticActiveMihomoTunSource::ready(MihomoTunSnapshot::inactive())),
        }
    }

    #[must_use]
    pub fn with_mihomo_source(mut self, source: Arc<dyn ActiveMihomoTunSource>) -> Self {
        self.mihomo_source = source;
        self
    }

    #[must_use]
    pub fn configuration(&self) -> &VerifiedProductionConfiguration {
        &self.configuration
    }

    fn initial_status_for(configuration: &VerifiedProductionConfiguration) -> ProductionNetworkStatus {
        ProductionNetworkStatus {
            state: NetworkState::Disconnected,
            sidecar_state: SidecarLifecycleState::Stopped,
            site: ProductionSiteSummary {
                id: configuration.profile.site.id.clone(),
                display_name: configuration.profile.site.display_name.clone(),
                private_route_count: configuration.profile.site.private_cidrs.len(),
            },
            active_transport: None,
            health: None,
            operation_id: None,
            last_error: None,
        }
    }

    #[cfg(target_os = "macos")]
    fn build_macos(&self) -> Result<ProductionNetworkingService, NetworkErrorCode> {
        // The only place that resolves the fixed production Keychain service.
        // This function is reached after an explicit connect request, never
        // from app setup or status/list commands.
        let mut auth_token = vec![0_u8; 32];
        SystemRandom::new()
            .fill(&mut auth_token)
            .map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
        let reference = CredentialReference::parse(&self.configuration.profile.identity_ref)?;
        let mut credentials = MacOsKeychainCredentialStore::new_for_runtime();
        let private_key = resolve_or_generate_wireguard_material(&mut credentials, &reference)?;
        let launch_material = SidecarLaunchMaterial::new(auth_token, private_key.expose().to_vec())?;

        // Construct the deferred route boundary before starting the broker.
        // This allocates only local retirement identity and opens no XPC
        // connection, so a local construction failure cannot leave a broker
        // child awaiting connection invalidation cleanup.
        let routes: Box<dyn ProductionRouteBoundary> = Box::new(DeferredV3ProductionRouteBoundary::new()?);

        // The privileged broker, not the ordinary App process, selects and
        // verifies the fixed sidecar executable.  Its typed start reply owns
        // the only valid instance ID for this one-shot controller generation.
        let mut broker = TunnelBrokerSidecarLauncher::new();
        let prepared = broker.prepare()?;
        let broker_reference = prepared.session_reference().clone();
        let instance_id = broker_reference.sidecar_instance_id.clone();
        let bound_launch = launch_material.bind(broker_reference)?;
        let runtime = AsyncStdioSidecarRuntime::new(StdioSidecarRuntime::with_launcher(
            self.configuration.sidecar_executable.clone(),
            prepared,
        ));
        let controller = spawn_broker_bound_production_controller(runtime, bound_launch);
        ProductionNetworkingService::new_broker_bound_with_mihomo_source(
            controller,
            self.configuration.profile.clone(),
            routes,
            instance_id,
            self.configuration.profile_revision,
            Arc::clone(&self.mihomo_source),
        )
    }
}

#[async_trait]
impl ProductionServiceFactory for DeferredProductionServiceFactory {
    fn initial_status(&self) -> ProductionNetworkStatus {
        Self::initial_status_for(&self.configuration)
    }

    async fn build(&self) -> Result<ProductionNetworkingService, NetworkErrorCode> {
        #[cfg(target_os = "macos")]
        {
            self.build_macos()
        }
        #[cfg(not(target_os = "macos"))]
        {
            // The locked production route boundary is macOS XPC.  Linux can
            // still compile and test the factory/state contract, but a live
            // production connection must fail closed until a reviewed native
            // route boundary is added for that platform.
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }
}

#[cfg(test)]
fn random_instance_id(seed: &[u8]) -> Result<String, NetworkErrorCode> {
    if seed.len() != 32 {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    let mut entropy = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut entropy)
        .map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    let mut value = String::from("kyclash.");
    for byte in entropy {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    }
    Ok(value)
}

/// Fixed-path provider for a signed app bundle.  The resource files are read
/// only when the explicit initialization command is invoked.
#[derive(Debug, Clone)]
pub struct BundleProductionInitializationProvider {
    resource_dir: PathBuf,
    app_data_dir: PathBuf,
    now: Option<u64>,
    #[cfg(test)]
    fail_after_configuration: bool,
}

impl BundleProductionInitializationProvider {
    pub fn new(resource_dir: PathBuf, app_data_dir: PathBuf) -> Result<Self, NetworkErrorCode> {
        if !resource_dir.is_absolute() || !app_data_dir.is_absolute() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self {
            resource_dir,
            app_data_dir,
            now: None,
            #[cfg(test)]
            fail_after_configuration: false,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub const fn with_now(mut self, now: u64) -> Self {
        self.now = Some(now);
        self
    }

    #[cfg(test)]
    #[must_use]
    pub const fn with_composition_failure(mut self) -> Self {
        self.fail_after_configuration = true;
        self
    }

    fn initialize_sync(&self) -> Result<Arc<dyn ProductionServiceFactory>, NetworkErrorCode> {
        let resources = self.resource_dir.join("resources");
        let store = FilePolicyIdentityStore::new(self.app_data_dir.clone())?;
        // The cross-process lock and durable snapshot precede authentication.
        // It remains held across every immutable composition check and the
        // commit-time freshness/snapshot recheck.
        let mut transaction = store.begin()?;
        let now = self.now.unwrap_or_else(unix_now);
        let trust_bytes = read_owned_resource(
            &resources.join(POLICY_TRUST_RESOURCE_NAME),
            POLICY_TRUST_RESOURCE_MAX_BYTES,
        )?;
        let policy_bytes = read_owned_resource(&resources.join(POLICY_RESOURCE_NAME), POLICY_RESOURCE_MAX_BYTES)?;
        let trust = PolicyTrustStore::from_json(&trust_bytes)?;
        let verified = trust.verify(&policy_bytes, now)?;
        let candidate = PolicyIdentityCandidate::new(
            verified.revision,
            verified.envelope_sha256.clone(),
            verified.key_id.clone(),
            verified.issued_at,
            verified.expires_at,
        )?;
        if transaction.classify(candidate, now)? == super::PolicyIdentityDecision::Reject {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }

        // Parse every remaining immutable composition input before allowing
        // the classified identity to commit. A malformed manifest or final
        // configuration leaves both legacy and v2 snapshots untouched.
        let manifest_bytes = read_owned_resource(
            &resources.join(SIDECAR_TRUST_RESOURCE_NAME),
            SIDECAR_TRUST_RESOURCE_MAX_BYTES,
        )?;
        let manifest: SidecarTrustManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
        validate_trust_metadata(&manifest)?;
        let configuration = VerifiedProductionConfiguration::new(
            verified.profile.clone(),
            verified.revision,
            self.resource_dir.join(SIDECAR_RESOURCE_NAME),
            manifest,
        )?;
        #[cfg(test)]
        if self.fail_after_configuration {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let commit_now = self.now.unwrap_or_else(unix_now);
        verified.validate_at(commit_now)?;
        transaction.commit(commit_now)?;
        let factory = DeferredProductionServiceFactory::new(configuration);
        #[cfg(all(target_os = "macos", feature = "networking-production"))]
        let factory = factory.with_mihomo_source(Arc::new(MacosActiveMihomoTunSource));
        Ok(Arc::new(factory))
    }

    fn verify_policy_variants_sync(&self) -> Result<Vec<VerifiedProductionPolicyVariant>, NetworkErrorCode> {
        let resources = self.resource_dir.join("resources");
        let now = self.now.unwrap_or_else(unix_now);
        verify_policy_catalog(&resources, now).map(|catalog| catalog.bindings())
    }

    fn prepare_policy_variant_sync(
        &self,
        catalog_id: &str,
        expected: Option<&VerifiedProductionPolicyVariant>,
    ) -> Result<PreparedProductionPolicyVariant, NetworkErrorCode> {
        let resources = self.resource_dir.join("resources");
        let store = FilePolicyIdentityStore::new(self.app_data_dir.clone())?;
        // The durable anti-replay identity belongs to the entire catalog, not
        // whichever route variant is currently selected. This permits an
        // operator to switch between the four concurrently signed variants
        // while still requiring a revision advance for any catalog change.
        let mut transaction = store.begin()?;
        let now = self.now.unwrap_or_else(unix_now);
        let first_catalog = verify_policy_catalog(&resources, now)?;
        let (first_binding, _) = first_catalog.selected(catalog_id)?;
        if expected.is_some_and(|expected| expected != first_binding) {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let candidate = PolicyIdentityCandidate::new(
            first_catalog.revision,
            first_catalog.identity_sha256.clone(),
            "catalog.v1".into(),
            first_catalog.issued_at,
            first_catalog.expires_at,
        )?;
        if transaction.classify(candidate, now)? == super::PolicyIdentityDecision::Reject {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }

        let manifest_bytes = read_owned_resource(
            &resources.join(SIDECAR_TRUST_RESOURCE_NAME),
            SIDECAR_TRUST_RESOURCE_MAX_BYTES,
        )?;
        let manifest: SidecarTrustManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
        validate_trust_metadata(&manifest)?;

        // Reopen and verify every catalog envelope immediately before commit.
        // This closes both expiry drift and cross-file replacement windows.
        let commit_now = self.now.unwrap_or_else(unix_now);
        let final_catalog = verify_policy_catalog(&resources, commit_now)?;
        if final_catalog.revision != first_catalog.revision
            || final_catalog.identity_sha256 != first_catalog.identity_sha256
            || final_catalog.bindings() != first_catalog.bindings()
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let (selected, policy) = final_catalog.selected(catalog_id)?;
        if expected.is_some_and(|expected| expected != selected) {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let configuration = VerifiedProductionConfiguration::new(
            policy.profile.clone(),
            policy.revision,
            self.resource_dir.join(SIDECAR_RESOURCE_NAME),
            manifest,
        )?;
        transaction.commit(commit_now)?;
        let factory = DeferredProductionServiceFactory::new(configuration);
        #[cfg(all(target_os = "macos", feature = "networking-production"))]
        let factory = factory.with_mihomo_source(Arc::new(MacosActiveMihomoTunSource));
        Ok(PreparedProductionPolicyVariant {
            variants: final_catalog.bindings(),
            selected: selected.clone(),
            factory: Arc::new(factory),
        })
    }
}

#[async_trait]
impl ProductionInitializationProvider for BundleProductionInitializationProvider {
    async fn initialize(&self) -> Result<Arc<dyn ProductionServiceFactory>, NetworkErrorCode> {
        let provider = self.clone();
        tokio::task::spawn_blocking(move || provider.initialize_sync())
            .await
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?
    }
}

#[async_trait]
impl ProductionPolicyCatalogProvider for BundleProductionInitializationProvider {
    async fn verify_policy_variants(&self) -> Result<Vec<VerifiedProductionPolicyVariant>, NetworkErrorCode> {
        let provider = self.clone();
        tokio::task::spawn_blocking(move || provider.verify_policy_variants_sync())
            .await
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?
    }

    async fn prepare_policy_variant(
        &self,
        catalog_id: &str,
        expected: Option<&VerifiedProductionPolicyVariant>,
    ) -> Result<PreparedProductionPolicyVariant, NetworkErrorCode> {
        let provider = self.clone();
        let catalog_id = catalog_id.to_owned();
        let expected = expected.cloned();
        tokio::task::spawn_blocking(move || provider.prepare_policy_variant_sync(&catalog_id, expected.as_ref()))
            .await
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?
    }
}

pub(crate) fn read_owned_resource(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, NetworkErrorCode> {
    read_owned_resource_with_hook(path, maximum_bytes, || Ok(()))
}

fn read_owned_resource_with_hook<F>(
    path: &Path,
    maximum_bytes: usize,
    after_initial_stat: F,
) -> Result<Vec<u8>, NetworkErrorCode>
where
    F: FnOnce() -> Result<(), NetworkErrorCode>,
{
    // Open the final path without following a symlink.  The bundle is an
    // app-owned trust boundary: a metadata check followed by `fs::read` has
    // a replace-between-check-and-use window in which a writable resource
    // directory could redirect policy or trust bytes to an attacker-selected
    // file.  Checking the descriptor after opening also avoids trusting a
    // path's pre-open metadata.
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_NONBLOCK prevents an attacker-controlled FIFO/device replacement
        // from hanging initialization before descriptor-type validation.
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    let before = file.metadata().map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    let expected_len = usize::try_from(before.len()).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    if !before.is_file() || expected_len == 0 || expected_len > maximum_bytes {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    after_initial_stat()?;
    let mut bytes = Vec::with_capacity(expected_len);
    (&mut file)
        .take((maximum_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    let after = file.metadata().map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    if bytes.len() != expected_len || bytes.len() > maximum_bytes || !same_resource_snapshot(&before, &after) {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_resource_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn same_resource_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() == after.len()
        && matches!(
            (before.modified(), after.modified()),
            (Ok(before_modified), Ok(after_modified)) if before_modified == after_modified
        )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(all(test, unix))]
pub(crate) use tests::{
    signed_policy as signed_test_policy, signed_policy_with_profile as signed_test_policy_with_profile,
    write_bundle_resources as write_test_bundle_resources,
};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(unix)]
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    #[cfg(unix)]
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;

    #[cfg(unix)]
    const TEST_POLICY_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49,
        0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];

    #[cfg(unix)]
    fn policy_signing_message(key_id: &str, algorithm: &str, payload: &[u8]) -> Vec<u8> {
        let mut message = b"kyclash-policy-envelope-v2\0".to_vec();
        message.extend_from_slice(key_id.as_bytes());
        message.push(0);
        message.extend_from_slice(algorithm.as_bytes());
        message.push(0);
        message.extend_from_slice(payload);
        message
    }

    #[cfg(unix)]
    pub(crate) fn signed_policy(
        revision: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> anyhow::Result<(crate::networking::SignedNetworkPolicyEnvelope, Vec<u8>)> {
        signed_policy_with_profile(
            revision,
            issued_at,
            expires_at,
            "policy.test",
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))?,
        )
    }

    #[cfg(unix)]
    pub(crate) fn signed_policy_with_profile(
        revision: u64,
        issued_at: u64,
        expires_at: u64,
        key_id: &str,
        profile: NetworkProfile,
    ) -> anyhow::Result<(crate::networking::SignedNetworkPolicyEnvelope, Vec<u8>)> {
        let pair = Ed25519KeyPair::from_seed_unchecked(&TEST_POLICY_SEED)
            .map_err(|_| anyhow::anyhow!("decode test policy key"))?;
        let payload = crate::networking::SignedNetworkPolicyPayload {
            issued_at,
            expires_at,
            revision,
            profile,
        };
        let payload_bytes = serde_json::to_vec(&payload)?;
        let envelope = crate::networking::SignedNetworkPolicyEnvelope {
            envelope_version: 2,
            key_id: key_id.into(),
            algorithm: "ed25519".into(),
            payload_base64: STANDARD.encode(&payload_bytes),
            signature_base64: STANDARD.encode(
                pair.sign(&policy_signing_message(key_id, "ed25519", &payload_bytes))
                    .as_ref(),
            ),
        };
        Ok((envelope, pair.public_key().as_ref().to_vec()))
    }

    #[cfg(unix)]
    pub(crate) fn write_bundle_resources(
        resource_dir: &Path,
        envelope: &crate::networking::SignedNetworkPolicyEnvelope,
        public_key: &[u8],
        pretty_policy: bool,
    ) -> anyhow::Result<()> {
        let resources = resource_dir.join("resources");
        fs::create_dir_all(&resources)?;
        let trust = serde_json::json!({
            "schema_version": 1,
            "keys": [{
                "key_id": envelope.key_id.clone(),
                "public_key_base64": STANDARD.encode(public_key),
            }],
        });
        fs::write(resources.join(POLICY_TRUST_RESOURCE_NAME), serde_json::to_vec(&trust)?)?;
        fs::write(
            resources.join(POLICY_RESOURCE_NAME),
            if pretty_policy {
                serde_json::to_vec_pretty(envelope)?
            } else {
                serde_json::to_vec(envelope)?
            },
        )?;
        let manifest = SidecarTrustManifest {
            schema_version: 1,
            sha256: "a".repeat(64),
            architecture: "arm64".into(),
            team_id: "RQUQ8Y3S9H".into(),
            designated_requirement: "identifier \"net.kysion.kyclash.network-sidecar\"".into(),
        };
        fs::write(
            resources.join(SIDECAR_TRUST_RESOURCE_NAME),
            serde_json::to_vec(&manifest)?,
        )?;
        Ok(())
    }

    #[cfg(unix)]
    fn provider(
        resource_dir: PathBuf,
        app_data_dir: PathBuf,
        now: u64,
    ) -> anyhow::Result<BundleProductionInitializationProvider> {
        BundleProductionInitializationProvider::new(resource_dir, app_data_dir)
            .map(|provider| provider.with_now(now))
            .map_err(|error| anyhow::anyhow!("{error:?}"))
    }

    #[test]
    fn configuration_rejects_relative_sidecar_and_invalid_identity() -> anyhow::Result<()> {
        let profile: NetworkProfile =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))?;
        let manifest = SidecarTrustManifest {
            schema_version: 1,
            sha256: "a".repeat(64),
            architecture: "arm64".into(),
            team_id: "RQUQ8Y3S9H".into(),
            designated_requirement: "identifier \"net.kysion.kyclash.network-sidecar\"".into(),
        };
        assert_eq!(
            VerifiedProductionConfiguration::new(profile.clone(), 1, PathBuf::from("relative"), manifest.clone()),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
        let mut invalid = profile;
        invalid.identity_ref = "file:private".into();
        assert_eq!(
            VerifiedProductionConfiguration::new(invalid, 1, PathBuf::from("/sidecar"), manifest),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn instance_ids_are_opaque_and_safe_for_ipc() -> anyhow::Result<()> {
        let id = random_instance_id(&[0x41; 32]).map_err(|error| anyhow::anyhow!("instance id: {error:?}"))?;
        assert!(id.starts_with("kyclash."));
        assert!(super::super::valid_ipc_id(&id));
        assert!(!id.contains('/'));
        Ok(())
    }

    struct CountingFactory {
        builds: Arc<AtomicUsize>,
        status: ProductionNetworkStatus,
    }

    #[async_trait]
    impl ProductionServiceFactory for CountingFactory {
        fn initial_status(&self) -> ProductionNetworkStatus {
            self.status.clone()
        }

        async fn build(&self) -> Result<ProductionNetworkingService, NetworkErrorCode> {
            self.builds.fetch_add(1, Ordering::SeqCst);
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }

    #[test]
    fn trust_metadata_is_validated_before_any_runtime_materialization() {
        let manifest = SidecarTrustManifest {
            schema_version: 1,
            sha256: "g".repeat(64),
            architecture: "arm64".into(),
            team_id: "RQUQ8Y3S9H".into(),
            designated_requirement: "identifier \"x\"".into(),
        };
        assert_eq!(
            validate_trust_metadata(&manifest),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
    }

    #[test]
    fn counting_factory_contract_has_no_implicit_build() {
        let builds = Arc::new(AtomicUsize::new(0));
        let factory = CountingFactory {
            builds: Arc::clone(&builds),
            status: ProductionNetworkStatus {
                state: NetworkState::Disconnected,
                sidecar_state: SidecarLifecycleState::Stopped,
                site: ProductionSiteSummary {
                    id: "site.test".into(),
                    display_name: "Test".into(),
                    private_route_count: 1,
                },
                active_transport: None,
                health: None,
                operation_id: None,
                last_error: None,
            },
        };
        assert_eq!(factory.initial_status().state, NetworkState::Disconnected);
        assert_eq!(builds.load(Ordering::SeqCst), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_bundle_resources_fail_closed_without_materialization_or_revision_write() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let resource_dir = directory.path().join("KyClash.app/Contents/Resources");
        fs::create_dir_all(&resource_dir)?;
        let app_data_dir = directory.path().join("app-data");
        fs::create_dir(&app_data_dir)?;
        let revision_path = app_data_dir.join("networking/policy-revision.json");
        let provider = provider(resource_dir, app_data_dir, 150)?;
        assert_eq!(
            provider.initialize().await.err(),
            Some(NetworkErrorCode::InvalidConfiguration)
        );
        assert!(!revision_path.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn malformed_sidecar_manifest_is_reported_before_policy_revision_commit() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let resource_dir = directory.path().join("KyClash.app/Contents/Resources");
        let resources = resource_dir.join("resources");
        let (envelope, public_key) = signed_policy(42, 100, 200)?;
        write_bundle_resources(&resource_dir, &envelope, &public_key, false)?;
        fs::write(resources.join(SIDECAR_TRUST_RESOURCE_NAME), br"{")?;
        let app_data_dir = directory.path().join("app-data");
        fs::create_dir(&app_data_dir)?;
        let revision_path = app_data_dir.join("networking/policy-revision.json");
        let provider = provider(resource_dir, app_data_dir, 150)?;
        assert_eq!(
            provider.initialize().await.err(),
            Some(NetworkErrorCode::AuthenticationFailed)
        );
        assert!(!revision_path.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn app_restart_accepts_exact_policy_identity_without_rewrite_or_runtime_materialization() -> anyhow::Result<()>
    {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir()?;
        let resource_dir = directory.path().join("KyClash.app/Contents/Resources");
        let app_data_dir = directory.path().join("app-data");
        fs::create_dir(&app_data_dir)?;
        let (envelope, public_key) = signed_policy(42, 100, 200)?;
        write_bundle_resources(&resource_dir, &envelope, &public_key, false)?;

        let first = provider(resource_dir.clone(), app_data_dir.clone(), 150)?
            .initialize()
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(first.initial_status().state, NetworkState::Disconnected);
        let record_path = app_data_dir.join("networking/policy-revision.json");
        let before_bytes = fs::read(&record_path)?;
        let before = fs::metadata(&record_path)?;

        let restarted = provider(resource_dir, app_data_dir, 151)?
            .initialize()
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(restarted.initial_status().state, NetworkState::Disconnected);
        let after = fs::metadata(&record_path)?;
        assert_eq!(fs::read(&record_path)?, before_bytes);
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.mtime(), before.mtime());
        assert_eq!(after.mtime_nsec(), before.mtime_nsec());

        let record: serde_json::Value = serde_json::from_slice(&before_bytes)?;
        let keys = record
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("identity record object"))?
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            ["envelope_sha256", "key_id", "revision", "schema_version"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        let encoded = String::from_utf8(before_bytes)?;
        for forbidden in [
            "profile",
            "endpoint",
            "identity_ref",
            "signature",
            "private",
            "keychain:",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn same_revision_whitespace_change_and_expired_exact_restart_fail_without_mutation() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let resource_dir = directory.path().join("KyClash.app/Contents/Resources");
        let app_data_dir = directory.path().join("app-data");
        fs::create_dir(&app_data_dir)?;
        let (envelope, public_key) = signed_policy(42, 100, 200)?;
        write_bundle_resources(&resource_dir, &envelope, &public_key, false)?;
        provider(resource_dir.clone(), app_data_dir.clone(), 150)?
            .initialize()
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let record_path = app_data_dir.join("networking/policy-revision.json");
        let accepted = fs::read(&record_path)?;

        write_bundle_resources(&resource_dir, &envelope, &public_key, true)?;
        assert_eq!(
            provider(resource_dir.clone(), app_data_dir.clone(), 151)?
                .initialize()
                .await
                .err(),
            Some(NetworkErrorCode::PolicySignatureInvalid)
        );
        assert_eq!(fs::read(&record_path)?, accepted);

        write_bundle_resources(&resource_dir, &envelope, &public_key, false)?;
        assert_eq!(
            provider(resource_dir, app_data_dir, 200)?.initialize().await.err(),
            Some(NetworkErrorCode::PolicySignatureInvalid)
        );
        assert_eq!(fs::read(&record_path)?, accepted);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provider_rejects_all_same_revision_identity_changes_and_lower_then_accepts_higher() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let resource_dir = directory.path().join("KyClash.app/Contents/Resources");
        let resources = resource_dir.join("resources");
        let policy_path = resources.join(POLICY_RESOURCE_NAME);
        let app_data_dir = directory.path().join("app-data");
        fs::create_dir(&app_data_dir)?;
        let (original, public_key) = signed_policy(42, 100, 200)?;
        write_bundle_resources(&resource_dir, &original, &public_key, false)?;
        provider(resource_dir.clone(), app_data_dir.clone(), 150)?
            .initialize()
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let record_path = app_data_dir.join("networking/policy-revision.json");
        let accepted = fs::read(&record_path)?;

        let reordered = format!(
            "{{\"signature_base64\":{},\"payload_base64\":{},\"algorithm\":{},\"key_id\":{},\"envelope_version\":{}}}",
            serde_json::to_string(&original.signature_base64)?,
            serde_json::to_string(&original.payload_base64)?,
            serde_json::to_string(&original.algorithm)?,
            serde_json::to_string(&original.key_id)?,
            original.envelope_version,
        );
        fs::write(&policy_path, reordered)?;
        assert_eq!(
            provider(resource_dir.clone(), app_data_dir.clone(), 151)?
                .initialize()
                .await
                .err(),
            Some(NetworkErrorCode::PolicySignatureInvalid)
        );
        assert_eq!(fs::read(&record_path)?, accepted);

        let profile: NetworkProfile =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))?;
        let (rotated_key, rotated_public) =
            signed_policy_with_profile(42, 100, 200, "policy.rotated", profile.clone())?;
        write_bundle_resources(&resource_dir, &rotated_key, &rotated_public, false)?;
        assert_eq!(
            provider(resource_dir.clone(), app_data_dir.clone(), 151)?
                .initialize()
                .await
                .err(),
            Some(NetworkErrorCode::PolicySignatureInvalid)
        );
        assert_eq!(fs::read(&record_path)?, accepted);

        let mut changed_profile = profile;
        changed_profile.site.display_name = "Changed Site".into();
        let (changed_payload, changed_public) =
            signed_policy_with_profile(42, 100, 200, "policy.test", changed_profile)?;
        write_bundle_resources(&resource_dir, &changed_payload, &changed_public, false)?;
        assert_eq!(
            provider(resource_dir.clone(), app_data_dir.clone(), 151)?
                .initialize()
                .await
                .err(),
            Some(NetworkErrorCode::PolicySignatureInvalid)
        );
        assert_eq!(fs::read(&record_path)?, accepted);

        let mut changed_signature = original.clone();
        let replacement = if changed_signature.signature_base64.starts_with('A') {
            "B"
        } else {
            "A"
        };
        changed_signature.signature_base64.replace_range(..1, replacement);
        write_bundle_resources(&resource_dir, &changed_signature, &public_key, false)?;
        assert_eq!(
            provider(resource_dir.clone(), app_data_dir.clone(), 151)?
                .initialize()
                .await
                .err(),
            Some(NetworkErrorCode::PolicySignatureInvalid)
        );
        assert_eq!(fs::read(&record_path)?, accepted);

        let (lower, lower_public) = signed_policy(41, 100, 200)?;
        write_bundle_resources(&resource_dir, &lower, &lower_public, false)?;
        assert_eq!(
            provider(resource_dir.clone(), app_data_dir.clone(), 151)?
                .initialize()
                .await
                .err(),
            Some(NetworkErrorCode::PolicySignatureInvalid)
        );
        assert_eq!(fs::read(&record_path)?, accepted);

        let (higher, higher_public) = signed_policy(43, 100, 200)?;
        write_bundle_resources(&resource_dir, &higher, &higher_public, false)?;
        let factory = provider(resource_dir, app_data_dir, 151)?
            .initialize()
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(factory.initial_status().state, NetworkState::Disconnected);
        let advanced: serde_json::Value = serde_json::from_slice(&fs::read(&record_path)?)?;
        assert_eq!(advanced["revision"], 43);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn manifest_and_final_composition_failures_preserve_legacy_and_v2_records() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        for durable_version in [1_u8, 2] {
            for failure in ["manifest", "composition"] {
                let directory = tempfile::tempdir()?;
                let resource_dir = directory.path().join("KyClash.app/Contents/Resources");
                let app_data_dir = directory.path().join("app-data");
                fs::create_dir(&app_data_dir)?;
                let (accepted_policy, public_key) = signed_policy(42, 100, 200)?;
                write_bundle_resources(&resource_dir, &accepted_policy, &public_key, false)?;
                let record_path = app_data_dir.join("networking/policy-revision.json");
                if durable_version == 1 {
                    fs::create_dir(app_data_dir.join("networking"))?;
                    fs::set_permissions(app_data_dir.join("networking"), fs::Permissions::from_mode(0o700))?;
                    fs::write(&record_path, br#"{"schema_version":1,"revision":42}"#)?;
                    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600))?;
                } else {
                    provider(resource_dir.clone(), app_data_dir.clone(), 150)?
                        .initialize()
                        .await
                        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
                }
                let before = fs::read(&record_path)?;
                let (higher, higher_public) = signed_policy(43, 100, 200)?;
                write_bundle_resources(&resource_dir, &higher, &higher_public, false)?;
                let mut failing = provider(resource_dir.clone(), app_data_dir.clone(), 151)?;
                let expected = if failure == "manifest" {
                    fs::write(resource_dir.join("resources").join(SIDECAR_TRUST_RESOURCE_NAME), br"{")?;
                    NetworkErrorCode::AuthenticationFailed
                } else {
                    failing = failing.with_composition_failure();
                    NetworkErrorCode::InvalidConfiguration
                };
                assert_eq!(failing.initialize().await.err(), Some(expected));
                assert_eq!(fs::read(&record_path)?, before);
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn owned_resource_open_refuses_symlink_without_a_check_use_window() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let regular = directory.path().join("regular.json");
        let link = directory.path().join("link.json");
        fs::write(&regular, br"{}")?;
        symlink(&regular, &link)?;

        assert_eq!(
            read_owned_resource(&regular, 16).map_err(|error| anyhow::anyhow!("{error:?}"))?,
            b"{}".to_vec()
        );
        assert_eq!(
            read_owned_resource(&link, 16).err(),
            Some(NetworkErrorCode::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn owned_resource_read_rejects_empty_and_oversized_files() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resource.json");
        fs::write(&path, b"")?;
        assert_eq!(
            read_owned_resource(&path, 16).err(),
            Some(NetworkErrorCode::InvalidConfiguration)
        );
        fs::write(&path, [0x41; 17])?;
        assert_eq!(
            read_owned_resource(&path, 16).err(),
            Some(NetworkErrorCode::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn each_owned_resource_limit_rejects_empty_oversize_and_changed_during_read() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        for (name, maximum) in [
            (POLICY_RESOURCE_NAME, POLICY_RESOURCE_MAX_BYTES),
            (POLICY_TRUST_RESOURCE_NAME, POLICY_TRUST_RESOURCE_MAX_BYTES),
            (SIDECAR_TRUST_RESOURCE_NAME, SIDECAR_TRUST_RESOURCE_MAX_BYTES),
        ] {
            let path = directory.path().join(name);
            fs::write(&path, b"")?;
            assert_eq!(
                read_owned_resource(&path, maximum),
                Err(NetworkErrorCode::InvalidConfiguration)
            );
            fs::write(&path, vec![b'x'; maximum + 1])?;
            assert_eq!(
                read_owned_resource(&path, maximum),
                Err(NetworkErrorCode::InvalidConfiguration)
            );
            fs::write(&path, b"0123456789abcdef")?;
            let changed_path = path.clone();
            assert_eq!(
                read_owned_resource_with_hook(&path, maximum, move || {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    fs::write(changed_path, b"fedcba9876543210").map_err(|_| NetworkErrorCode::InvalidConfiguration)
                }),
                Err(NetworkErrorCode::InvalidConfiguration)
            );
        }
        Ok(())
    }
}
