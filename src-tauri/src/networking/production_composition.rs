//! Explicit production-networking composition.
//!
//! The production feature is intentionally default-off and its resources are
//! deliberately lazy.  This module separates three boundaries that must not
//! be conflated:
//!
//! * initialization verifies an app-owned signed policy and the public
//!   sidecar trust manifest, but does not touch Keychain, XPC, a sidecar, a
//!   tunnel, or routes;
//! * materialization happens only after an explicit connect request and creates
//!   the Keychain-backed bootstrap context, XPC route client, and controller;
//! * the service itself still owns the locked health/utun/route ordering.
//!
//! No endpoint, public key, executable path, or credential is guessed here.
//! The bundle provider uses fixed resource names and fails closed when the
//! explicitly provisioned resources are absent or malformed.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use ring::rand::{SecureRandom as _, SystemRandom};

use super::{
    ActiveMihomoTunSource, FilePolicyRevisionStore, MihomoTunSnapshot, NetworkErrorCode, NetworkProfile, NetworkState,
    PolicyRevisionStore, PolicyTrustStore, ProductionControllerHandle, ProductionNetworkStatus,
    ProductionNetworkingService, ProductionRouteBoundary, ProductionSiteSummary, SidecarLifecycleState,
    SidecarTrustManifest, StaticActiveMihomoTunSource, XpcProductionRouteBoundary, prepare_sidecar_launch_context,
    sidecar_auth_proof,
};

#[cfg(all(unix, feature = "networking-production"))]
use super::{AsyncStdioSidecarRuntime, StdioSidecarRuntime, spawn_production_controller};
#[cfg(target_os = "macos")]
use super::{MacOsKeychainCredentialStore, MacosActiveMihomoTunSource};

/// Fixed, app-owned resource names.  They are intentionally not configurable
/// through a frontend command or an environment variable.
pub const POLICY_RESOURCE_NAME: &str = "kyclash-networking-policy-v2.json";
pub const POLICY_TRUST_RESOURCE_NAME: &str = "kyclash-networking-policy-keys.json";

#[cfg(target_arch = "aarch64")]
const SIDECAR_TRUST_RESOURCE_NAME: &str = "kyclash-network-sidecar-aarch64-apple-darwin.trust.json";
#[cfg(target_arch = "x86_64")]
const SIDECAR_TRUST_RESOURCE_NAME: &str = "kyclash-network-sidecar-x86_64-apple-darwin.trust.json";
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const SIDECAR_TRUST_RESOURCE_NAME: &str = "kyclash-network-sidecar-unsupported.trust.json";

const SIDECAR_RESOURCE_NAME: &str = "kyclash-network-sidecar";

/// The immutable, already-authenticated inputs needed to construct one
/// service.  Creating this value is side-effect free; in particular it does
/// not verify the executable bytes or read a Keychain item.  Executable trust
/// is rechecked by `StdioSidecarRuntime` immediately before the child starts.
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
        let instance_id = random_instance_id(&auth_token)?;
        let materialized = (|| {
            let mut credentials = MacOsKeychainCredentialStore::new();
            let context = prepare_sidecar_launch_context(
                instance_id.clone(),
                auth_token.clone(),
                &self.configuration.profile.identity_ref,
                &mut credentials,
            )?;
            let proof = sidecar_auth_proof(&auth_token, &instance_id);
            Ok::<_, NetworkErrorCode>((context, proof))
        })();
        // Do not retain the temporary copy after the context/proof have been
        // constructed.  The context owns its zeroizing copy for the actor.
        auth_token.fill(0);
        let (context, expected_auth_proof) = materialized?;

        // XPC discovery is explicit-connect work.  It is deliberately after
        // policy initialization and before any route mutation; `connect()`
        // itself performs only typed helper discovery.
        let routes: Box<dyn ProductionRouteBoundary> = Box::new(XpcProductionRouteBoundary::connect()?);
        let runtime = AsyncStdioSidecarRuntime::new(StdioSidecarRuntime::new_trusted(
            self.configuration.sidecar_executable.clone(),
            self.configuration.sidecar_trust.clone(),
        ));
        let controller: ProductionControllerHandle = spawn_production_controller(runtime, context, expected_auth_proof);
        ProductionNetworkingService::new_with_mihomo_source(
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
    revision_path: PathBuf,
    now: Option<u64>,
}

impl BundleProductionInitializationProvider {
    pub fn new(resource_dir: PathBuf, revision_path: PathBuf) -> Result<Self, NetworkErrorCode> {
        if !resource_dir.is_absolute() || !revision_path.is_absolute() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self {
            resource_dir,
            revision_path,
            now: None,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub const fn with_now(mut self, now: u64) -> Self {
        self.now = Some(now);
        self
    }

    fn initialize_sync(&self) -> Result<Arc<dyn ProductionServiceFactory>, NetworkErrorCode> {
        let resources = self.resource_dir.join("resources");
        let trust_bytes = read_owned_resource(&resources.join(POLICY_TRUST_RESOURCE_NAME))?;
        let policy_bytes = read_owned_resource(&resources.join(POLICY_RESOURCE_NAME))?;
        // Parse all immutable bundle metadata before touching the replay
        // revision store. A malformed trust manifest must not consume a valid
        // policy revision and brick the next retry.
        let manifest_bytes = read_owned_resource(&resources.join(SIDECAR_TRUST_RESOURCE_NAME))?;
        let manifest: SidecarTrustManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
        validate_trust_metadata(&manifest)?;
        let trust = PolicyTrustStore::from_json(&trust_bytes)?;
        let mut revisions = FilePolicyRevisionStore::new(self.revision_path.clone())?;
        let now = self.now.unwrap_or_else(unix_now);
        // Stage the revision until every non-secret composition input has
        // passed validation. The real file store is written only after the
        // factory configuration is complete.
        let mut staged = StagedRevisionStore {
            backing: &revisions,
            pending: None,
        };
        let verified = trust.verify(&policy_bytes, now, &mut staged)?;
        let configuration = VerifiedProductionConfiguration::new(
            verified.profile,
            verified.revision,
            self.resource_dir.join(SIDECAR_RESOURCE_NAME),
            manifest,
        )?;
        let accepted_revision = staged.pending.ok_or(NetworkErrorCode::PolicySignatureInvalid)?;
        revisions.store(accepted_revision)?;
        let factory = DeferredProductionServiceFactory::new(configuration);
        #[cfg(all(target_os = "macos", feature = "networking-production"))]
        let factory = factory.with_mihomo_source(Arc::new(MacosActiveMihomoTunSource));
        Ok(Arc::new(factory))
    }
}

/// A transactional adapter around the durable revision store. Policy
/// verification can validate replay/freshness against the existing value and
/// record the candidate revision, while the provider delays the actual write
/// until the sidecar manifest and profile composition have also passed.
struct StagedRevisionStore<'a> {
    backing: &'a dyn PolicyRevisionStore,
    pending: Option<u64>,
}

impl PolicyRevisionStore for StagedRevisionStore<'_> {
    fn latest(&self) -> Result<Option<u64>, NetworkErrorCode> {
        self.backing.latest()
    }

    fn store(&mut self, revision: u64) -> Result<(), NetworkErrorCode> {
        if self.pending.replace(revision).is_some() {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
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

fn read_owned_resource(path: &Path) -> Result<Vec<u8>, NetworkErrorCode> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    fs::read(path).map_err(|_| NetworkErrorCode::InvalidConfiguration)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

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

    #[tokio::test]
    async fn missing_bundle_resources_fail_closed_without_materialization_or_revision_write() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let resource_dir = directory.path().join("KyClash.app/Contents/Resources");
        fs::create_dir_all(&resource_dir)?;
        let revision_path = directory.path().join("app-data/networking/policy-revision.json");
        let provider = BundleProductionInitializationProvider::new(resource_dir, revision_path.clone())
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(
            provider.initialize().await.err(),
            Some(NetworkErrorCode::InvalidConfiguration)
        );
        assert!(!revision_path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn malformed_sidecar_manifest_is_reported_before_policy_revision_commit() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let resource_dir = directory.path().join("KyClash.app/Contents/Resources");
        let resources = resource_dir.join("resources");
        fs::create_dir_all(&resources)?;
        fs::write(resources.join(POLICY_TRUST_RESOURCE_NAME), br"{}")?;
        fs::write(resources.join(POLICY_RESOURCE_NAME), br"{}")?;
        fs::write(resources.join(SIDECAR_TRUST_RESOURCE_NAME), br"{")?;
        let revision_path = directory.path().join("app-data/networking/policy-revision.json");
        let provider = BundleProductionInitializationProvider::new(resource_dir, revision_path.clone())
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(
            provider.initialize().await.err(),
            Some(NetworkErrorCode::AuthenticationFailed)
        );
        assert!(!revision_path.exists());
        Ok(())
    }
}
