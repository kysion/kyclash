//! Closed, versioned catalog for production policy variants.
//!
//! The frontend never supplies routes or resource paths. It may select only
//! one of the four compile-time catalog IDs below. Every catalog operation
//! reopens the app-owned catalog, trust bundle, and all four envelope
//! resources, verifies every envelope v2 signature, and then validates the
//! exact route entitlement for that ID.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

use async_trait::async_trait;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};

use super::{
    NetworkErrorCode, NetworkProfile, PolicyTrustStore, ProductionServiceFactory, VerifiedNetworkPolicy,
    read_owned_resource,
};

pub const POLICY_CATALOG_RESOURCE_NAME: &str = "kyclash-networking-policy-catalog-v1.json";
const CATALOG_POLICY_TRUST_RESOURCE_NAME: &str = "kyclash-networking-policy-keys.json";
const POLICY_CATALOG_SCHEMA_VERSION: u8 = 1;
const POLICY_CATALOG_MAX_BYTES: usize = 32 * 1024;
const POLICY_ENVELOPE_MAX_BYTES: usize = 64 * 1024;
const POLICY_TRUST_MAX_BYTES: usize = 64 * 1024;

pub const BASE_VARIANT_ID: &str = "base";
pub const BASE_30_VARIANT_ID: &str = "base+.30";
pub const BASE_31_VARIANT_ID: &str = "base+.31";
pub const BASE_BOTH_VARIANT_ID: &str = "base+both";

const BASE_ROUTES: [&str; 2] = ["10.68.72.0/21", "10.20.81.0/24"];
const HOST_30: &str = "10.68.64.30/32";
const HOST_31: &str = "10.68.64.31/32";

#[derive(Debug, Clone, Copy)]
struct LockedVariant {
    id: &'static str,
    display_name: &'static str,
    envelope_resource: &'static str,
    routes: &'static [&'static str],
}

const BASE_30_ROUTES: [&str; 3] = [BASE_ROUTES[0], BASE_ROUTES[1], HOST_30];
const BASE_31_ROUTES: [&str; 3] = [BASE_ROUTES[0], BASE_ROUTES[1], HOST_31];
const BASE_BOTH_ROUTES: [&str; 4] = [BASE_ROUTES[0], BASE_ROUTES[1], HOST_30, HOST_31];

const LOCKED_VARIANTS: [LockedVariant; 4] = [
    LockedVariant {
        id: BASE_VARIANT_ID,
        display_name: "Base routes",
        envelope_resource: "kyclash-networking-policy-base-v2.json",
        routes: &BASE_ROUTES,
    },
    LockedVariant {
        id: BASE_30_VARIANT_ID,
        display_name: "Base + 10.68.64.30",
        envelope_resource: "kyclash-networking-policy-base-30-v2.json",
        routes: &BASE_30_ROUTES,
    },
    LockedVariant {
        id: BASE_31_VARIANT_ID,
        display_name: "Base + 10.68.64.31",
        envelope_resource: "kyclash-networking-policy-base-31-v2.json",
        routes: &BASE_31_ROUTES,
    },
    LockedVariant {
        id: BASE_BOTH_VARIANT_ID,
        display_name: "Base + both optional hosts",
        envelope_resource: "kyclash-networking-policy-base-both-v2.json",
        routes: &BASE_BOTH_ROUTES,
    },
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyCatalogResource {
    schema_version: u8,
    revision: u64,
    entries: Vec<PolicyCatalogEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyCatalogEntry {
    id: String,
    envelope_resource: String,
}

/// Redacted, authenticated option safe to render in the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionPolicyVariantSummary {
    pub catalog_id: String,
    pub display_name: String,
    pub revision: u64,
    pub profile_sha256: String,
    pub private_cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionPolicyCatalogView {
    pub schema_version: u8,
    pub selected_catalog_id: Option<String>,
    pub variants: Vec<ProductionPolicyVariantSummary>,
}

impl ProductionPolicyCatalogView {
    pub(crate) fn from_verified(
        variants: &[VerifiedProductionPolicyVariant],
        selected: Option<&VerifiedProductionPolicyVariant>,
    ) -> Result<Self, NetworkErrorCode> {
        if let Some(selected) = selected {
            let current = variants
                .iter()
                .find(|variant| variant.summary.catalog_id == selected.summary.catalog_id)
                .ok_or(NetworkErrorCode::PolicySignatureInvalid)?;
            if current != selected {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
        }
        Ok(Self {
            schema_version: POLICY_CATALOG_SCHEMA_VERSION,
            selected_catalog_id: selected.map(|variant| variant.summary.catalog_id.clone()),
            variants: variants.iter().map(|variant| variant.summary.clone()).collect(),
        })
    }
}

/// Full backend-only binding retained between selection and Connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProductionPolicyVariant {
    pub summary: ProductionPolicyVariantSummary,
    envelope_sha256: String,
}

impl VerifiedProductionPolicyVariant {
    fn new(locked: LockedVariant, policy: &VerifiedNetworkPolicy) -> Result<Self, NetworkErrorCode> {
        validate_route_entitlement(&policy.profile, locked.routes)?;
        Ok(Self {
            summary: ProductionPolicyVariantSummary {
                catalog_id: locked.id.into(),
                display_name: locked.display_name.into(),
                revision: policy.revision,
                profile_sha256: profile_sha256(&policy.profile)?,
                private_cidrs: policy.profile.site.private_cidrs.clone(),
            },
            envelope_sha256: policy.envelope_sha256.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_binding(catalog_id: &str, revision: u64, route_count: usize) -> Self {
        Self {
            summary: ProductionPolicyVariantSummary {
                catalog_id: catalog_id.into(),
                display_name: catalog_id.into(),
                revision,
                profile_sha256: format!("{revision:064x}"),
                private_cidrs: (0..route_count).map(|index| format!("10.0.{index}.0/24")).collect(),
            },
            envelope_sha256: format!("{:064x}", revision.saturating_add(1)),
        }
    }
}

pub struct PreparedProductionPolicyVariant {
    pub variants: Vec<VerifiedProductionPolicyVariant>,
    pub selected: VerifiedProductionPolicyVariant,
    pub factory: Arc<dyn ProductionServiceFactory>,
}

#[async_trait]
pub trait ProductionPolicyCatalogProvider: Send + Sync {
    async fn verify_policy_variants(&self) -> Result<Vec<VerifiedProductionPolicyVariant>, NetworkErrorCode>;

    async fn prepare_policy_variant(
        &self,
        catalog_id: &str,
        expected: Option<&VerifiedProductionPolicyVariant>,
    ) -> Result<PreparedProductionPolicyVariant, NetworkErrorCode>;
}

#[derive(Clone)]
pub(crate) struct VerifiedProductionPolicyCatalog {
    pub revision: u64,
    pub identity_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    entries: Vec<VerifiedCatalogEntry>,
}

#[derive(Clone)]
struct VerifiedCatalogEntry {
    binding: VerifiedProductionPolicyVariant,
    policy: VerifiedNetworkPolicy,
}

impl VerifiedProductionPolicyCatalog {
    pub(crate) fn bindings(&self) -> Vec<VerifiedProductionPolicyVariant> {
        self.entries.iter().map(|entry| entry.binding.clone()).collect()
    }

    pub(crate) fn selected(
        &self,
        catalog_id: &str,
    ) -> Result<(&VerifiedProductionPolicyVariant, &VerifiedNetworkPolicy), NetworkErrorCode> {
        self.entries
            .iter()
            .find(|entry| entry.binding.summary.catalog_id == catalog_id)
            .map(|entry| (&entry.binding, &entry.policy))
            .ok_or(NetworkErrorCode::InvalidConfiguration)
    }

    pub(crate) fn validate_at(&self, now: u64) -> Result<(), NetworkErrorCode> {
        if self.revision == 0 || self.issued_at > now || self.expires_at <= now {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        for entry in &self.entries {
            entry.policy.validate_at(now)?;
        }
        Ok(())
    }
}

pub(crate) fn verify_policy_catalog(
    resources: &Path,
    now: u64,
) -> Result<VerifiedProductionPolicyCatalog, NetworkErrorCode> {
    let catalog_bytes = read_owned_resource(&resources.join(POLICY_CATALOG_RESOURCE_NAME), POLICY_CATALOG_MAX_BYTES)?;
    let catalog: PolicyCatalogResource =
        serde_json::from_slice(&catalog_bytes).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    if catalog.schema_version != POLICY_CATALOG_SCHEMA_VERSION || catalog.revision == 0 {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }

    let mut resources_by_id = BTreeMap::new();
    for entry in catalog.entries {
        if resources_by_id.insert(entry.id, entry.envelope_resource).is_some() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
    }
    if resources_by_id.len() != LOCKED_VARIANTS.len() {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    for locked in LOCKED_VARIANTS {
        if resources_by_id.get(locked.id).map(String::as_str) != Some(locked.envelope_resource) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
    }

    let trust_bytes = read_owned_resource(
        &resources.join(CATALOG_POLICY_TRUST_RESOURCE_NAME),
        POLICY_TRUST_MAX_BYTES,
    )?;
    let trust = PolicyTrustStore::from_json(&trust_bytes)?;
    let mut digest_context = Context::new(&SHA256);
    digest_context.update(b"kyclash-production-policy-catalog-v1\0");
    digest_context.update(&catalog_bytes);
    digest_context.update(&[0]);
    digest_context.update(&trust_bytes);
    digest_context.update(&[0]);

    let mut entries = Vec::with_capacity(LOCKED_VARIANTS.len());
    let mut issued_at = 0_u64;
    let mut expires_at = u64::MAX;
    for locked in LOCKED_VARIANTS {
        let envelope_bytes = read_owned_resource(&resources.join(locked.envelope_resource), POLICY_ENVELOPE_MAX_BYTES)?;
        let policy = trust.verify(&envelope_bytes, now)?;
        let binding = VerifiedProductionPolicyVariant::new(locked, &policy)?;
        issued_at = issued_at.max(policy.issued_at);
        expires_at = expires_at.min(policy.expires_at);
        digest_context.update(locked.id.as_bytes());
        digest_context.update(&[0]);
        digest_context.update(policy.envelope_sha256.as_bytes());
        digest_context.update(&[0]);
        entries.push(VerifiedCatalogEntry { binding, policy });
    }
    let identity_sha256 = digest_context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let verified = VerifiedProductionPolicyCatalog {
        revision: catalog.revision,
        identity_sha256,
        issued_at,
        expires_at,
        entries,
    };
    verified.validate_at(now)?;
    Ok(verified)
}

fn validate_route_entitlement(profile: &NetworkProfile, expected: &[&str]) -> Result<(), NetworkErrorCode> {
    let actual = profile
        .site
        .private_cidrs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual.len() != profile.site.private_cidrs.len() || actual != expected {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    Ok(())
}

fn profile_sha256(profile: &NetworkProfile) -> Result<String, NetworkErrorCode> {
    let bytes = serde_json::to_vec(profile).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    Ok(ring::digest::digest(&SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::*;

    fn profile(routes: &[&str]) -> anyhow::Result<NetworkProfile> {
        let mut profile: NetworkProfile =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))?;
        profile.site.private_cidrs = routes.iter().map(|route| (*route).to_owned()).collect();
        Ok(profile)
    }

    fn write_fixture(resources: &Path, routes_by_id: &[(&str, &[&str])], expires_at: u64) -> anyhow::Result<()> {
        fs::create_dir_all(resources)?;
        let mut public_key = None;
        for locked in LOCKED_VARIANTS {
            let routes = routes_by_id
                .iter()
                .find(|(id, _)| *id == locked.id)
                .map(|(_, routes)| *routes)
                .unwrap_or(locked.routes);
            let (envelope, current_public_key) = crate::networking::signed_test_policy_with_profile(
                100 + u64::try_from(
                    LOCKED_VARIANTS
                        .iter()
                        .position(|candidate| candidate.id == locked.id)
                        .ok_or_else(|| anyhow::anyhow!("locked variant"))?,
                )?,
                100,
                expires_at,
                "policy.test",
                profile(routes)?,
            )?;
            public_key = Some(current_public_key);
            fs::write(resources.join(locked.envelope_resource), serde_json::to_vec(&envelope)?)?;
        }
        let trust = serde_json::json!({
            "schema_version": 1,
            "keys": [{
                "key_id": "policy.test",
                "public_key_base64": STANDARD.encode(
                    public_key.ok_or_else(|| anyhow::anyhow!("public key"))?
                ),
            }],
        });
        fs::write(
            resources.join(CATALOG_POLICY_TRUST_RESOURCE_NAME),
            serde_json::to_vec(&trust)?,
        )?;
        write_catalog(resources, LOCKED_VARIANTS.iter().map(|variant| variant.id))?;
        Ok(())
    }

    fn write_catalog<'a>(resources: &Path, ids: impl IntoIterator<Item = &'a str>) -> anyhow::Result<()> {
        let entries = ids
            .into_iter()
            .map(|id| {
                let resource = LOCKED_VARIANTS
                    .iter()
                    .find(|variant| variant.id == id)
                    .map_or("unknown.json", |variant| variant.envelope_resource);
                serde_json::json!({"id": id, "envelope_resource": resource})
            })
            .collect::<Vec<_>>();
        fs::write(
            resources.join(POLICY_CATALOG_RESOURCE_NAME),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "revision": 9,
                "entries": entries,
            }))?,
        )?;
        Ok(())
    }

    #[test]
    fn exact_four_variant_catalog_is_verified_and_profile_bound() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        write_fixture(directory.path(), &[], 300)?;
        let catalog = verify_policy_catalog(directory.path(), 150).map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(catalog.revision, 9);
        assert_eq!(
            catalog
                .bindings()
                .iter()
                .map(|variant| variant.summary.catalog_id.as_str())
                .collect::<Vec<_>>(),
            [
                BASE_VARIANT_ID,
                BASE_30_VARIANT_ID,
                BASE_31_VARIANT_ID,
                BASE_BOTH_VARIANT_ID
            ]
        );
        for binding in catalog.bindings() {
            assert_eq!(binding.summary.profile_sha256.len(), 64);
            assert_eq!(binding.envelope_sha256.len(), 64);
        }
        let base = catalog
            .selected(BASE_VARIANT_ID)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let both = catalog
            .selected(BASE_BOTH_VARIANT_ID)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_ne!(base.0.summary.profile_sha256, both.0.summary.profile_sha256);
        Ok(())
    }

    #[test]
    fn route_entitlements_reject_default_widened_obsolete_and_wrong_optional_hosts() -> anyhow::Result<()> {
        for routes in [
            vec!["0.0.0.0/0", BASE_ROUTES[0], BASE_ROUTES[1]],
            vec![BASE_ROUTES[0], BASE_ROUTES[1], "10.68.64.0/24"],
            vec![BASE_ROUTES[0], BASE_ROUTES[1], "10.68.72.1/32"],
            vec![BASE_ROUTES[0], BASE_ROUTES[1], HOST_31],
        ] {
            let directory = tempfile::tempdir()?;
            write_fixture(directory.path(), &[(BASE_30_VARIANT_ID, routes.as_slice())], 300)?;
            assert_eq!(
                verify_policy_catalog(directory.path(), 150).err(),
                Some(NetworkErrorCode::InvalidConfiguration)
            );
        }
        Ok(())
    }

    #[test]
    fn catalog_rejects_unknown_and_duplicate_ids() -> anyhow::Result<()> {
        for ids in [
            vec![BASE_VARIANT_ID, BASE_30_VARIANT_ID, BASE_31_VARIANT_ID, "unknown"],
            vec![BASE_VARIANT_ID, BASE_30_VARIANT_ID, BASE_31_VARIANT_ID, BASE_VARIANT_ID],
        ] {
            let directory = tempfile::tempdir()?;
            write_fixture(directory.path(), &[], 300)?;
            write_catalog(directory.path(), ids)?;
            assert_eq!(
                verify_policy_catalog(directory.path(), 150).err(),
                Some(NetworkErrorCode::InvalidConfiguration)
            );
        }
        Ok(())
    }

    #[test]
    fn catalog_rejects_tampered_and_expired_envelopes() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        write_fixture(directory.path(), &[], 300)?;
        let path = directory.path().join(LOCKED_VARIANTS[2].envelope_resource);
        let mut envelope: crate::networking::SignedNetworkPolicyEnvelope = serde_json::from_slice(&fs::read(&path)?)?;
        envelope.payload_base64.push('A');
        fs::write(&path, serde_json::to_vec(&envelope)?)?;
        assert_eq!(
            verify_policy_catalog(directory.path(), 150).err(),
            Some(NetworkErrorCode::PolicySignatureInvalid)
        );

        let expired = tempfile::tempdir()?;
        write_fixture(expired.path(), &[], 150)?;
        assert_eq!(
            verify_policy_catalog(expired.path(), 150).err(),
            Some(NetworkErrorCode::PolicySignatureInvalid)
        );
        Ok(())
    }
}
