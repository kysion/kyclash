use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::digest::{SHA256, digest};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use super::{NetworkErrorCode, NetworkProfile};

const SIGNED_POLICY_ENVELOPE_VERSION: u8 = 2;
const SIGNED_POLICY_ALGORITHM: &str = "ed25519";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNetworkPolicyEnvelope {
    pub envelope_version: u8,
    pub key_id: String,
    pub algorithm: String,
    pub payload_base64: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNetworkPolicyPayload {
    pub issued_at: u64,
    pub expires_at: u64,
    pub revision: u64,
    pub profile: NetworkProfile,
}

/// The result of accepting a signed policy envelope.  Keeping the revision
/// alongside the validated profile is important at the composition boundary:
/// the route lease must carry the exact revision that was authenticated, not a
/// caller-supplied or regenerated value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNetworkPolicy {
    pub key_id: String,
    /// Lowercase SHA-256 of the exact signed-envelope resource bytes. This is
    /// deliberately not calculated from a reserialized envelope or payload.
    pub envelope_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revision: u64,
    pub profile: NetworkProfile,
}

impl VerifiedNetworkPolicy {
    /// Recheck authenticated temporal fields against a caller-supplied clock.
    /// The durable identity transaction invokes this again immediately before
    /// commit so an otherwise idempotent restart cannot outlive policy expiry.
    pub const fn validate_at(&self, now: u64) -> Result<(), NetworkErrorCode> {
        if self.revision == 0 || self.issued_at > now || self.expires_at <= now || self.expires_at <= self.issued_at {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTrustBundle {
    schema_version: u8,
    keys: Vec<PolicyTrustKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTrustKey {
    key_id: String,
    public_key_base64: String,
}

#[derive(Default)]
pub struct PolicyTrustStore {
    public_keys: HashMap<String, Vec<u8>>,
}

impl PolicyTrustStore {
    pub fn from_ed25519_keys(keys: impl IntoIterator<Item = (String, Vec<u8>)>) -> Result<Self, NetworkErrorCode> {
        let mut public_keys = HashMap::new();
        for (key_id, public_key) in keys {
            if !valid_key_id(&key_id) || public_key.len() != 32 || public_keys.insert(key_id, public_key).is_some() {
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
        }
        if public_keys.is_empty() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self { public_keys })
    }

    /// Parse the app-owned, signed-resource trust bundle.  The bundle carries
    /// public verification material only; private signing keys are never
    /// accepted by this API.  Callers should obtain these bytes from a
    /// code-signed resource or another explicitly pinned backend boundary,
    /// never from a frontend-provided key.
    pub fn from_json(encoded: &[u8]) -> Result<Self, NetworkErrorCode> {
        let bundle: PolicyTrustBundle =
            serde_json::from_slice(encoded).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        if bundle.schema_version != 1 || bundle.keys.is_empty() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let keys = bundle
            .keys
            .into_iter()
            .map(|key| {
                let public_key = STANDARD
                    .decode(key.public_key_base64)
                    .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
                Ok((key.key_id, public_key))
            })
            .collect::<Result<Vec<_>, NetworkErrorCode>>()?;
        Self::from_ed25519_keys(keys)
    }

    pub fn verify_profile(&self, encoded: &[u8], now: u64) -> Result<NetworkProfile, NetworkErrorCode> {
        self.verify(encoded, now).map(|verified| verified.profile)
    }

    /// Verify a v2 envelope while retaining the authenticated metadata needed
    /// by production composition. Replay classification and durable identity
    /// persistence are intentionally owned by the caller's locked identity
    /// transaction so the lock spans this complete authentication step.
    pub fn verify(&self, encoded: &[u8], now: u64) -> Result<VerifiedNetworkPolicy, NetworkErrorCode> {
        let envelope: SignedNetworkPolicyEnvelope =
            serde_json::from_slice(encoded).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        if envelope.envelope_version != SIGNED_POLICY_ENVELOPE_VERSION
            || envelope.algorithm != SIGNED_POLICY_ALGORITHM
            || !valid_key_id(&envelope.key_id)
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let public_key = self
            .public_keys
            .get(&envelope.key_id)
            .ok_or(NetworkErrorCode::PolicySignatureInvalid)?;
        let payload_bytes = STANDARD
            .decode(&envelope.payload_base64)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let signature = STANDARD
            .decode(&envelope.signature_base64)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let signed = signing_message(&envelope.key_id, &envelope.algorithm, &payload_bytes);
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&signed, &signature)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let payload: SignedNetworkPolicyPayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        payload.profile.validate()?;
        let verified = VerifiedNetworkPolicy {
            key_id: envelope.key_id,
            envelope_sha256: hex_sha256(encoded),
            issued_at: payload.issued_at,
            expires_at: payload.expires_at,
            revision: payload.revision,
            profile: payload.profile,
        };
        verified.validate_at(now)?;
        Ok(verified)
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn signing_message(key_id: &str, algorithm: &str, payload: &[u8]) -> Vec<u8> {
    let mut message = b"kyclash-policy-envelope-v2\0".to_vec();
    message.extend_from_slice(key_id.as_bytes());
    message.push(0);
    message.extend_from_slice(algorithm.as_bytes());
    message.push(0);
    message.extend_from_slice(payload);
    message
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_alphanumeric() || (index > 0 && matches!(character, '.' | '_' | ':' | '-'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    const VALID_PROFILE: &str = include_str!("../../../schemas/fixtures/network-v1.valid.json");
    const TEST_POLICY_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49,
        0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    const TEST_POLICY_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1,
        0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];

    fn signed_fixture(
        issued_at: u64,
        expires_at: u64,
        revision: u64,
    ) -> anyhow::Result<(PolicyTrustStore, Ed25519KeyPair, SignedNetworkPolicyEnvelope)> {
        let pair = Ed25519KeyPair::from_seed_unchecked(&TEST_POLICY_SEED).map_err(|_| anyhow::anyhow!("decode key"))?;
        assert_eq!(pair.public_key().as_ref(), TEST_POLICY_PUBLIC);
        let payload = SignedNetworkPolicyPayload {
            issued_at,
            expires_at,
            revision,
            profile: serde_json::from_str(VALID_PROFILE)?,
        };
        let payload_bytes = serde_json::to_vec(&payload)?;
        let envelope = SignedNetworkPolicyEnvelope {
            envelope_version: 2,
            key_id: "policy.test".into(),
            algorithm: "ed25519".into(),
            payload_base64: STANDARD.encode(&payload_bytes),
            signature_base64: STANDARD.encode(
                pair.sign(&signing_message("policy.test", "ed25519", &payload_bytes))
                    .as_ref(),
            ),
        };
        let trust = PolicyTrustStore::from_ed25519_keys([("policy.test".into(), pair.public_key().as_ref().to_vec())])
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        Ok((trust, pair, envelope))
    }

    #[test]
    fn v2_verification_is_pure_and_rejects_clock_boundaries() -> anyhow::Result<()> {
        let (trust, _, envelope) = signed_fixture(100, 200, 7)?;
        let encoded = serde_json::to_vec(&envelope)?;
        assert_eq!(
            trust
                .verify_profile(&encoded, 100)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?
                .profile_id,
            "profile.test"
        );
        assert_eq!(
            trust
                .verify_profile(&encoded, 101)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?
                .profile_id,
            "profile.test"
        );
        for (issued, expires, now) in [(101, 200, 100), (100, 100, 100), (100, 200, 200)] {
            let (trust, _, envelope) = signed_fixture(issued, expires, 8)?;
            assert_eq!(
                trust.verify_profile(&serde_json::to_vec(&envelope)?, now),
                Err(NetworkErrorCode::PolicySignatureInvalid)
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_v1_unknown_key_and_tamper() -> anyhow::Result<()> {
        let (trust, _, mut envelope) = signed_fixture(100, 200, 9)?;
        envelope.envelope_version = 1;
        assert_eq!(
            trust.verify_profile(&serde_json::to_vec(&envelope)?, 150),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        let (trust, _, mut envelope) = signed_fixture(100, 200, 9)?;
        envelope.key_id = "policy.unknown".into();
        assert_eq!(
            trust.verify_profile(&serde_json::to_vec(&envelope)?, 150),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        let (trust, _, mut envelope) = signed_fixture(100, 200, 9)?;
        envelope.payload_base64.push('A');
        assert_eq!(
            trust.verify_profile(&serde_json::to_vec(&envelope)?, 150),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        Ok(())
    }

    #[test]
    fn trust_bundle_parser_is_strict_and_rejects_duplicate_keys() -> anyhow::Result<()> {
        let encoded_key = STANDARD.encode(TEST_POLICY_PUBLIC);
        let valid = serde_json::json!({
            "schema_version": 1,
            "keys": [{"key_id": "policy.test", "public_key_base64": encoded_key}],
        });
        let trust = PolicyTrustStore::from_json(&serde_json::to_vec(&valid)?);
        assert!(trust.is_ok());

        let duplicate = serde_json::json!({
            "schema_version": 1,
            "keys": [
                {"key_id": "policy.test", "public_key_base64": STANDARD.encode(TEST_POLICY_PUBLIC)},
                {"key_id": "policy.test", "public_key_base64": STANDARD.encode(TEST_POLICY_PUBLIC)},
            ],
        });
        assert_eq!(
            PolicyTrustStore::from_json(&serde_json::to_vec(&duplicate)?).err(),
            Some(NetworkErrorCode::InvalidConfiguration)
        );
        let unknown = serde_json::json!({
            "schema_version": 1,
            "keys": [{"key_id": "policy.test", "public_key_base64": encoded_key}],
            "unexpected": true,
        });
        assert_eq!(
            PolicyTrustStore::from_json(&serde_json::to_vec(&unknown)?).err(),
            Some(NetworkErrorCode::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn verify_retains_authenticated_revision_for_composition() -> anyhow::Result<()> {
        let (trust, _, envelope) = signed_fixture(100, 200, 11)?;
        let verified = trust
            .verify(&serde_json::to_vec(&envelope)?, 150)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(verified.key_id, "policy.test");
        assert_eq!(verified.revision, 11);
        assert_eq!(verified.profile.profile_id, "profile.test");
        assert_eq!(verified.envelope_sha256.len(), 64);
        assert!(verified.envelope_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn exact_envelope_digest_changes_with_json_whitespace() -> anyhow::Result<()> {
        let (trust, _, envelope) = signed_fixture(100, 200, 12)?;
        let compact = serde_json::to_vec(&envelope)?;
        let pretty = serde_json::to_vec_pretty(&envelope)?;
        let compact_verified = trust
            .verify(&compact, 150)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let pretty_verified = trust
            .verify(&pretty, 150)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(compact_verified.revision, pretty_verified.revision);
        assert_ne!(compact_verified.envelope_sha256, pretty_verified.envelope_sha256);
        assert!(
            compact_verified
                .envelope_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        Ok(())
    }

    #[cfg(feature = "networking-system-lab")]
    #[test]
    fn random_js_generator_output_verifies_with_production_rust() -> anyhow::Result<()> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct JsFixture {
            now: u64,
            policy_base64: String,
            trust_base64: String,
        }

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../scripts/networking-production-policy-rust-fixture.mjs");
        let output = std::process::Command::new("node")
            .arg(script)
            .output()
            .map_err(|_| anyhow::anyhow!("cannot launch the JS policy fixture"))?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(anyhow::anyhow!("JS policy fixture failed"));
        }
        let fixture: JsFixture = serde_json::from_slice(&output.stdout)?;
        let policy = STANDARD.decode(fixture.policy_base64)?;
        let trust_bytes = STANDARD.decode(fixture.trust_base64)?;
        let trust = PolicyTrustStore::from_json(&trust_bytes).map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let verified = trust
            .verify(&policy, fixture.now)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(verified.key_id, "lab.vm.0123456789abcdef");
        assert_eq!(verified.revision, 42);
        assert_eq!(verified.profile.control_plane, "https://127.0.0.1:20001/control");
        assert_eq!(verified.profile.site.private_cidrs, ["10.88.0.2/32", "fd00:88::2/128"]);
        Ok(())
    }
}
