use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use super::{NetworkErrorCode, NetworkProfile};

const SIGNED_POLICY_ENVELOPE_VERSION: u8 = 2;
const SIGNED_POLICY_ALGORITHM: &str = "ed25519";
const REVISION_STORE_VERSION: u8 = 1;

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

pub trait PolicyRevisionStore {
    fn latest(&self) -> Result<Option<u64>, NetworkErrorCode>;
    fn store(&mut self, revision: u64) -> Result<(), NetworkErrorCode>;
}

#[derive(Default)]
pub struct MemoryPolicyRevisionStore {
    latest: Option<u64>,
    fail_store: bool,
}

impl MemoryPolicyRevisionStore {
    #[cfg(test)]
    const fn failing() -> Self {
        Self {
            latest: None,
            fail_store: true,
        }
    }
}

impl PolicyRevisionStore for MemoryPolicyRevisionStore {
    fn latest(&self) -> Result<Option<u64>, NetworkErrorCode> {
        Ok(self.latest)
    }
    fn store(&mut self, revision: u64) -> Result<(), NetworkErrorCode> {
        if self.fail_store {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        self.latest = Some(revision);
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionRecord {
    schema_version: u8,
    revision: u64,
}

pub struct FilePolicyRevisionStore {
    path: PathBuf,
}

impl FilePolicyRevisionStore {
    pub fn new(path: PathBuf) -> Result<Self, NetworkErrorCode> {
        if path.file_name().is_none() || path.parent().is_none() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self { path })
    }

    fn refuse_symlink(&self) -> Result<(), NetworkErrorCode> {
        if self
            .path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
    }
}

impl PolicyRevisionStore for FilePolicyRevisionStore {
    fn latest(&self) -> Result<Option<u64>, NetworkErrorCode> {
        self.refuse_symlink()?;
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(NetworkErrorCode::PolicySignatureInvalid),
        };
        let record: RevisionRecord =
            serde_json::from_slice(&bytes).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        if record.schema_version != REVISION_STORE_VERSION {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(Some(record.revision))
    }

    fn store(&mut self, revision: u64) -> Result<(), NetworkErrorCode> {
        self.refuse_symlink()?;
        let parent = self.path.parent().ok_or(NetworkErrorCode::InvalidConfiguration)?;
        fs::create_dir_all(parent).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let temporary = temporary_path(&self.path);
        let bytes = serde_json::to_vec(&RevisionRecord {
            schema_version: REVISION_STORE_VERSION,
            revision,
        })
        .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options
                .open(&temporary)
                .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
            fs::rename(&temporary, &self.path).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[derive(Default)]
pub struct PolicyTrustStore {
    public_keys: HashMap<String, Vec<u8>>,
}

impl PolicyTrustStore {
    pub fn from_ed25519_keys(keys: impl IntoIterator<Item = (String, Vec<u8>)>) -> Result<Self, NetworkErrorCode> {
        let public_keys = keys.into_iter().collect::<HashMap<_, _>>();
        if public_keys.is_empty()
            || public_keys
                .iter()
                .any(|(key_id, public_key)| !valid_key_id(key_id) || public_key.len() != 32)
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self { public_keys })
    }

    pub fn verify_profile(
        &self,
        encoded: &[u8],
        now: u64,
        revisions: &mut dyn PolicyRevisionStore,
    ) -> Result<NetworkProfile, NetworkErrorCode> {
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
        if payload.revision == 0
            || payload.issued_at > now
            || payload.expires_at <= now
            || payload.expires_at <= payload.issued_at
            || revisions.latest()?.is_some_and(|latest| payload.revision <= latest)
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        payload.profile.validate()?;
        revisions.store(payload.revision)?;
        Ok(payload.profile)
    }
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

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}.tmp", std::process::id()));
    PathBuf::from(name)
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
    fn v2_accepts_once_and_rejects_replay_and_clock_boundaries() -> anyhow::Result<()> {
        let (trust, _, envelope) = signed_fixture(100, 200, 7)?;
        let encoded = serde_json::to_vec(&envelope)?;
        let mut revisions = MemoryPolicyRevisionStore::default();
        assert_eq!(
            trust
                .verify_profile(&encoded, 100, &mut revisions)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?
                .profile_id,
            "profile.test"
        );
        assert_eq!(
            trust.verify_profile(&encoded, 101, &mut revisions),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        for (issued, expires, now) in [(101, 200, 100), (100, 100, 100), (100, 200, 200)] {
            let (trust, _, envelope) = signed_fixture(issued, expires, 8)?;
            assert_eq!(
                trust.verify_profile(
                    &serde_json::to_vec(&envelope)?,
                    now,
                    &mut MemoryPolicyRevisionStore::default()
                ),
                Err(NetworkErrorCode::PolicySignatureInvalid)
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_v1_unknown_key_tamper_and_revision_store_failure() -> anyhow::Result<()> {
        let (trust, _, mut envelope) = signed_fixture(100, 200, 9)?;
        envelope.envelope_version = 1;
        assert_eq!(
            trust.verify_profile(
                &serde_json::to_vec(&envelope)?,
                150,
                &mut MemoryPolicyRevisionStore::default()
            ),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        let (trust, _, mut envelope) = signed_fixture(100, 200, 9)?;
        envelope.key_id = "policy.unknown".into();
        assert_eq!(
            trust.verify_profile(
                &serde_json::to_vec(&envelope)?,
                150,
                &mut MemoryPolicyRevisionStore::default()
            ),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        let (trust, _, mut envelope) = signed_fixture(100, 200, 9)?;
        envelope.payload_base64.push('A');
        assert_eq!(
            trust.verify_profile(
                &serde_json::to_vec(&envelope)?,
                150,
                &mut MemoryPolicyRevisionStore::default()
            ),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        let (trust, _, envelope) = signed_fixture(100, 200, 9)?;
        assert_eq!(
            trust.verify_profile(
                &serde_json::to_vec(&envelope)?,
                150,
                &mut MemoryPolicyRevisionStore::failing()
            ),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        Ok(())
    }

    #[test]
    fn file_store_persists_only_revision_and_refuses_corruption() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("revision.json");
        let mut store = FilePolicyRevisionStore::new(path.clone()).map_err(|error| anyhow::anyhow!("{error:?}"))?;
        store.store(42).map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(store.latest().map_err(|error| anyhow::anyhow!("{error:?}"))?, Some(42));
        let bytes = fs::read(&path)?;
        assert!(!String::from_utf8_lossy(&bytes).contains("profile"));
        fs::write(&path, b"not-json")?;
        assert_eq!(store.latest(), Err(NetworkErrorCode::PolicySignatureInvalid));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            fs::remove_file(&path)?;
            let target = directory.path().join("target.json");
            fs::write(&target, br#"{"schema_version":1,"revision":99}"#)?;
            symlink(&target, &path)?;
            assert_eq!(store.latest(), Err(NetworkErrorCode::PolicySignatureInvalid));
        }
        Ok(())
    }
}
