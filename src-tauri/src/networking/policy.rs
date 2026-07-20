use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use super::{NetworkErrorCode, NetworkProfile};

const SIGNED_POLICY_ENVELOPE_VERSION: u8 = 1;
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

    pub fn verify_profile(&self, encoded_envelope: &[u8]) -> Result<NetworkProfile, NetworkErrorCode> {
        let envelope = serde_json::from_slice::<SignedNetworkPolicyEnvelope>(encoded_envelope)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
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
        let payload = STANDARD
            .decode(envelope.payload_base64)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let signature = STANDARD
            .decode(envelope.signature_base64)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&payload, &signature)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let profile =
            serde_json::from_slice::<NetworkProfile>(&payload).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        profile.validate()?;
        Ok(profile)
    }
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
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair as _},
    };

    use super::*;

    const VALID_PROFILE: &str = include_str!("../../../schemas/fixtures/network-v1.valid.json");

    fn signed_fixture() -> anyhow::Result<(PolicyTrustStore, Vec<u8>)> {
        let random = SystemRandom::new();
        let document =
            Ed25519KeyPair::generate_pkcs8(&random).map_err(|_| anyhow::anyhow!("failed to generate test key"))?;
        let pair =
            Ed25519KeyPair::from_pkcs8(document.as_ref()).map_err(|_| anyhow::anyhow!("failed to decode test key"))?;
        let payload = VALID_PROFILE.as_bytes();
        let envelope = SignedNetworkPolicyEnvelope {
            envelope_version: SIGNED_POLICY_ENVELOPE_VERSION,
            key_id: "policy.test".into(),
            algorithm: SIGNED_POLICY_ALGORITHM.into(),
            payload_base64: STANDARD.encode(payload),
            signature_base64: STANDARD.encode(pair.sign(payload).as_ref()),
        };
        let trust = PolicyTrustStore::from_ed25519_keys([("policy.test".into(), pair.public_key().as_ref().to_vec())])
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        Ok((trust, serde_json::to_vec(&envelope)?))
    }

    #[test]
    fn signed_policy_verifies_and_returns_validated_profile() -> anyhow::Result<()> {
        let (trust, envelope) = signed_fixture()?;
        let profile = trust
            .verify_profile(&envelope)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(profile.profile_id, "profile.test");
        Ok(())
    }

    #[test]
    fn unsigned_unknown_key_and_tampered_policy_fail_closed() -> anyhow::Result<()> {
        let (trust, envelope) = signed_fixture()?;
        assert_eq!(
            trust.verify_profile(VALID_PROFILE.as_bytes()),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );

        let mut unknown = serde_json::from_slice::<SignedNetworkPolicyEnvelope>(&envelope)?;
        unknown.key_id = "policy.unknown".into();
        assert_eq!(
            trust.verify_profile(&serde_json::to_vec(&unknown)?),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );

        let mut tampered = serde_json::from_slice::<SignedNetworkPolicyEnvelope>(&envelope)?;
        let mut payload = STANDARD.decode(&tampered.payload_base64)?;
        payload[0] ^= 1;
        tampered.payload_base64 = STANDARD.encode(payload);
        assert_eq!(
            trust.verify_profile(&serde_json::to_vec(&tampered)?),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        Ok(())
    }
}
