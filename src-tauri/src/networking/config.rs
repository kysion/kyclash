use std::{collections::HashSet, net::IpAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use super::NetworkErrorCode;

pub const NETWORK_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProfile {
    pub schema_version: u8,
    pub profile_id: String,
    pub control_plane: String,
    pub identity_ref: String,
    pub site: SiteConfig,
    pub tunnel: TunnelConfig,
    pub transports: TransportConfig,
    pub policy: NetworkPolicy,
}

impl std::fmt::Debug for NetworkProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkProfile")
            .field("schema_version", &self.schema_version)
            .field("profile_id", &self.profile_id)
            .field("site_id", &self.site.id)
            .field("tunnel", &"<redacted>")
            .field("endpoints", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    pub id: String,
    pub display_name: String,
    pub private_cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub local_addresses: Vec<String>,
    pub peer_public_key: String,
    pub keepalive_seconds: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    pub primary: TransportKind,
    pub fallbacks: Vec<TransportKind>,
    pub endpoints: Vec<TransportEndpoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Quic,
    Wss,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportEndpoint {
    pub transport: TransportKind,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub connect_timeout_seconds: u16,
    pub health_interval_seconds: u16,
    pub fallback_threshold: u8,
}

impl NetworkProfile {
    pub fn validate(&self) -> Result<(), NetworkErrorCode> {
        if self.schema_version != NETWORK_SCHEMA_VERSION {
            return Err(NetworkErrorCode::UnsupportedSchemaVersion);
        }
        if !valid_id(&self.profile_id)
            || self
                .identity_ref
                .strip_prefix("keychain:")
                .is_none_or(|identifier| !valid_id(identifier))
            || !valid_id(&self.site.id)
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let control_plane = Url::parse(&self.control_plane).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        if control_plane.scheme() != "https"
            || !control_plane.username().is_empty()
            || control_plane.password().is_some()
            || control_plane.fragment().is_some()
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        if self.site.display_name.is_empty()
            || !valid_unique_cidrs(&self.site.private_cidrs)
            || !valid_unique_cidrs(&self.tunnel.local_addresses)
            || BASE64
                .decode(&self.tunnel.peer_public_key)
                .ok()
                .is_none_or(|key| key.len() != 32)
            || self.tunnel.keepalive_seconds == 0
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        if self.transports.primary != TransportKind::Quic
            || self.transports.endpoints.is_empty()
            || self.transports.fallbacks.contains(&TransportKind::Quic)
            || !all_unique(self.transports.fallbacks.iter().copied())
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let configured: HashSet<_> = std::iter::once(self.transports.primary)
            .chain(self.transports.fallbacks.iter().copied())
            .collect();
        if !all_unique(self.transports.endpoints.iter().map(|endpoint| endpoint.transport))
            || self
                .transports
                .endpoints
                .iter()
                .map(|endpoint| endpoint.transport)
                .collect::<HashSet<_>>()
                != configured
            || self.transports.endpoints.iter().any(|endpoint| {
                !configured.contains(&endpoint.transport)
                    || Url::parse(&endpoint.url).ok().is_none_or(|url| {
                        !endpoint_scheme_matches(endpoint.transport, url.scheme())
                            || !url.username().is_empty()
                            || url.password().is_some()
                            || url.query().is_some()
                            || url.fragment().is_some()
                            || url.host_str().is_none()
                            || (endpoint.transport == TransportKind::Tcp && url.port().is_none())
                            || (endpoint.transport != TransportKind::Wss && !matches!(url.path(), "" | "/"))
                    })
            })
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        if self.policy.connect_timeout_seconds == 0
            || self.policy.health_interval_seconds == 0
            || self.policy.fallback_threshold == 0
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(())
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .enumerate()
            .all(|(index, ch)| ch.is_ascii_alphanumeric() || (index > 0 && matches!(ch, '.' | '_' | ':' | '-')))
}

fn valid_unique_cidrs(values: &[String]) -> bool {
    !values.is_empty() && all_unique(values.iter()) && values.iter().all(|value| valid_cidr(value))
}

fn valid_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.rsplit_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if address.is_ipv4() { 32 } else { 128 }
}

fn all_unique<T, I>(values: I) -> bool
where
    T: Eq + std::hash::Hash,
    I: IntoIterator<Item = T>,
{
    let mut seen = HashSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

const fn endpoint_scheme_matches(transport: TransportKind, scheme: &str) -> bool {
    match transport {
        TransportKind::Quic => matches!(scheme.as_bytes(), b"https"),
        TransportKind::Wss => matches!(scheme.as_bytes(), b"wss"),
        TransportKind::Tcp => matches!(scheme.as_bytes(), b"tcp"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PROFILE: &str = include_str!("../../../schemas/fixtures/network-v1.valid.json");
    const UNSUPPORTED_PROFILE: &str = include_str!("../../../schemas/fixtures/network-v2.unsupported.json");

    #[test]
    fn valid_fixture_round_trips() -> anyhow::Result<()> {
        let profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        profile.validate().map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let encoded = serde_json::to_string(&profile)?;
        let decoded: NetworkProfile = serde_json::from_str(&encoded)?;
        assert_eq!(profile, decoded);
        Ok(())
    }

    #[test]
    fn unsupported_schema_fails_closed() -> anyhow::Result<()> {
        let profile: NetworkProfile = serde_json::from_str(UNSUPPORTED_PROFILE)?;
        assert_eq!(profile.validate(), Err(NetworkErrorCode::UnsupportedSchemaVersion));
        Ok(())
    }

    #[test]
    fn invalid_cidr_and_transport_fail_validation() -> anyhow::Result<()> {
        let mut profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        profile.site.private_cidrs = vec!["10.0.0.0/99".into()];
        assert_eq!(profile.validate(), Err(NetworkErrorCode::InvalidConfiguration));

        let mut profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        profile.transports.endpoints[0].url = "tcp://edge.example.test:443".into();
        assert_eq!(profile.validate(), Err(NetworkErrorCode::InvalidConfiguration));
        Ok(())
    }

    #[test]
    fn strict_data_plane_fields_fail_closed_and_debug_is_redacted() -> anyhow::Result<()> {
        let profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        let formatted = format!("{profile:?}");
        assert!(!formatted.contains(&profile.tunnel.peer_public_key));
        assert!(!formatted.contains("edge.example.test"));

        let mut invalid_key = profile.clone();
        invalid_key.tunnel.peer_public_key = "invalid".into();
        assert_eq!(invalid_key.validate(), Err(NetworkErrorCode::InvalidConfiguration));

        let mut invalid_identity = profile.clone();
        invalid_identity.identity_ref = "file:forbidden".into();
        assert_eq!(invalid_identity.validate(), Err(NetworkErrorCode::InvalidConfiguration));

        let mut endpoint_query = profile.clone();
        endpoint_query.transports.endpoints[0].url = "https://edge.example.test:443?token=forbidden".into();
        assert_eq!(endpoint_query.validate(), Err(NetworkErrorCode::InvalidConfiguration));

        let mut duplicate_endpoint = profile;
        duplicate_endpoint
            .transports
            .endpoints
            .push(duplicate_endpoint.transports.endpoints[0].clone());
        assert_eq!(
            duplicate_endpoint.validate(),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
        Ok(())
    }
}
