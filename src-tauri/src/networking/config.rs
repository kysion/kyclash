use std::{collections::HashSet, net::IpAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use super::NetworkErrorCode;

pub const NETWORK_SCHEMA_VERSION: u8 = 1;
pub const PRODUCTION_NETWORK_SCHEMA_VERSION: u8 = 2;
pub const PRODUCTION_CARRIER_AUTH_VERSION: u8 = 1;
pub const PRODUCTION_QUIC_ALPN: &str = "kyclash-network/1";
pub const PRODUCTION_WSS_PATH: &str = "/kynp";
pub const PRODUCTION_TUNNEL_MTU: u16 = 1420;

const PRODUCTION_MAX_PRIVATE_CIDRS: usize = 16;
const PRODUCTION_MAX_PRIVATE_CIDR_TEXT_BYTES: usize = 1024;

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

/// The first production profile paired with the locked Linux Peer v2
/// configuration.
///
/// This type is deliberately separate from [`NetworkProfile`]. Constructing
/// and validating it does not opt the existing lab or production composition
/// into the v2 runtime.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionNetworkProfileV2 {
    pub schema_version: u8,
    pub carrier_auth_version: u8,
    pub profile_id: String,
    pub control_plane: String,
    pub identity_ref: String,
    pub site: ProductionSiteConfigV2,
    pub tunnel: ProductionTunnelConfigV2,
    pub transports: ProductionTransportConfigV2,
    pub policy: ProductionNetworkPolicyV2,
}

impl std::fmt::Debug for ProductionNetworkProfileV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionNetworkProfileV2")
            .field("schema_version", &self.schema_version)
            .field("carrier_auth_version", &self.carrier_auth_version)
            .field("profile_id", &self.profile_id)
            .field("site_id", &self.site.id)
            .field("tunnel", &"<redacted>")
            .field("endpoints", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionSiteConfigV2 {
    pub id: String,
    pub display_name: String,
    pub private_cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionTunnelConfigV2 {
    pub local_addresses: Vec<String>,
    pub local_public_key: String,
    pub peer_public_key: String,
    pub keepalive_seconds: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionTransportConfigV2 {
    pub primary: ProductionTransportKindV2,
    pub fallbacks: Vec<ProductionTransportKindV2>,
    pub endpoints: Vec<ProductionTransportEndpointV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProductionTransportKindV2 {
    Quic,
    Wss,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionTransportEndpointV2 {
    pub transport: ProductionTransportKindV2,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionNetworkPolicyV2 {
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

impl ProductionNetworkProfileV2 {
    pub fn validate(&self) -> Result<(), NetworkErrorCode> {
        if self.schema_version != PRODUCTION_NETWORK_SCHEMA_VERSION {
            return Err(NetworkErrorCode::UnsupportedSchemaVersion);
        }
        if self.carrier_auth_version != PRODUCTION_CARRIER_AUTH_VERSION
            || !valid_id(&self.profile_id)
            || self
                .identity_ref
                .strip_prefix("keychain:")
                .is_none_or(|identifier| !valid_id(identifier))
            || !valid_id(&self.site.id)
            || !valid_production_display_name(&self.site.display_name)
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }

        if !valid_production_control_plane(&self.control_plane) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }

        let Some(local_key) = decode_canonical_production_key(&self.tunnel.local_public_key) else {
            return Err(NetworkErrorCode::InvalidConfiguration);
        };
        let Some(peer_key) = decode_canonical_production_key(&self.tunnel.peer_public_key) else {
            return Err(NetworkErrorCode::InvalidConfiguration);
        };
        if local_key == peer_key || self.tunnel.keepalive_seconds == 0 {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }

        let Some((local_addresses, local_families)) = parse_production_host_addresses(&self.tunnel.local_addresses)
        else {
            return Err(NetworkErrorCode::InvalidConfiguration);
        };
        let Some((private_cidrs, private_families)) = parse_production_private_cidrs(&self.site.private_cidrs) else {
            return Err(NetworkErrorCode::InvalidConfiguration);
        };
        if local_families != private_families
            || prefix_sets_overlap(&local_addresses, &private_cidrs)
            || !valid_production_transports(&self.transports)
            || self.policy.connect_timeout_seconds == 0
            || self.policy.connect_timeout_seconds > 300
            || self.policy.health_interval_seconds == 0
            || self.policy.health_interval_seconds > 300
            || self.policy.fallback_threshold == 0
            || self.policy.fallback_threshold > 20
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProductionPrefix {
    address: IpAddr,
    bits: u8,
}

const PRODUCTION_X25519_LOW_ORDER_POINTS: [[u8; 32]; 7] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09,
        0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44,
        0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
];

const PRODUCTION_X25519_FIELD_PRIME: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

fn decode_canonical_production_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != 44 {
        return None;
    }
    let decoded = BASE64.decode(value).ok()?;
    let key: [u8; 32] = decoded.try_into().ok()?;
    if !canonical_production_x25519_coordinate(&key)
        || PRODUCTION_X25519_LOW_ORDER_POINTS.contains(&key)
        || BASE64.encode(key) != value
    {
        return None;
    }
    Some(key)
}

fn canonical_production_x25519_coordinate(key: &[u8; 32]) -> bool {
    for index in (0..key.len()).rev() {
        match key[index].cmp(&PRODUCTION_X25519_FIELD_PRIME[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

fn parse_production_host_addresses(values: &[String]) -> Option<(Vec<ProductionPrefix>, u8)> {
    if values.is_empty() || values.len() > 2 {
        return None;
    }
    let mut prefixes = Vec::with_capacity(values.len());
    let mut families = 0_u8;
    for value in values {
        let prefix = parse_canonical_production_prefix(value)?;
        let family = production_family(prefix.address);
        if prefix.bits != production_address_bits(prefix.address)
            || !production_prefix_is_private(prefix)
            || families & family != 0
        {
            return None;
        }
        families |= family;
        prefixes.push(prefix);
    }
    Some((prefixes, families))
}

fn parse_production_private_cidrs(values: &[String]) -> Option<(Vec<ProductionPrefix>, u8)> {
    if values.is_empty() || values.len() > PRODUCTION_MAX_PRIVATE_CIDRS {
        return None;
    }
    let mut text_bytes = 0;
    let mut prefixes = Vec::with_capacity(values.len());
    let mut families = 0_u8;
    for value in values {
        text_bytes += value.len();
        if value.len() > 64 || text_bytes > PRODUCTION_MAX_PRIVATE_CIDR_TEXT_BYTES {
            return None;
        }
        let prefix = parse_canonical_production_prefix(value)?;
        if prefix.bits == 0
            || !production_prefix_is_network(prefix)
            || !production_prefix_is_private(prefix)
            || prefixes
                .iter()
                .any(|existing| production_prefixes_overlap(*existing, prefix))
        {
            return None;
        }
        families |= production_family(prefix.address);
        prefixes.push(prefix);
    }
    Some((prefixes, families))
}

fn parse_canonical_production_prefix(value: &str) -> Option<ProductionPrefix> {
    let (raw_address, raw_bits) = value.rsplit_once('/')?;
    let address = raw_address.parse::<IpAddr>().ok()?;
    let bits = raw_bits.parse::<u8>().ok()?;
    if raw_address != address.to_string() || raw_bits != bits.to_string() || bits > production_address_bits(address) {
        return None;
    }
    Some(ProductionPrefix { address, bits })
}

fn production_prefix_is_private(prefix: ProductionPrefix) -> bool {
    match prefix.address {
        IpAddr::V4(address) => {
            let address = u32::from(address);
            (prefix.bits >= 8 && address & 0xff00_0000 == 0x0a00_0000)
                || (prefix.bits >= 12 && address & 0xfff0_0000 == 0xac10_0000)
                || (prefix.bits >= 16 && address & 0xffff_0000 == 0xc0a8_0000)
        }
        IpAddr::V6(address) => prefix.bits >= 7 && u128::from(address) >> 121 == 0x7e,
    }
}

fn production_prefix_is_network(prefix: ProductionPrefix) -> bool {
    production_masked_value(prefix.address, prefix.bits) == production_address_value(prefix.address)
}

fn production_prefixes_overlap(left: ProductionPrefix, right: ProductionPrefix) -> bool {
    production_same_family(left.address, right.address)
        && production_masked_value(left.address, left.bits.min(right.bits))
            == production_masked_value(right.address, left.bits.min(right.bits))
}

fn prefix_sets_overlap(left: &[ProductionPrefix], right: &[ProductionPrefix]) -> bool {
    left.iter()
        .any(|left| right.iter().any(|right| production_prefixes_overlap(*left, *right)))
}

fn production_masked_value(address: IpAddr, bits: u8) -> u128 {
    let width = production_address_bits(address);
    let value = production_address_value(address);
    if bits == 0 {
        0
    } else {
        value & (u128::MAX << (width - bits))
    }
}

fn production_address_value(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u32::from(address) as u128,
        IpAddr::V6(address) => u128::from(address),
    }
}

const fn production_address_bits(address: IpAddr) -> u8 {
    if address.is_ipv4() { 32 } else { 128 }
}

const fn production_family(address: IpAddr) -> u8 {
    if address.is_ipv4() { 1 } else { 2 }
}

const fn production_same_family(left: IpAddr, right: IpAddr) -> bool {
    left.is_ipv4() == right.is_ipv4()
}

fn valid_production_transports(transports: &ProductionTransportConfigV2) -> bool {
    const EXPECTED: [ProductionTransportKindV2; 3] = [
        ProductionTransportKindV2::Quic,
        ProductionTransportKindV2::Wss,
        ProductionTransportKindV2::Tcp,
    ];
    if transports.primary != ProductionTransportKindV2::Quic
        || transports.fallbacks != EXPECTED[1..]
        || transports.endpoints.len() != EXPECTED.len()
    {
        return false;
    }

    let mut expected_host = None;
    let mut ports = HashSet::new();
    for (endpoint, expected_transport) in transports.endpoints.iter().zip(EXPECTED) {
        if endpoint.transport != expected_transport {
            return false;
        }
        let Some((host, port)) = parse_production_endpoint(endpoint.transport, &endpoint.url) else {
            return false;
        };
        if expected_host.is_some_and(|expected| expected != host) || !ports.insert(port) {
            return false;
        }
        expected_host = Some(host);
    }
    true
}

fn parse_production_endpoint(transport: ProductionTransportKindV2, raw: &str) -> Option<(&str, u16)> {
    let (scheme, path) = match transport {
        ProductionTransportKindV2::Quic => ("https", ""),
        ProductionTransportKindV2::Wss => ("wss", PRODUCTION_WSS_PATH),
        ProductionTransportKindV2::Tcp => ("tcp", ""),
    };
    if raw
        .chars()
        .any(|character| matches!(character, '%' | '\\' | '?' | '#') || character.is_whitespace())
        || !raw.starts_with(&format!("{scheme}://"))
        || !raw.ends_with(path)
    {
        return None;
    }
    let authority = raw.strip_prefix(&format!("{scheme}://"))?.strip_suffix(path)?;
    if authority
        .chars()
        .any(|character| matches!(character, '/' | '@' | '[' | ']'))
    {
        return None;
    }
    let (host, raw_port) = authority.rsplit_once(':')?;
    let port = raw_port.parse::<u16>().ok()?;
    if port < 1024 || raw_port != port.to_string() || !valid_production_server_name(host) {
        return None;
    }

    let parsed = Url::parse(raw).ok()?;
    if parsed.scheme() != scheme
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host_str() != Some(host)
        || parsed.port_or_known_default() != Some(port)
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (transport == ProductionTransportKindV2::Wss && parsed.path() != PRODUCTION_WSS_PATH)
        || (transport == ProductionTransportKindV2::Quic && parsed.path() != "/")
        || (transport == ProductionTransportKindV2::Tcp && !parsed.path().is_empty())
    {
        return None;
    }
    Some((host, port))
}

fn valid_production_display_name(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    let mut count = 1;
    let mut last = first;
    for character in characters {
        count += 1;
        if count > 128 {
            return false;
        }
        last = character;
    }
    !production_trim_space(first) && !production_trim_space(last)
}

fn valid_production_control_plane(value: &str) -> bool {
    // Keep this lexical preflight aligned with net/url's canonical String
    // contract. `Url::as_str()` cannot be used for equality here because the
    // Rust URL implementation lowercases hosts, removes an explicit :443 and
    // resolves dot segments that Go deliberately preserves.
    if value.is_empty()
        || value.len() > 2048
        || !value.is_ascii()
        || value
            .chars()
            .any(|character| matches!(character, '%' | '\\' | '?' | '#') || character.is_ascii_control())
    {
        return false;
    }
    let Some(remainder) = value.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, None), |(authority, path)| (authority, Some(path)));
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains(['[', ']'])
        || !authority.chars().all(production_control_authority_character)
        || path.is_some_and(|path| !path.chars().all(production_control_path_character))
    {
        return false;
    }
    let (host, raw_port) = match authority.rsplit_once(':') {
        Some((host, raw_port)) if !host.contains(':') => (host, Some(raw_port)),
        Some(_) => return false,
        None => (authority, None),
    };
    if !valid_production_server_name(host)
        || !host
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().any(|octet| octet.is_ascii_lowercase()))
    {
        return false;
    }
    raw_port.is_none_or(|raw_port| {
        raw_port
            .parse::<u16>()
            .is_ok_and(|port| port > 0 && raw_port == port.to_string())
    })
}

const fn production_control_authority_character(character: char) -> bool {
    matches!(
        character,
        'a'..='z'
            | 'A'..='Z'
            | '0'..='9'
            | '-'
            | '.'
            | '_'
            | '~'
            | '!'
            | '$'
            | '&'
            | '\''
            | '('
            | ')'
            | '*'
            | '+'
            | ','
            | ';'
            | '='
            | ':'
            | '['
            | ']'
    )
}

const fn production_control_path_character(character: char) -> bool {
    (production_control_authority_character(character) && !matches!(character, '[' | ']'))
        || character == '/'
        || character == '@'
}

const fn production_trim_space(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000d}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn valid_production_server_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value != value.to_ascii_lowercase()
        || value.ends_with('.')
        || value.parse::<IpAddr>().is_ok()
        || value
            .chars()
            .all(|character| character == '.' || character.is_ascii_digit())
    {
        return false;
    }
    let mut labels = value.split('.');
    if labels.clone().count() < 2 {
        return false;
    }
    labels.all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-')
    })
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
    const VALID_PRODUCTION_PROFILE_V2: &str =
        include_str!("../../../schemas/fixtures/network-production-v2.valid.json");

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

    fn valid_production_profile_v2() -> anyhow::Result<ProductionNetworkProfileV2> {
        Ok(serde_json::from_str(VALID_PRODUCTION_PROFILE_V2)?)
    }

    fn assert_invalid_production_profile(profile: &ProductionNetworkProfileV2) {
        assert_eq!(profile.validate(), Err(NetworkErrorCode::InvalidConfiguration));
    }

    #[test]
    fn production_v2_fixture_round_trips_without_enabling_the_runtime() -> anyhow::Result<()> {
        let profile = valid_production_profile_v2()?;
        profile.validate().map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let encoded = serde_json::to_string(&profile)?;
        let decoded: ProductionNetworkProfileV2 = serde_json::from_str(&encoded)?;
        assert_eq!(profile, decoded);
        assert_eq!(PRODUCTION_NETWORK_SCHEMA_VERSION, 2);
        assert_eq!(PRODUCTION_CARRIER_AUTH_VERSION, 1);
        assert_eq!(PRODUCTION_QUIC_ALPN, "kyclash-network/1");
        assert_eq!(PRODUCTION_WSS_PATH, "/kynp");
        assert_eq!(PRODUCTION_TUNNEL_MTU, 1420);

        let formatted = format!("{profile:?}");
        assert!(!formatted.contains(&profile.tunnel.local_public_key));
        assert!(!formatted.contains(&profile.tunnel.peer_public_key));
        assert!(!formatted.contains("peer.example.invalid"));
        Ok(())
    }

    #[test]
    fn production_v2_rejects_v1_unknown_versions_and_missing_pair_fields() -> anyhow::Result<()> {
        assert!(serde_json::from_str::<ProductionNetworkProfileV2>(VALID_PROFILE).is_err());

        let mut profile = valid_production_profile_v2()?;
        profile.schema_version = 1;
        assert_eq!(profile.validate(), Err(NetworkErrorCode::UnsupportedSchemaVersion));
        profile.schema_version = 3;
        assert_eq!(profile.validate(), Err(NetworkErrorCode::UnsupportedSchemaVersion));

        let mut profile = valid_production_profile_v2()?;
        profile.carrier_auth_version = 0;
        assert_invalid_production_profile(&profile);
        profile.carrier_auth_version = 2;
        assert_invalid_production_profile(&profile);

        let mut value: serde_json::Value = serde_json::from_str(VALID_PRODUCTION_PROFILE_V2)?;
        value
            .as_object_mut()
            .expect("profile object")
            .remove("carrier_auth_version");
        assert!(serde_json::from_value::<ProductionNetworkProfileV2>(value).is_err());

        let mut value: serde_json::Value = serde_json::from_str(VALID_PRODUCTION_PROFILE_V2)?;
        value["tunnel"]
            .as_object_mut()
            .expect("tunnel object")
            .remove("local_public_key");
        assert!(serde_json::from_value::<ProductionNetworkProfileV2>(value).is_err());

        let mut value: serde_json::Value = serde_json::from_str(VALID_PRODUCTION_PROFILE_V2)?;
        value["tunnel"]
            .as_object_mut()
            .expect("tunnel object")
            .remove("peer_public_key");
        assert!(serde_json::from_value::<ProductionNetworkProfileV2>(value).is_err());
        Ok(())
    }

    #[test]
    fn production_v2_keys_are_nonzero_canonical_and_distinct() -> anyhow::Result<()> {
        let profile = valid_production_profile_v2()?;
        assert!(decode_canonical_production_key(&profile.tunnel.local_public_key).is_some());
        assert!(decode_canonical_production_key(&profile.tunnel.peer_public_key).is_some());

        let mut low_order_u_one = [0_u8; 32];
        low_order_u_one[0] = 1;
        let low_order_toolchain = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09,
            0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
        ];
        let mut high_bit_alias = [0x22_u8; 32];
        high_bit_alias[31] |= 0x80;
        let mut field_alias = [0xff_u8; 32];
        field_alias[0] = 0xf6;
        field_alias[31] = 0x7f;
        for invalid in [
            profile.tunnel.local_public_key.trim_end_matches('=').to_owned(),
            format!("{}=", profile.tunnel.local_public_key),
            format!("{}\n", profile.tunnel.local_public_key),
            format!("{}\r", profile.tunnel.local_public_key),
            BASE64.encode([0_u8; 32]),
            BASE64.encode(low_order_u_one),
            BASE64.encode(low_order_toolchain),
            BASE64.encode(high_bit_alias),
            BASE64.encode(field_alias),
        ] {
            let mut invalid_local = profile.clone();
            invalid_local.tunnel.local_public_key = invalid.clone();
            assert_invalid_production_profile(&invalid_local);

            let mut invalid_peer = profile.clone();
            invalid_peer.tunnel.peer_public_key = invalid;
            assert_invalid_production_profile(&invalid_peer);
        }

        let mut noncanonical_padding = profile.tunnel.local_public_key.clone().into_bytes();
        let trailing_sextet = noncanonical_padding.len() - 2;
        noncanonical_padding[trailing_sextet] = match noncanonical_padding[trailing_sextet] {
            b'A' => b'B',
            b'E' => b'F',
            b'I' => b'J',
            b'M' => b'N',
            b'Q' => b'R',
            b'U' => b'V',
            b'Y' => b'Z',
            b'c' => b'd',
            b'g' => b'h',
            b'k' => b'l',
            b'o' => b'p',
            b's' => b't',
            b'w' => b'x',
            b'0' => b'1',
            b'4' => b'5',
            b'8' => b'9',
            value => panic!("canonical 32-byte Base64 has unexpected trailing sextet {value}"),
        };
        let mut candidate = profile.clone();
        candidate.tunnel.local_public_key = String::from_utf8(noncanonical_padding)?;
        assert_invalid_production_profile(&candidate);

        let mut same_keys = profile.clone();
        same_keys.tunnel.local_public_key = same_keys.tunnel.peer_public_key.clone();
        assert_invalid_production_profile(&same_keys);
        Ok(())
    }

    #[test]
    fn production_v2_requires_canonical_host_addresses_and_bounded_private_cidrs() -> anyhow::Result<()> {
        let profile = valid_production_profile_v2()?;

        for local_addresses in [
            vec!["10.127.0.2/24".into(), "fd00:127::2/128".into()],
            vec!["10.127.000.2/32".into(), "fd00:127::2/128".into()],
            vec!["8.8.8.8/32".into(), "fd00:127::2/128".into()],
            vec!["10.127.0.2/32".into(), "10.127.0.3/32".into()],
        ] {
            let mut candidate = profile.clone();
            candidate.tunnel.local_addresses = local_addresses;
            assert_invalid_production_profile(&candidate);
        }

        for private_cidrs in [
            vec!["10.127.1.1/16".into(), "fd00:127::/48".into()],
            vec!["8.8.8.0/24".into(), "fd00:127::/48".into()],
            vec!["10.127.0.0/16".into(), "10.127.1.0/24".into(), "fd00:127::/48".into()],
            vec!["10.127.0.0/16".into(), "10.127.0.0/16".into(), "fd00:127::/48".into()],
            vec!["10.127.0.0/16".into()],
        ] {
            let mut candidate = profile.clone();
            candidate.site.private_cidrs = private_cidrs;
            assert_invalid_production_profile(&candidate);
        }

        let mut too_many = profile;
        too_many.site.private_cidrs = (0..=PRODUCTION_MAX_PRIVATE_CIDRS)
            .map(|index| format!("10.{index}.0.0/16"))
            .collect();
        assert_invalid_production_profile(&too_many);
        Ok(())
    }

    #[test]
    fn production_v2_control_plane_matches_the_go_canonical_corpus() -> anyhow::Result<()> {
        let profile = valid_production_profile_v2()?;

        for accepted in [
            "https://control.example.invalid",
            "https://control.example.invalid:443",
            "https://control.example.invalid/",
            "https://control.example.invalid:8443/api/v2",
            "https://control.example.invalid/a/../b",
        ] {
            let mut candidate = profile.clone();
            candidate.control_plane = accepted.into();
            candidate.validate().map_err(|error| anyhow::anyhow!("{error:?}"))?;
        }

        let oversized_host = format!("https://{}.invalid", "a".repeat(2050));
        assert!(oversized_host.len() > 2048);
        for rejected in [
            "".to_owned(),
            "http://control.example.invalid".into(),
            "HTTPS://control.example.invalid".into(),
            oversized_host,
            "https://user@control.example.invalid".into(),
            "https://user:password@control.example.invalid".into(),
            "https://@control.example.invalid".into(),
            "https://control.example.invalid?token=forbidden".into(),
            "https://control.example.invalid?".into(),
            "https://control.example.invalid#forbidden".into(),
            "https://control.example.invalid#".into(),
            "https://%63ontrol.example.invalid".into(),
            "https://control.example.invalid/%61pi".into(),
            "https://control.example.invalid\\api".into(),
            "https://例子.invalid".into(),
            "https://control.example.invalid/界".into(),
            "https://control.example.invalid/a b".into(),
            "https://control.example.invalid/<api>".into(),
            "https://control.example.invalid:65536".into(),
            "https://:443".into(),
            "https://[fe80::1%25en0]/".into(),
            "https://999.999.999.999".into(),
            "https://256.1.1.1".into(),
            "https://1..2".into(),
            "https://127.1".into(),
            "https://Control.Example.Invalid".into(),
            "https://control.example.999".into(),
            "https://control.example.invalid:0".into(),
            "https://control.example.invalid:0443".into(),
        ] {
            let mut candidate = profile.clone();
            candidate.control_plane = rejected;
            assert_invalid_production_profile(&candidate);
        }
        Ok(())
    }

    #[test]
    fn production_v2_display_name_uses_the_locked_unicode_scalar_boundary() -> anyhow::Result<()> {
        let profile = valid_production_profile_v2()?;

        for accepted in [
            "A".into(),
            "内\u{0085}部".into(),
            "\u{feff}accepted".into(),
            "accepted\u{feff}".into(),
            "界".repeat(128),
        ] {
            let mut candidate = profile.clone();
            candidate.site.display_name = accepted;
            candidate.validate().map_err(|error| anyhow::anyhow!("{error:?}"))?;
        }

        for rejected in [
            "".into(),
            " leading".into(),
            "trailing ".into(),
            "\u{0085}leading".into(),
            "trailing\u{0085}".into(),
            "界".repeat(129),
        ] {
            let mut candidate = profile.clone();
            candidate.site.display_name = rejected;
            assert_invalid_production_profile(&candidate);
        }
        Ok(())
    }

    #[test]
    fn production_v2_json_rejects_lone_surrogates_and_accepts_a_valid_emoji_pair() -> anyhow::Result<()> {
        let lone_surrogate = VALID_PRODUCTION_PROFILE_V2.replace("KyClash production pair fixture", r"\ud800");
        assert!(serde_json::from_str::<ProductionNetworkProfileV2>(&lone_surrogate).is_err());

        let emoji_pair = VALID_PRODUCTION_PROFILE_V2.replace("KyClash production pair fixture", r"\ud83d\ude00");
        let profile: ProductionNetworkProfileV2 = serde_json::from_str(&emoji_pair)?;
        assert_eq!(profile.site.display_name, "😀");
        profile.validate().map_err(|error| anyhow::anyhow!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn production_v2_requires_exact_transport_order_host_ports_and_path() -> anyhow::Result<()> {
        let profile = valid_production_profile_v2()?;

        let mut reversed_fallbacks = profile.clone();
        reversed_fallbacks.transports.fallbacks.swap(0, 1);
        assert_invalid_production_profile(&reversed_fallbacks);

        let mut reversed_endpoints = profile.clone();
        reversed_endpoints.transports.endpoints.swap(0, 1);
        assert_invalid_production_profile(&reversed_endpoints);

        for (index, invalid_url) in [
            (0, "https://other.example.invalid:2443"),
            (0, "https://PEER.example.invalid:2443"),
            (0, "https://127.0.0.1:2443"),
            (0, "https://peer.example.invalid"),
            (0, "https://peer.example.invalid:443"),
            (0, "https://peer.example.invalid:02443"),
            (0, "https://user@peer.example.invalid:2443"),
            (0, "https://peer.example.invalid:2443?token=forbidden"),
            (0, "https://peer.example.invalid:2443#forbidden"),
            (0, "https://%70eer.example.invalid:2443"),
            (1, "wss://peer.example.invalid:2444/wrong"),
            (1, "wss://peer.example.invalid:2444/k%79np"),
            (1, "wss://peer.example.invalid:2444/kynp/"),
            (2, "tcp://peer.example.invalid:2444"),
            (2, "tcp://peer.example.invalid:2445/"),
        ] {
            let mut candidate = profile.clone();
            candidate.transports.endpoints[index].url = invalid_url.into();
            assert_invalid_production_profile(&candidate);
        }
        Ok(())
    }

    #[test]
    fn production_v2_strict_nested_serde_rejects_unknown_fields() -> anyhow::Result<()> {
        let mut value: serde_json::Value = serde_json::from_str(VALID_PRODUCTION_PROFILE_V2)?;
        value["tunnel"]["private_key"] = serde_json::Value::String("forbidden".into());
        assert!(serde_json::from_value::<ProductionNetworkProfileV2>(value).is_err());
        Ok(())
    }
}
