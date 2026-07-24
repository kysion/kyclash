export const NETWORK_SCHEMA_VERSION = 1 as const
export const NETWORK_IPC_PROTOCOL_VERSION = 2 as const

export type TransportKind = 'quic' | 'wss' | 'tcp'

export interface NetworkProfile {
  schema_version: typeof NETWORK_SCHEMA_VERSION
  profile_id: string
  control_plane: string
  identity_ref: string
  site: {
    id: string
    display_name: string
    private_cidrs: string[]
  }
  tunnel: {
    local_addresses: string[]
    peer_public_key: string
    keepalive_seconds: number
  }
  transports: {
    primary: 'quic'
    fallbacks: Exclude<TransportKind, 'quic'>[]
    endpoints: Array<{
      transport: TransportKind
      url: string
    }>
  }
  policy: {
    connect_timeout_seconds: number
    health_interval_seconds: number
    fallback_threshold: number
  }
}

export type NetworkState =
  | 'disconnected'
  | 'authenticating'
  | 'fetching_config'
  | 'preparing_tunnel'
  | 'connecting_primary'
  | 'connected_primary'
  | 'degraded_fallback'
  | 'reconnecting'
  | 'disconnecting'
  | 'error'

export type NetworkErrorCode =
  | 'unsupported_schema_version'
  | 'unsupported_protocol_version'
  | 'invalid_configuration'
  | 'authentication_failed'
  | 'permission_denied'
  | 'policy_signature_invalid'
  | 'route_discovery_failed'
  | 'route_conflict'
  | 'route_journal_corrupted'
  | 'route_journal_unavailable'
  | 'route_rollback_failed'
  | 'tunnel_start_failed'
  | 'primary_transport_unavailable'
  | 'fallback_transport_unavailable'
  | 'operation_cancelled'
  | 'operation_timed_out'
  | 'sidecar_unavailable'
  | 'invalid_state_transition'

export interface NetworkStatus {
  state: NetworkState
  active_profile_id: string | null
  active_transport: TransportKind | null
  last_error: NetworkErrorCode | null
}

export interface NetworkingDevStatus {
  network_state: NetworkState
  sidecar_state: 'stopped' | 'starting' | 'running' | 'backoff' | 'crash_loop'
  site_id: string
  site_display_name: string
  private_routes: string[]
  active_transport: TransportKind | null
  health: {
    latency_ms: number
    jitter_ms: number
    packet_loss_percent: number
  } | null
  last_error: NetworkErrorCode | null
}

export interface NetworkingUserspaceLabTransportCheck {
  transport: TransportKind
  reachable: boolean
  latency_ms: number
  jitter_ms: number
  loss_percent: number
  private_reachable: boolean
  mihomo_coexisting: boolean
}

/**
 * Status returned only by an explicit no-sign lab App. `vm_utun_lab` is the
 * route-free fixture; `vm_network_lab` is the disposable VirtualMac fixture
 * whose root harness owns the private route and Mihomo coexistence proof. Both
 * remain separate from production helpers and credentials.
 */
export interface NetworkingUserspaceLabStatus {
  runtime_mode: 'userspace_lab' | 'vm_utun_lab' | 'vm_network_lab'
  tunnel_kind: 'userspace_netstack' | 'darwin_utun'
  network_state: NetworkState
  sidecar_state: 'stopped' | 'starting' | 'running' | 'backoff' | 'crash_loop'
  site_id: string
  site_display_name: string
  private_routes: string[]
  routes_installed: boolean
  private_reachable: boolean
  mihomo_coexisting: boolean
  tunnel_interface: string | null
  active_transport: TransportKind | null
  health: {
    reachable: boolean
    latency_ms: number
    jitter_ms: number
    loss_percent: number
  } | null
  transport_checks: NetworkingUserspaceLabTransportCheck[]
  last_error: NetworkErrorCode | null
}

export type NetworkingExternalPeerLabPhase =
  | 'disconnected'
  | 'waiting_for_validated_peer'
  | 'ready'
  | 'preparing_mihomo'
  | 'preparing_utun'
  | 'connecting_quic'
  | 'connected_quic'
  | 'switching_to_wss'
  | 'connected_wss'
  | 'switching_to_tcp'
  | 'connected_tcp'
  | 'peer_lost_cleaning_up'
  | 'disconnecting'
  | 'failed'

export type NetworkingExternalPeerImpairmentReason =
  'carrier_unhealthy_observed'

export interface NetworkingExternalPeerTransportCheck {
  transport: TransportKind
  carrier_healthy: boolean
  private_echo_healthy: boolean
  mihomo_coexisting: boolean
  overlay_ssh_verified: boolean
  system_ssh_verified: boolean
  latency_ms: number
  jitter_ms: number
  loss_percent: number
  impairment_reason: NetworkingExternalPeerImpairmentReason | null
}

/**
 * Redacted status from the default-off two-VirtualMac lab. It deliberately
 * has no endpoint, port, descriptor, certificate, key, hash, PID, path, or
 * free-form backend message.
 */
export interface NetworkingExternalPeerLabStatus {
  runtime_mode: 'vm_external_peer_lab'
  tunnel_kind: 'darwin_utun'
  phase: NetworkingExternalPeerLabPhase
  network_state: NetworkState
  sidecar_state: 'stopped' | 'starting' | 'running' | 'backoff' | 'crash_loop'
  site_id: 'lab-vm-external-peer'
  site_display_name: string
  peer_vm: 'kyclash-macos-lab-peer'
  non_production: true
  lan_forwarding_enabled: false
  tunnel_interface: string | null
  private_routes: string[]
  routes_installed: boolean
  mihomo_interface: 'utun4094' | null
  mihomo_route: '10.88.0.0/24' | null
  active_transport: TransportKind | null
  health: {
    reachable: boolean
    latency_ms: number
    jitter_ms: number
    loss_percent: number
  } | null
  private_echo_healthy: boolean
  mihomo_coexisting: boolean
  overlay_ssh_verified: boolean
  system_ssh_verified: boolean
  transport_checks: NetworkingExternalPeerTransportCheck[]
  last_error: NetworkErrorCode | null
}

export interface ProductionSiteSummary {
  id: string
  display_name: string
  private_route_count: number
}

export interface ProductionPolicyVariantSummary {
  catalog_id: 'base' | 'base+.30' | 'base+.31' | 'base+both'
  display_name: string
  revision: number
  profile_sha256: string
  private_cidrs: string[]
}

export interface ProductionPolicyCatalogView {
  schema_version: 1
  selected_catalog_id: ProductionPolicyVariantSummary['catalog_id'] | null
  variants: ProductionPolicyVariantSummary[]
}

export interface ProductionNetworkStatus {
  state: NetworkState
  sidecar_state: 'stopped' | 'starting' | 'running' | 'backoff' | 'crash_loop'
  site: ProductionSiteSummary
  active_transport: TransportKind | null
  health: {
    reachable: boolean
    latency_ms: number
    jitter_ms: number
    loss_percent: number
  } | null
  operation_id: string | null
  last_error: NetworkErrorCode | null
}

export interface ProductionNetworkDiagnostic {
  sequence: number
  operation_id: string | null
  kind:
    | 'started'
    | 'request_completed'
    | 'cancelled'
    | 'timed_out'
    | 'restarting'
    | 'crash_loop'
    | 'stopped'
    | 'failed'
  error: NetworkErrorCode | null
}

export type RouteHelperRegistrationStatus =
  | 'not_registered'
  | 'enabled'
  | 'requires_approval'
  | 'not_found'
  | 'unknown'

/**
 * Registration state for the two fixed privileged services required by the
 * production networking composition. `ready` is authoritative for Connect;
 * enabling only one service never grants partial production authority.
 */
export interface PrivilegedNetworkingServicesStatus {
  route_helper: RouteHelperRegistrationStatus
  tunnel_broker: RouteHelperRegistrationStatus
  ready: boolean
}

export interface NetworkStateEvent {
  /** Monotonically increasing within one sidecar process lifetime. */
  sequence: number
  operation_id: string
  state: NetworkState
  reason: NetworkErrorCode | null
}

export type NetworkIpcRequestPayload =
  | { type: 'get_status' }
  | { type: 'apply_profile'; data: NetworkProfile }
  | { type: 'prepare_tunnel' }
  | { type: 'stop_tunnel' }
  | { type: 'connect_transport'; data: { transport: TransportKind } }
  | { type: 'disconnect_transport' }
  | { type: 'sample_health' }
  | { type: 'connect' }
  | { type: 'disconnect' }
  | { type: 'cancel'; data: { target_request_id: string } }

export interface NetworkIpcRequest {
  protocol_version: typeof NETWORK_IPC_PROTOCOL_VERSION
  request_id: string
  payload: NetworkIpcRequestPayload
}

export type NetworkIpcResponsePayload =
  | { type: 'acknowledged' }
  | { type: 'cancel_accepted'; data: { target_request_id: string } }
  | { type: 'status'; data: NetworkStatus }
  | {
      type: 'health'
      data: {
        reachable: boolean
        latency_ms: number
        jitter_ms: number
        loss_percent: number
      }
    }
  | {
      type: 'tunnel_prepared'
      data: {
        interface_name: string
        mtu: 1420
        has_ipv4: boolean
        has_ipv6: boolean
        instance_id: string
        operation_id: string
      }
    }

export interface NetworkIpcError {
  code: NetworkErrorCode
  message: string
  retryable: boolean
}

export interface NetworkIpcResponse {
  protocol_version: typeof NETWORK_IPC_PROTOCOL_VERSION
  request_id: string
  result: { Ok: NetworkIpcResponsePayload } | { Err: NetworkIpcError }
}

export function assertNetworkProfileV1(
  value: unknown,
): asserts value is NetworkProfile {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('schema_version' in value) ||
    value.schema_version !== NETWORK_SCHEMA_VERSION
  ) {
    throw new Error('Unsupported KyClash network profile schema')
  }
}
