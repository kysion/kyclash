export const NETWORK_SCHEMA_VERSION = 1 as const
export const NETWORK_IPC_PROTOCOL_VERSION = 1 as const

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

export interface ProductionNetworkStatus {
  state: NetworkState
  sidecar_state: 'stopped' | 'starting' | 'running' | 'backoff' | 'crash_loop'
  site: {
    id: string
    display_name: string
    private_route_count: number
  }
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
  | { type: 'connect' }
  | { type: 'disconnect' }
  | { type: 'cancel'; data: { operation_id: string } }

export interface NetworkIpcRequest {
  protocol_version: typeof NETWORK_IPC_PROTOCOL_VERSION
  request_id: string
  payload: NetworkIpcRequestPayload
}

export type NetworkIpcResponsePayload =
  | { type: 'acknowledged' }
  | { type: 'status'; data: NetworkStatus }
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
