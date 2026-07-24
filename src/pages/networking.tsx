import LinkOffRounded from '@mui/icons-material/LinkOffRounded'
import PowerSettingsNewRounded from '@mui/icons-material/PowerSettingsNewRounded'
import RefreshRounded from '@mui/icons-material/RefreshRounded'
import StopCircleRounded from '@mui/icons-material/StopCircleRounded'
import {
  Alert,
  Button,
  Card,
  CardContent,
  Chip,
  FormControl,
  FormHelperText,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Typography,
} from '@mui/material'
import { useCallback, useEffect, useState } from 'react'

import { BasePage } from '@/components/base'
import {
  cancelNetworkingOperation,
  connectNetworking,
  disconnectNetworking,
  getNetworkingDiagnostics,
  getNetworkingStatus,
  getPrivilegedNetworkingServicesStatus,
  initializeNetworking,
  listNetworkingPolicyVariants,
  listNetworkingSites,
  openRouteHelperSystemSettings,
  registerPrivilegedNetworkingServices,
  selectNetworkingPolicyVariant,
  unregisterPrivilegedNetworkingServices,
} from '@/services/cmds'
import type {
  NetworkErrorCode,
  PrivilegedNetworkingServicesStatus,
  ProductionNetworkStatus,
  ProductionPolicyCatalogView,
  ProductionSiteSummary,
} from '@/types/networking'

const pollingStates = new Set([
  'authenticating',
  'fetching_config',
  'preparing_tunnel',
  'connecting_primary',
  'connected_primary',
  'degraded_fallback',
  'reconnecting',
  'disconnecting',
])

const cancellableStates = new Set([
  'authenticating',
  'fetching_config',
  'preparing_tunnel',
  'connecting_primary',
  'reconnecting',
  'disconnecting',
])

const stateLabel: Record<ProductionNetworkStatus['state'], string> = {
  disconnected: 'Disconnected',
  authenticating: 'Authenticating policy and device',
  fetching_config: 'Validating signed configuration',
  preparing_tunnel: 'Preparing encrypted tunnel',
  connecting_primary: 'Connecting primary transport',
  connected_primary: 'Connected over QUIC',
  degraded_fallback: 'Connected over fallback transport',
  reconnecting: 'Recovering connection',
  disconnecting: 'Disconnecting and rolling back routes',
  error: 'Connection failed',
}

const networkErrorLabel: Record<NetworkErrorCode, string> = {
  unsupported_schema_version: 'The network policy schema is not supported.',
  unsupported_protocol_version:
    'The bundled network sidecar protocol is not supported.',
  invalid_configuration:
    'Production networking is not initialized with a valid signed policy.',
  authentication_failed: 'Network authentication failed.',
  permission_denied:
    'macOS denied the narrowly scoped networking service; no route was changed.',
  policy_signature_invalid: 'The signed network policy could not be verified.',
  route_discovery_failed: 'Private-route discovery failed.',
  route_conflict:
    'A private route is already owned by another interface; KyClash refused to replace it.',
  route_journal_corrupted:
    'The private-route recovery journal is corrupted; KyClash failed closed.',
  route_journal_unavailable:
    'The private-route recovery journal is unavailable; KyClash failed closed.',
  route_rollback_failed:
    'Private-route rollback did not complete; reconnect remains disabled.',
  tunnel_start_failed: 'The encrypted tunnel could not be created.',
  primary_transport_unavailable: 'The QUIC transport is unavailable.',
  fallback_transport_unavailable:
    'The WSS and TCP fallback transports are unavailable.',
  operation_cancelled: 'The networking operation was cancelled.',
  operation_timed_out: 'The networking operation timed out.',
  sidecar_unavailable:
    'The trusted production sidecar could not be started; no real utun or private route is active.',
  invalid_state_transition:
    'The requested action is not valid in the current networking state.',
}

const formatNetworkError = (reason: unknown) => {
  const raw = reason instanceof Error ? reason.message : String(reason)
  let code = raw
  try {
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed === 'string') code = parsed
  } catch {
    // Non-JSON command errors are displayed without inventing a typed cause.
  }
  return Object.hasOwn(networkErrorLabel, code)
    ? networkErrorLabel[code as NetworkErrorCode]
    : raw
}

const NetworkingPage = () => {
  const [status, setStatus] = useState<ProductionNetworkStatus>()
  const [sites, setSites] = useState<ProductionSiteSummary[]>([])
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [diagnosticCount, setDiagnosticCount] = useState(0)
  const [servicesStatus, setServicesStatus] =
    useState<PrivilegedNetworkingServicesStatus>()
  const [policyCatalog, setPolicyCatalog] =
    useState<ProductionPolicyCatalogView>()

  const run = useCallback(
    async (action: () => Promise<ProductionNetworkStatus>) => {
      setBusy(true)
      setError(undefined)
      try {
        setStatus(await action())
      } catch (reason) {
        setError(formatNetworkError(reason))
        try {
          setStatus(await getNetworkingStatus())
        } catch {
          // A missing configured service is already represented by the first error.
        }
      } finally {
        setBusy(false)
      }
    },
    [],
  )

  const refresh = useCallback(() => run(getNetworkingStatus), [run])
  const refreshServices = useCallback(async () => {
    try {
      setServicesStatus(await getPrivilegedNetworkingServicesStatus())
    } catch (reason) {
      setError(formatNetworkError(reason))
      setServicesStatus(undefined)
    }
  }, [])
  // Initialization verifies only the signed app-owned policy and registers a
  // deferred factory. It does not start the sidecar or touch Keychain/XPC;
  // those remain behind the explicit Connect action.
  useEffect(
    () =>
      void run(async () => {
        const initialized = await initializeNetworking()
        setPolicyCatalog(await listNetworkingPolicyVariants())
        setSites(await listNetworkingSites())
        return initialized
      }),
    [run],
  )
  useEffect(() => void refreshServices(), [refreshServices])

  useEffect(() => {
    if (!status || !pollingStates.has(status.state)) return
    const timer = window.setInterval(() => {
      void getNetworkingStatus()
        .then(setStatus)
        .catch((reason: unknown) => setError(formatNetworkError(reason)))
    }, 500)
    return () => window.clearInterval(timer)
  }, [status])

  const isTransitioning = status ? cancellableStates.has(status.state) : false
  const selectedVariant = policyCatalog?.variants.find(
    (variant) => variant.catalog_id === policyCatalog.selected_catalog_id,
  )
  return (
    <BasePage
      title="KyClash Network"
      header={
        <Button
          disabled={busy}
          onClick={() => void refresh()}
          startIcon={<RefreshRounded />}
        >
          Refresh
        </Button>
      }
    >
      <Stack spacing={2}>
        {error && <Alert severity="error">{error}</Alert>}
        {status?.last_error && (
          <Alert severity="error">{networkErrorLabel[status.last_error]}</Alert>
        )}
        <Card variant="outlined">
          <CardContent>
            <Stack spacing={1.5}>
              <Typography variant="h6">
                Production networking permission
              </Typography>
              <Alert severity="info">
                KyClash uses two signed, narrowly scoped macOS services. The
                tunnel broker owns the exact sidecar and utun generation; the
                route helper discovers, applies, and rolls back only the private
                CIDRs shown for this site. Neither service can run arbitrary
                shell commands, change DNS, or take over a default route.
                Registration happens only when you choose Enable.
              </Alert>
              <Stack
                direction="row"
                spacing={1}
                useFlexGap
                sx={{ alignItems: 'center', flexWrap: 'wrap' }}
              >
                <Chip
                  label={`Route helper: ${servicesStatus?.route_helper ?? 'unknown'}`}
                  variant="outlined"
                />
                <Chip
                  label={`Tunnel broker: ${servicesStatus?.tunnel_broker ?? 'unknown'}`}
                  variant="outlined"
                />
                <Button
                  disabled={busy || servicesStatus?.ready === true}
                  onClick={() => {
                    setBusy(true)
                    setError(undefined)
                    void registerPrivilegedNetworkingServices()
                      .then(setServicesStatus)
                      .catch((reason: unknown) =>
                        setError(formatNetworkError(reason)),
                      )
                      .finally(() => {
                        setBusy(false)
                        void refreshServices()
                      })
                  }}
                >
                  Enable
                </Button>
                <Button
                  disabled={
                    busy ||
                    !servicesStatus ||
                    (servicesStatus.route_helper === 'not_registered' &&
                      servicesStatus.tunnel_broker === 'not_registered')
                  }
                  onClick={() => {
                    setBusy(true)
                    setError(undefined)
                    void unregisterPrivilegedNetworkingServices()
                      .then(setServicesStatus)
                      .catch((reason: unknown) =>
                        setError(formatNetworkError(reason)),
                      )
                      .finally(() => {
                        setBusy(false)
                        void refreshServices()
                      })
                  }}
                >
                  Disable
                </Button>
                {(servicesStatus?.route_helper === 'requires_approval' ||
                  servicesStatus?.tunnel_broker === 'requires_approval') && (
                  <Button onClick={() => void openRouteHelperSystemSettings()}>
                    Open System Settings
                  </Button>
                )}
                <Button disabled={busy} onClick={() => void refreshServices()}>
                  Refresh permission
                </Button>
              </Stack>
              {(servicesStatus?.route_helper === 'not_found' ||
                servicesStatus?.tunnel_broker === 'not_found') && (
                <Alert severity="warning">
                  One or both signed networking services are not available in
                  this App. Connect remains disabled; this build cannot claim a
                  production utun or private routes.
                </Alert>
              )}
            </Stack>
          </CardContent>
        </Card>
        <Card variant="outlined">
          <CardContent>
            <Stack spacing={2}>
              <Typography variant="h6">
                {status?.site.display_name ?? 'No configured site'}
              </Typography>
              <Typography color="text.secondary">{status?.site.id}</Typography>
              <FormControl
                disabled={
                  busy ||
                  !status ||
                  status.state !== 'disconnected' ||
                  !policyCatalog
                }
                fullWidth
              >
                <InputLabel id="network-policy-variant-label">
                  Signed route policy
                </InputLabel>
                <Select
                  label="Signed route policy"
                  labelId="network-policy-variant-label"
                  value={policyCatalog?.selected_catalog_id ?? ''}
                  onChange={(event) => {
                    const variant = policyCatalog?.variants.find(
                      (candidate) =>
                        candidate.catalog_id === event.target.value,
                    )
                    if (!variant) {
                      setError(networkErrorLabel.invalid_configuration)
                      return
                    }
                    setBusy(true)
                    setError(undefined)
                    void selectNetworkingPolicyVariant(variant.catalog_id)
                      .then(async (catalog) => {
                        setPolicyCatalog(catalog)
                        setStatus(await getNetworkingStatus())
                        setSites(await listNetworkingSites())
                      })
                      .catch((reason: unknown) =>
                        setError(formatNetworkError(reason)),
                      )
                      .finally(() => setBusy(false))
                  }}
                >
                  {policyCatalog?.variants.map((variant) => (
                    <MenuItem
                      key={variant.catalog_id}
                      value={variant.catalog_id}
                    >
                      {variant.display_name} —{' '}
                      {variant.private_cidrs.join(', ')}
                    </MenuItem>
                  ))}
                </Select>
                <FormHelperText>
                  Only individually verified, pre-signed route variants are
                  available. Selection is disabled while connected.
                </FormHelperText>
              </FormControl>
              {selectedVariant && (
                <Typography color="text.secondary" variant="caption">
                  Policy revision {selectedVariant.revision}; profile digest{' '}
                  {selectedVariant.profile_sha256.slice(0, 12)}…
                </Typography>
              )}
              <Stack
                direction="row"
                spacing={1}
                useFlexGap
                sx={{ flexWrap: 'wrap' }}
              >
                <Chip
                  label={status ? stateLabel[status.state] : 'Unavailable'}
                />
                <Chip
                  label={`Sidecar: ${status?.sidecar_state ?? 'unavailable'}`}
                  variant="outlined"
                />
                <Chip
                  label={`Transport: ${status?.active_transport ?? 'none'}`}
                  variant="outlined"
                />
              </Stack>
              {status?.health && (
                <Typography>
                  {status.health.latency_ms} ms latency ·{' '}
                  {status.health.jitter_ms} ms jitter ·{' '}
                  {status.health.loss_percent}% loss
                </Typography>
              )}
              <Typography color="text.secondary">
                {status?.site.private_route_count ?? 0} private routes; endpoint
                and credential details are hidden.
              </Typography>
              <Typography color="text.secondary">
                {`${sites.length} configured ${sites.length === 1 ? 'site' : 'sites'}; v1 permits one active site.`}
              </Typography>
              <Typography color="text.secondary">
                {diagnosticCount} redacted diagnostic events loaded.
              </Typography>
              <Stack direction="row" spacing={1}>
                <Button
                  disabled={
                    busy ||
                    servicesStatus?.ready !== true ||
                    status?.state !== 'disconnected'
                  }
                  onClick={() => void run(connectNetworking)}
                  startIcon={<PowerSettingsNewRounded />}
                  variant="contained"
                >
                  Connect
                </Button>
                <Button
                  disabled={busy || !status || status.state === 'disconnected'}
                  onClick={() => void run(disconnectNetworking)}
                  startIcon={<LinkOffRounded />}
                  variant="outlined"
                >
                  Disconnect
                </Button>
                <Button
                  disabled={!isTransitioning || !status?.operation_id}
                  onClick={() => {
                    if (!status?.operation_id) return
                    void cancelNetworkingOperation(status.operation_id)
                      .then(refresh)
                      .catch((reason: unknown) => {
                        setError(formatNetworkError(reason))
                      })
                  }}
                  startIcon={<StopCircleRounded />}
                >
                  Cancel
                </Button>
                <Button
                  disabled={busy || !status}
                  onClick={() => {
                    void getNetworkingDiagnostics()
                      .then((events) => setDiagnosticCount(events.length))
                      .catch((reason: unknown) =>
                        setError(formatNetworkError(reason)),
                      )
                  }}
                >
                  Refresh diagnostics
                </Button>
              </Stack>
            </Stack>
          </CardContent>
        </Card>
      </Stack>
    </BasePage>
  )
}

export default NetworkingPage
