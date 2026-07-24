import DownloadRounded from '@mui/icons-material/DownloadRounded'
import LinkOffRounded from '@mui/icons-material/LinkOffRounded'
import PowerSettingsNewRounded from '@mui/icons-material/PowerSettingsNewRounded'
import RefreshRounded from '@mui/icons-material/RefreshRounded'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  Stack,
  Typography,
} from '@mui/material'
import { save } from '@tauri-apps/plugin-dialog'
import { writeTextFile } from '@tauri-apps/plugin-fs'
import { useCallback, useEffect, useRef, useState } from 'react'

import { BasePage } from '@/components/base'
import {
  cancelNetworkingExternalPeerLab,
  connectNetworkingExternalPeerLab,
  connectNetworkingUserspaceLab,
  connectNetworkingDev,
  disconnectNetworkingExternalPeerLab,
  disconnectNetworkingUserspaceLab,
  disconnectNetworkingDev,
  getNetworkingExternalPeerLabStatus,
  getNetworkingUserspaceLabStatus,
  getNetworkingDevStatus,
} from '@/services/cmds'
import type {
  NetworkingDevStatus,
  NetworkingExternalPeerLabPhase,
  NetworkingExternalPeerLabStatus,
  NetworkingUserspaceLabStatus,
} from '@/types/networking'

const userspaceLabBuild = import.meta.env.VITE_NETWORKING_SYSTEM_LAB === 'true'
const vmUtunLabBuild = import.meta.env.VITE_NETWORKING_VM_UTUN_LAB === 'true'
const vmNetworkLabBuild =
  import.meta.env.VITE_NETWORKING_VM_NETWORK_LAB === 'true'
const vmExternalPeerLabBuild =
  import.meta.env.VITE_NETWORKING_VM_EXTERNAL_PEER_LAB === 'true'
type DisplayStatus = NetworkingDevStatus | NetworkingUserspaceLabStatus

const externalConnectingPhases: ReadonlySet<NetworkingExternalPeerLabPhase> =
  new Set([
    'waiting_for_validated_peer',
    'ready',
    'preparing_mihomo',
    'preparing_utun',
    'connecting_quic',
    'connected_quic',
    'switching_to_wss',
    'connected_wss',
    'switching_to_tcp',
  ])

const NetworkingExternalPeerLabPage = () => {
  const [status, setStatus] = useState<NetworkingExternalPeerLabStatus>()
  const [error, setError] = useState<string>()
  const [actionBusy, setActionBusy] = useState(false)
  const mountedRef = useRef(false)
  const actionBusyRef = useRef(false)
  const responseGenerationRef = useRef(0)
  const refreshInFlightRef = useRef<Promise<void> | null>(null)

  const refresh = useCallback((): Promise<void> => {
    if (actionBusyRef.current) return Promise.resolve()
    if (refreshInFlightRef.current) return refreshInFlightRef.current

    const generation = ++responseGenerationRef.current
    const task = getNetworkingExternalPeerLabStatus()
      .then((nextStatus) => {
        if (!mountedRef.current || generation !== responseGenerationRef.current)
          return
        setStatus(nextStatus)
        setError(undefined)
      })
      .catch((reason: unknown) => {
        if (!mountedRef.current || generation !== responseGenerationRef.current)
          return
        setError(reason instanceof Error ? reason.message : String(reason))
      })
      .finally(() => {
        if (refreshInFlightRef.current === task)
          refreshInFlightRef.current = null
      })
    refreshInFlightRef.current = task
    return task
  }, [])

  const runAction = useCallback(
    async (
      action: () => Promise<NetworkingExternalPeerLabStatus>,
    ): Promise<void> => {
      if (actionBusyRef.current) return
      actionBusyRef.current = true
      setActionBusy(true)
      setError(undefined)
      const generation = ++responseGenerationRef.current
      try {
        const nextStatus = await action()
        if (mountedRef.current && generation === responseGenerationRef.current)
          setStatus(nextStatus)
      } catch (reason) {
        if (mountedRef.current && generation === responseGenerationRef.current)
          setError(reason instanceof Error ? reason.message : String(reason))
      } finally {
        actionBusyRef.current = false
        if (mountedRef.current && generation === responseGenerationRef.current)
          setActionBusy(false)
      }
    },
    [],
  )

  useEffect(() => {
    mountedRef.current = true
    const initial = window.setTimeout(() => void refresh(), 0)
    const timer = window.setInterval(() => void refresh(), 500)
    return () => {
      mountedRef.current = false
      responseGenerationRef.current += 1
      window.clearTimeout(initial)
      window.clearInterval(timer)
    }
  }, [refresh])

  const phase = status?.phase ?? 'disconnected'
  const connecting = externalConnectingPhases.has(phase)
  const connected = phase === 'connected_tcp'
  const canConnect =
    status?.phase === 'disconnected' && status.last_error === null
  const supervisorRestartRequired =
    status?.phase === 'disconnected' &&
    status.last_error === 'sidecar_unavailable'

  return (
    <BasePage title="KyClash Network">
      <Stack spacing={2}>
        <Alert severity="warning">
          <strong>
            VM LAB · EXTERNAL PEER · REAL UTUN · MIHOMO COEXISTENCE
          </strong>
          <br />
          Peer: <strong>kyclash-macos-lab-peer</strong>. This is a
          non-production two-VirtualMac result. LAN forwarding is disabled.
          Connect waits for the separately validated peer, then proves QUIC →
          WSS → TCP break-before-make through one real utun.
        </Alert>
        {error && <Alert severity="error">{error}</Alert>}
        {supervisorRestartRequired && (
          <Alert severity="info">
            This one-shot root-supervisor session has been consumed. Cleanup is
            complete; visibly re-stage/restart the lab supervisor before
            launching a new App session.
          </Alert>
        )}
        <Card variant="outlined">
          <CardContent>
            <Stack spacing={2}>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  External-peer state
                </Typography>
                <Box>
                  <Chip
                    color={connected ? 'success' : 'default'}
                    label={status?.phase ?? 'unavailable'}
                  />
                </Box>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Peer boundary
                </Typography>
                <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                  <Chip
                    label={status?.peer_vm ?? 'kyclash-macos-lab-peer'}
                    size="small"
                    variant="outlined"
                  />
                  <Chip
                    color="warning"
                    label="non-production"
                    size="small"
                    variant="outlined"
                  />
                  <Chip
                    label="LAN forwarding: disabled"
                    size="small"
                    variant="outlined"
                  />
                </Stack>
              </Box>
              <Divider />
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Real KyClash utun and exact private route
                </Typography>
                <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                  <Chip
                    color={status?.tunnel_interface ? 'success' : 'default'}
                    label={status?.tunnel_interface ?? 'utun: pending'}
                    size="small"
                    variant="outlined"
                  />
                  <Chip
                    color={status?.routes_installed ? 'success' : 'default'}
                    label={
                      status?.routes_installed
                        ? '10.88.0.2/32'
                        : '10.88.0.2/32: pending carrier health'
                    }
                    size="small"
                    variant="outlined"
                  />
                </Stack>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Mihomo coexistence
                </Typography>
                <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                  <Chip
                    color={status?.mihomo_coexisting ? 'success' : 'default'}
                    label={status?.mihomo_interface ?? 'utun4094: pending'}
                    size="small"
                    variant="outlined"
                  />
                  <Chip
                    color={status?.mihomo_coexisting ? 'success' : 'default'}
                    label={status?.mihomo_route ?? '10.88.0.0/24: pending'}
                    size="small"
                    variant="outlined"
                  />
                </Stack>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Active carrier
                </Typography>
                <Box>
                  <Chip
                    color={
                      status?.active_transport === 'tcp' ? 'success' : 'default'
                    }
                    label={status?.active_transport?.toUpperCase() ?? 'none'}
                  />
                </Box>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Same-run automated SSH proofs · fixed command only
                </Typography>
                <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                  <Chip
                    color={status?.private_echo_healthy ? 'success' : 'default'}
                    label={`private echo: ${status?.private_echo_healthy ? 'healthy' : 'pending'}`}
                    size="small"
                    variant="outlined"
                  />
                  <Chip
                    color={status?.overlay_ssh_verified ? 'success' : 'default'}
                    label={`in-process SSH proof: ${status?.overlay_ssh_verified ? 'verified' : 'pending'}`}
                    size="small"
                    variant="outlined"
                  />
                  <Chip
                    color={status?.system_ssh_verified ? 'success' : 'default'}
                    label={`Apple SSH forced command: ${status?.system_ssh_verified ? 'verified' : 'pending'}`}
                    size="small"
                    variant="outlined"
                  />
                  <Chip
                    color={
                      status?.overlay_ssh_verified && status.system_ssh_verified
                        ? 'success'
                        : 'default'
                    }
                    label={
                      status?.overlay_ssh_verified && status.system_ssh_verified
                        ? 'SSH 隧道已验证（非交互式）'
                        : 'SSH 隧道验证未完成'
                    }
                    size="small"
                  />
                </Stack>
                <Typography
                  color="text.secondary"
                  sx={{ display: 'block', mt: 0.75 }}
                  variant="caption"
                >
                  System SSH endpoint: 10.88.0.2:2222 → peer 127.0.0.1:22.
                  Interactive login depends on the peer sshd account and public
                  key policy; the automated acceptance key never grants a shell.
                </Typography>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Carrier proofs
                </Typography>
                <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                  {(['quic', 'wss', 'tcp'] as const).map((transport) => {
                    const check = status?.transport_checks.find(
                      (value) => value.transport === transport,
                    )
                    const systemSshRequired = transport === 'tcp'
                    const verified =
                      check?.carrier_healthy &&
                      check.private_echo_healthy &&
                      check.mihomo_coexisting &&
                      check.overlay_ssh_verified &&
                      (!systemSshRequired || check.system_ssh_verified)
                    const impairment =
                      check?.impairment_reason === 'carrier_unhealthy_observed'
                        ? 'carrier unhealthy observed'
                        : undefined
                    return (
                      <Chip
                        key={transport}
                        color={verified ? 'success' : 'default'}
                        label={`${transport.toUpperCase()}: ${
                          verified
                            ? `verified${impairment ? ` · ${impairment}` : ''}`
                            : 'pending'
                        }`}
                        size="small"
                        variant="outlined"
                      />
                    )
                  })}
                </Stack>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Last redacted error
                </Typography>
                <Typography>{status?.last_error ?? 'none'}</Typography>
              </Box>
              <Divider />
              <Stack direction="row" spacing={1}>
                <Button
                  disabled={actionBusy || !canConnect}
                  onClick={() =>
                    void runAction(connectNetworkingExternalPeerLab)
                  }
                  startIcon={<PowerSettingsNewRounded />}
                  variant="contained"
                >
                  Connect
                </Button>
                <Button
                  color="warning"
                  disabled={actionBusy || !connecting}
                  onClick={() =>
                    void runAction(cancelNetworkingExternalPeerLab)
                  }
                  startIcon={<LinkOffRounded />}
                  variant="outlined"
                >
                  Cancel
                </Button>
                <Button
                  disabled={actionBusy || !connected}
                  onClick={() =>
                    void runAction(disconnectNetworkingExternalPeerLab)
                  }
                  startIcon={<LinkOffRounded />}
                  variant="outlined"
                >
                  Disconnect
                </Button>
              </Stack>
            </Stack>
          </CardContent>
        </Card>
      </Stack>
    </BasePage>
  )
}

const NetworkingDevStandardPage = () => {
  const [status, setStatus] = useState<DisplayStatus>()
  const [error, setError] = useState<string>()
  const [loading, setLoading] = useState(false)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(undefined)
    try {
      setStatus(
        await (userspaceLabBuild
          ? getNetworkingUserspaceLabStatus()
          : getNetworkingDevStatus()),
      )
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setLoading(false)
    }
  }, [])

  const runAction = useCallback(
    async (action: () => Promise<DisplayStatus>) => {
      setLoading(true)
      setError(undefined)
      try {
        setStatus(await action())
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : String(reason))
      } finally {
        setLoading(false)
      }
    },
    [],
  )

  const exportDiagnostics = useCallback(async () => {
    if (!status) return
    setLoading(true)
    setError(undefined)
    try {
      const path = await save({
        defaultPath: 'kyclash-network-diagnostics.json',
        filters: [{ name: 'JSON', extensions: ['json'] }],
      })
      if (!path) return
      const diagnostic = {
        schema_version: 1,
        ...('runtime_mode' in status
          ? {
              runtime_mode: status.runtime_mode,
              tunnel_kind: status.tunnel_kind,
              tunnel_interface: status.tunnel_interface,
              routes_installed: status.routes_installed,
              private_reachable: status.private_reachable,
              mihomo_coexisting: status.mihomo_coexisting,
            }
          : {}),
        network_state: status.network_state,
        sidecar_state: status.sidecar_state,
        site_id: status.site_id,
        private_route_count: status.private_routes.length,
        private_routes: status.private_routes,
        active_transport: status.active_transport,
        health: status.health,
        last_error: status.last_error,
      }
      await writeTextFile(path, `${JSON.stringify(diagnostic, null, 2)}\n`)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setLoading(false)
    }
  }, [status])

  useEffect(() => {
    void refresh()
  }, [refresh])

  return (
    <BasePage
      title={
        userspaceLabBuild
          ? vmNetworkLabBuild
            ? 'KyClash Network (VM LAB · REAL UTUN · PRIVATE ROUTE · MIHOMO)'
            : vmUtunLabBuild
              ? 'KyClash Network (VM LAB · REAL UTUN · NO ROUTES)'
              : 'KyClash Network (LAB · userspace)'
          : 'KyClash Network (Development)'
      }
      header={
        <Button
          color="inherit"
          disabled={loading}
          onClick={() => void refresh()}
          startIcon={<RefreshRounded />}
        >
          Refresh
        </Button>
      }
    >
      <Stack spacing={2}>
        {vmNetworkLabBuild ? (
          <Alert severity="warning">
            <strong>VM LAB · REAL UTUN · PRIVATE ROUTE · MIHOMO.</strong>{' '}
            Connect uses the fixed root harness manually authorized in this
            disposable VirtualMac. It creates a real KyClash utun, installs the
            fixed private route only after carrier health, proves the private
            TCP echo, and keeps Mihomo on utun4094 with its covering route. QUIC
            → WSS → TCP uses break-before-make on the same utun. This is not
            production XPC, does not read Keychain, and does not use a
            production endpoint.
          </Alert>
        ) : vmUtunLabBuild ? (
          <Alert severity="warning">
            <strong>VM LAB · REAL UTUN · NO ROUTES.</strong> Connect uses the
            fixed root harness that the user manually authorized in this
            disposable VirtualMac. It creates a real utun and exercises QUIC →
            WSS → TCP. It does not install private routes, call the production
            XPC helpers, read Keychain, change DNS, or use a production
            endpoint. Displayed private CIDRs are metadata only.
          </Alert>
        ) : userspaceLabBuild ? (
          <Alert severity="warning">
            <strong>LAB / USERSPACE ONLY.</strong> Connect starts the bundled Go
            loopback lab sidecar and exercises QUIC → WSS → TCP with a userspace
            WireGuard netstack. It does not create utun, install routes, call
            the route helper, read Keychain, change DNS, or use a production
            endpoint. The displayed private CIDRs are metadata only.
          </Alert>
        ) : (
          <Alert severity="warning">
            Isolated development simulation. Connect and disconnect operate only
            on the in-process mock; no tunnel, route, DNS, interface,
            credential, or external endpoint is touched.
          </Alert>
        )}
        {error && <Alert severity="error">{error}</Alert>}
        <Card variant="outlined">
          <CardContent>
            <Stack spacing={2}>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Site
                </Typography>
                <Typography>
                  {status?.site_display_name ?? 'unavailable'}
                </Typography>
                <Typography color="text.secondary" variant="caption">
                  {status?.site_id}
                </Typography>
              </Box>
              <Divider />
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Network state
                </Typography>
                <Box>
                  <Chip label={status?.network_state ?? 'unavailable'} />
                </Box>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Sidecar lifecycle
                </Typography>
                <Box>
                  <Chip label={status?.sidecar_state ?? 'unavailable'} />
                </Box>
              </Box>
              {userspaceLabBuild && status && 'runtime_mode' in status && (
                <Box>
                  <Typography color="text.secondary" variant="caption">
                    Lab boundary
                  </Typography>
                  <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                    <Chip label={status.runtime_mode} size="small" />
                    <Chip label={status.tunnel_kind} size="small" />
                    <Chip
                      color={status.tunnel_interface ? 'success' : 'default'}
                      label={status.tunnel_interface ?? 'no tunnel'}
                      size="small"
                      variant="outlined"
                    />
                    <Chip
                      color={status.routes_installed ? 'success' : 'warning'}
                      label={
                        status.routes_installed
                          ? 'routes: installed (lab)'
                          : vmNetworkLabBuild
                            ? 'routes: pending health'
                            : 'routes: not installed'
                      }
                      size="small"
                      variant="outlined"
                    />
                  </Stack>
                </Box>
              )}
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Active transport
                </Typography>
                <Box>
                  <Chip label={status?.active_transport ?? 'none'} />
                </Box>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  {userspaceLabBuild ? 'Last lab health' : 'Mock health'}
                </Typography>
                <Typography>
                  {status?.health
                    ? `${status.health.latency_ms} ms latency · ${status.health.jitter_ms} ms jitter · ${'loss_percent' in status.health ? status.health.loss_percent : status.health.packet_loss_percent}% loss`
                    : 'unavailable while disconnected'}
                </Typography>
              </Box>
              {userspaceLabBuild && status && 'transport_checks' in status && (
                <Box>
                  <Typography color="text.secondary" variant="caption">
                    Actual carrier checks (break-before-make)
                  </Typography>
                  <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                    {(['quic', 'wss', 'tcp'] as const).map((transport) => {
                      const check = status.transport_checks.find(
                        (value) => value.transport === transport,
                      )
                      return (
                        <Chip
                          key={transport}
                          color={check?.reachable ? 'success' : 'default'}
                          label={`${transport.toUpperCase()}: ${check?.reachable ? 'passed' : 'pending'}${vmNetworkLabBuild && check?.private_reachable ? ' · echo' : ''}${vmNetworkLabBuild && check?.mihomo_coexisting ? ' · Mihomo' : ''}`}
                          size="small"
                          variant="outlined"
                        />
                      )
                    })}
                  </Stack>
                </Box>
              )}
              {vmNetworkLabBuild && status && 'runtime_mode' in status && (
                <Box>
                  <Typography color="text.secondary" variant="caption">
                    Private echo / Mihomo coexistence
                  </Typography>
                  <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                    <Chip
                      color={status.private_reachable ? 'success' : 'default'}
                      label={`private echo: ${status.private_reachable ? 'reachable' : 'pending'}`}
                      size="small"
                      variant="outlined"
                    />
                    <Chip
                      color={status.mihomo_coexisting ? 'success' : 'default'}
                      label={`Mihomo: ${status.mihomo_coexisting ? 'coexisting' : 'pending'}`}
                      size="small"
                      variant="outlined"
                    />
                  </Stack>
                </Box>
              )}
              <Box>
                <Typography color="text.secondary" variant="caption">
                  {vmNetworkLabBuild
                    ? 'Private routes (fixed VM lab · installed after health)'
                    : vmUtunLabBuild
                      ? 'Private routes (metadata only · not installed)'
                      : 'Private routes (planned only)'}
                </Typography>
                <Box
                  sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 0.5 }}
                >
                  {status?.private_routes.map((route) => (
                    <Chip
                      key={route}
                      label={route}
                      size="small"
                      variant="outlined"
                    />
                  ))}
                </Box>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Last error
                </Typography>
                <Typography>{status?.last_error ?? 'none'}</Typography>
              </Box>
              <Divider />
              <Stack direction="row" spacing={1}>
                <Button
                  disabled={loading || status?.network_state !== 'disconnected'}
                  onClick={() =>
                    void runAction(
                      userspaceLabBuild
                        ? connectNetworkingUserspaceLab
                        : connectNetworkingDev,
                    )
                  }
                  startIcon={<PowerSettingsNewRounded />}
                  variant="contained"
                >
                  {userspaceLabBuild
                    ? vmNetworkLabBuild
                      ? 'Connect · real utun · private route · Mihomo'
                      : vmUtunLabBuild
                        ? 'Connect · real utun · QUIC → WSS → TCP'
                        : 'Connect · run QUIC → WSS → TCP'
                    : 'Connect mock'}
                </Button>
                <Button
                  disabled={loading || status?.network_state === 'disconnected'}
                  onClick={() =>
                    void runAction(
                      userspaceLabBuild
                        ? disconnectNetworkingUserspaceLab
                        : disconnectNetworkingDev,
                    )
                  }
                  startIcon={<LinkOffRounded />}
                  variant="outlined"
                >
                  {userspaceLabBuild ? 'Disconnect lab' : 'Disconnect mock'}
                </Button>
                <Button
                  disabled={loading || !status}
                  onClick={() => void exportDiagnostics()}
                  startIcon={<DownloadRounded />}
                  variant="text"
                >
                  Export diagnostics
                </Button>
              </Stack>
            </Stack>
          </CardContent>
        </Card>
      </Stack>
    </BasePage>
  )
}

const NetworkingDevPage = () =>
  vmExternalPeerLabBuild ? (
    <NetworkingExternalPeerLabPage />
  ) : (
    <NetworkingDevStandardPage />
  )

export default NetworkingDevPage
