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
import { useCallback, useEffect, useState } from 'react'

import { BasePage } from '@/components/base'
import {
  connectNetworkingDev,
  disconnectNetworkingDev,
  getNetworkingDevStatus,
} from '@/services/cmds'
import type { NetworkingDevStatus } from '@/types/networking'

const NetworkingDevPage = () => {
  const [status, setStatus] = useState<NetworkingDevStatus>()
  const [error, setError] = useState<string>()
  const [loading, setLoading] = useState(false)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(undefined)
    try {
      setStatus(await getNetworkingDevStatus())
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setLoading(false)
    }
  }, [])

  const runAction = useCallback(
    async (action: () => Promise<NetworkingDevStatus>) => {
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

  useEffect(() => {
    void refresh()
  }, [refresh])

  return (
    <BasePage
      title="KyClash Network (Development)"
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
        <Alert severity="warning">
          Isolated development simulation. Connect and disconnect operate only
          on the in-process mock; no tunnel, route, DNS, interface, credential,
          or external endpoint is touched.
        </Alert>
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
                  Mock health
                </Typography>
                <Typography>
                  {status?.health
                    ? `${status.health.latency_ms} ms latency · ${status.health.jitter_ms} ms jitter · ${status.health.packet_loss_percent}% loss`
                    : 'unavailable while disconnected'}
                </Typography>
              </Box>
              <Box>
                <Typography color="text.secondary" variant="caption">
                  Private routes (planned only)
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
                  onClick={() => void runAction(connectNetworkingDev)}
                  startIcon={<PowerSettingsNewRounded />}
                  variant="contained"
                >
                  Connect mock
                </Button>
                <Button
                  disabled={loading || status?.network_state === 'disconnected'}
                  onClick={() => void runAction(disconnectNetworkingDev)}
                  startIcon={<LinkOffRounded />}
                  variant="outlined"
                >
                  Disconnect mock
                </Button>
              </Stack>
            </Stack>
          </CardContent>
        </Card>
      </Stack>
    </BasePage>
  )
}

export default NetworkingDevPage
