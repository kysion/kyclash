import RefreshRounded from '@mui/icons-material/RefreshRounded'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Stack,
  Typography,
} from '@mui/material'
import { useCallback, useEffect, useState } from 'react'

import { BasePage } from '@/components/base'
import { getNetworkingDevStatus } from '@/services/cmds'
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
          Read-only development diagnostics. This page cannot connect a tunnel
          or change routes, DNS, or network interfaces.
        </Alert>
        {error && <Alert severity="error">{error}</Alert>}
        <Card variant="outlined">
          <CardContent>
            <Stack spacing={2}>
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
            </Stack>
          </CardContent>
        </Card>
      </Stack>
    </BasePage>
  )
}

export default NetworkingDevPage
