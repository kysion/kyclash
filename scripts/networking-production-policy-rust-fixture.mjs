import { createPolicyArtifacts } from './generate-networking-production-vm-lab.mjs'

// Test-only bridge: a fresh single-use JS signing key produces one public
// envelope/trust pair, which the production Rust verifier must accept. No
// private key is serialized or returned across this process boundary.
const now = 1_800_000_000
const descriptor = {
  run_id: '0123456789abcdef',
  peer_public_key: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
  endpoints: [
    { transport: 'quic', url: 'https://127.0.0.1:20001' },
    { transport: 'wss', url: 'wss://127.0.0.1:20002/kynp' },
    { transport: 'tcp', url: 'tcp://127.0.0.1:20003' },
  ],
  expires_at: now + 3_600,
}
const artifacts = createPolicyArtifacts({
  descriptor,
  endpoints: [
    { transport: 'quic', url: descriptor.endpoints[0].url, port: 20_001 },
    { transport: 'wss', url: descriptor.endpoints[1].url, port: 20_002 },
    { transport: 'tcp', url: descriptor.endpoints[2].url, port: 20_003 },
  ],
  now,
  revision: 42,
})
process.stdout.write(
  `${JSON.stringify({
    now,
    policy_base64: artifacts.policyBytes.toString('base64'),
    trust_base64: artifacts.trustBytes.toString('base64'),
  })}\n`,
)
