import validProfileFixture from '@root/schemas/fixtures/network-v1.valid.json'

import { assertNetworkProfileV1 } from './networking'

// Importing the shared fixture keeps it in the TypeScript compilation graph.
// Rust owns full semantic validation; the UI rejects unsupported versions at
// its trust boundary before using the typed contract.
assertNetworkProfileV1(validProfileFixture)

export const NETWORK_V1_FIXTURE = validProfileFixture
