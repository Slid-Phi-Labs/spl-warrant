# @slidphi/warrant-ucan

UCAN-signed Warrant delegation chains — AIP integration (Priority #1).

## Problem

Warrants (`spl-narrow` spend permission slips, see `~/workspace/warrant-crossmint/warrant.py`)
are unsigned JSON. Anyone holding the file can present it, and nothing
cryptographically binds a delegation hop to the parent agent that authorized it.

## Solution

Each hop carries an optional `ucan` field — a UCAN JWT minted by the parent
agent's `did:key` (via `@agentic-identity/did`):

```json
{
  "v": 1, "kind": "spl-narrow",
  "authority": {"agent_id": "agent-root", "max_cents": 100, "until": 1792203600},
  "hops": [
    {"agent_id": "agent-alice", "max_cents": 40, "until": 1792201800,
     "ucan": "eyJhbGciOiJFZERTQSIs..."}
  ]
}
```

## API

```ts
import {
  createAgent, issueSignedWarrant, attenuateSigned, verifySignedWarrant,
} from '@slidphi/warrant-ucan';

const root  = createAgent('agent-root');   // fresh did:key
const alice = createAgent('agent-alice');

// Issue (authority is the trust root, unsigned as before)
let w = issueSignedWarrant(root, { max_cents: 100, until: T1 });

// Delegate: parent signs, child DID is the audience, numbers can only narrow
w = await attenuateSigned(w, root, alice, { max_cents: 40, until: T2 });

// Verify (needs agent_id -> did:key mapping, e.g. Rider seat registry)
const r = await verifySignedWarrant(w, {
  'agent-root': root.keypair.did,
  'agent-alice': alice.keypair.did,
});
// { ok: true, mode: 'signed', body: {...}, hops: 1 }
```

## Verification order

1. **Structural** (identical to `warrant.py`): kind/v, body validity, chain
   monotonicity, expiry. Cheap checks first.
2. **Mode dispatch**: no `ucan` anywhere → `legacy` (backward compatible);
   some-but-not-all signed → fail closed (`warrant_partial_ucan`).
3. **UCAN per hop**: signature, expiry, `iss` = parent DID, `aud` = child DID,
   `fct` facts deep-equal the hop body (tamper-evidence), numeric attenuation
   vs parent caps, `warrant/spend:delegate` capability present. The AIP's
   `validateUcan` additionally enforces `prf` chain linkage (parent.aud ==
   child.iss).

## Design decisions

- **Numeric attenuation lives in `fct` facts**, not string caps: UCAN string
  capabilities cannot express ranges, so every hop carries
  `cap: {"warrant/spend": ["delegate"]}` and the numbers are pinned in facts
  and checked explicitly. A validly-signed but widened hop is still rejected.
- **Only the current holder can attenuate**: `attenuateSigned` requires the
  signer's agentId to match the last hop (or authority), so no third party
  can extend the chain.
- **Python `warrant.py` untouched**: its `_body()` ignores unknown hop
  fields, so signed warrants pass legacy verification (proven by test (e)).
  Note: Python `attenuate()` would strip `ucan` — extend signed chains with
  `attenuateSigned()` only.
- **UCAN lifetime** covers the hop's validity window plus a 5-minute buffer.

## Tests

`npm test` → 17/17 pass (node:test):

| # | Property |
|---|----------|
| a | valid 3-hop UCAN chain verifies (signed mode) |
| b1 | tampered hop facts fail (`warrant_ucan_facts_mismatch`) |
| b1b | inflated caps fail at structural check (defense in depth) |
| b2 | tampered UCAN signature fails |
| b3 | wrong-parent issuer fails |
| b4 | wrong audience fails |
| b5 | expired UCAN fails |
| c | legacy unsigned warrant verifies (legacy mode) |
| c2 | legacy widening still rejected |
| d1/d2 | sign-time widening throws (`warrant_widen_cents` / `warrant_widen_until`) |
| d3 | validly-signed but widened hop rejected at verify (insider threat) |
| d4 | only the current holder can attenuate |
| — | partial chain fails closed |
| — | expiry enforced on signed warrants |
| — | unknown agent DID fails closed |
| e | Python `warrant.py` verifies signed warrants (cross-language) |
