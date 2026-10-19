/**
 * @slidphi/warrant-ucan
 *
 * UCAN-signed Warrant delegation chains — AIP integration (Priority #1).
 *
 * Warrants (see ~/workspace/warrant-crossmint/warrant.py) are "narrow" spend
 * permission slips with Biscuit-style offline attenuation:
 *
 *   {v: 1, kind: "spl-narrow",
 *    authority: {agent_id, max_cents, until},
 *    hops: [{agent_id, max_cents, until}, ...]}
 *
 * Problem: the chain is unsigned JSON. Anyone holding the file can present it,
 * and nothing cryptographically binds a hop to the parent that authorized it.
 *
 * Fix (this module): each hop carries an OPTIONAL `ucan` field — a UCAN JWT
 * minted by the parent agent's did:key (via @agentic-identity/did):
 *
 *   hops: [{agent_id, max_cents, until, ucan: "eyJ..."}]
 *
 * Design notes (read before changing):
 *
 * 1. Capability encoding. UCAN string caps cannot express numeric ranges, so
 *    every hop UCAN carries cap {"warrant/spend": ["delegate"]} ("this agent
 *    may further delegate spend authority") and the NUMERIC attenuation
 *    (max_cents, until) is pinned in `fct` facts:
 *      fct: [{ warrant: { agent_id, max_cents, until } }]
 *    Verification requires the facts to deep-equal the hop body — the token
 *    is tamper-evident w.r.t. the numbers it authorizes.
 *
 * 2. Chain linkage. Hop i's UCAN has iss = parent DID, aud = child DID, and
 *    prf = [hop i-1's UCAN] (empty for the first hop). @agentic-identity/did's
 *    validateUcan additionally enforces parent.aud == child.iss up the chain.
 *
 * 3. Backward compatibility. A warrant with NO `ucan` on any hop verifies via
 *    the legacy structural path (identical semantics to warrant.py). A warrant
 *    with SOME hops signed fails closed ("warrant_partial_ucan") — partial
 *    signatures are a downgrade attack, not a migration state.
 *
 * 4. The Python reference (warrant.py) is UNTOUCHED. Its _body() ignores
 *    unknown hop fields, so signed warrants still pass legacy verification.
 *    (Python attenuate() would strip `ucan` — use attenuateSigned() here to
 *    extend a signed chain.)
 *
 * 5. Trust root. The authority body is unsigned JSON by construction — whoever
 *    holds the root keypair defines it. issueSignedWarrant() requires the root
 *    identity's agentId to match authority.agent_id.
 */

import {
  generateDidKey,
  mintUcan,
  validateUcan,
  ucanGrants,
  type DidKeyPair,
} from '@agentic-identity/did';

// ---------------------------------------------------------------------------
// Types (mirror warrant.py)
// ---------------------------------------------------------------------------

export interface WarrantBody {
  agent_id: string;
  max_cents: number;
  until: number;
}

export interface WarrantHop extends WarrantBody {
  /** Optional UCAN JWT minted by the parent agent. Absent = legacy unsigned. */
  ucan?: string;
}

export interface Warrant {
  v: 1;
  kind: 'spl-narrow';
  authority: WarrantBody;
  hops: WarrantHop[];
}

export interface AgentIdentity {
  agentId: string;
  keypair: DidKeyPair;
}

export class WarrantUcanError extends Error {
  constructor(public code: string) {
    super(code);
    this.name = 'WarrantUcanError';
  }
}

// ---------------------------------------------------------------------------
// Agent identities (did:key per agent)
// ---------------------------------------------------------------------------

/** Create an agent identity: a fresh did:key bound to an agent_id. */
export function createAgent(agentId: string): AgentIdentity {
  if (typeof agentId !== 'string' || !agentId) throw new WarrantUcanError('warrant_agent');
  return { agentId, keypair: generateDidKey() };
}

// ---------------------------------------------------------------------------
// Validation helpers (mirror warrant.py error strings)
// ---------------------------------------------------------------------------

function checkBody(raw: unknown): WarrantBody {
  if (typeof raw !== 'object' || raw === null) throw new WarrantUcanError('warrant_agent');
  const r = raw as Record<string, unknown>;
  if (typeof r['agent_id'] !== 'string' || !r['agent_id']) throw new WarrantUcanError('warrant_agent');
  if (typeof r['max_cents'] !== 'number' || !Number.isInteger(r['max_cents']) || r['max_cents'] < 0)
    throw new WarrantUcanError('warrant_cents');
  if (typeof r['until'] !== 'number' || !Number.isInteger(r['until']) || r['until'] <= 0)
    throw new WarrantUcanError('warrant_until');
  return { agent_id: r['agent_id'] as string, max_cents: r['max_cents'] as number, until: r['until'] as number };
}

function checkKind(w: unknown): asserts w is { v: unknown; kind: unknown; authority: unknown; hops: unknown } {
  if (
    typeof w !== 'object' || w === null ||
    (w as Record<string, unknown>)['kind'] !== 'spl-narrow' ||
    (w as Record<string, unknown>)['v'] !== 1
  ) {
    throw new WarrantUcanError('warrant_kind');
  }
}

const SPEND_CAP = { 'warrant/spend': ['delegate'] } as const;

/** UCAN lifetime: cover the hop's validity window plus a 5-minute buffer. */
function ucanLifetimeSec(hopUntil: number, nowSec: number): number {
  return Math.max(60, hopUntil - nowSec + 300);
}

// ---------------------------------------------------------------------------
// Issuance / attenuation (signing side)
// ---------------------------------------------------------------------------

/**
 * Issue a root warrant. The authority body is the trust root (unsigned, as
 * before); `root` must be the identity named by authority.agent_id.
 */
export function issueSignedWarrant(
  root: AgentIdentity,
  authority: { max_cents: number; until: number },
): Warrant {
  const body = checkBody({ agent_id: root.agentId, ...authority });
  return { v: 1, kind: 'spl-narrow', authority: body, hops: [] };
}

function lastBody(w: Warrant): WarrantBody {
  return w.hops.length > 0 ? (w.hops[w.hops.length - 1] as WarrantBody) : w.authority;
}

/**
 * Delegate: append a hop that may only NARROW the budget, signed by the
 * parent's did:key via UCAN. The parent MUST be the current chain holder
 * (last hop's agent, or the authority when there are no hops) — otherwise
 * anyone could extend the chain.
 *
 * Raises WarrantUcanError with warrant.py-compatible codes on widening.
 */
export async function attenuateSigned(
  warrant: Warrant,
  parent: AgentIdentity,
  child: AgentIdentity,
  hop: { max_cents: number; until: number },
  nowSec?: number,
): Promise<Warrant> {
  checkKind(warrant);
  const now = nowSec ?? Math.floor(Date.now() / 1000);
  const prev = lastBody(warrant);
  if (parent.agentId !== prev.agent_id) {
    throw new WarrantUcanError('warrant_agent_mismatch');
  }
  const hopBody = checkBody({ agent_id: child.agentId, ...hop });
  if (hopBody.max_cents > prev.max_cents) throw new WarrantUcanError('warrant_widen_cents');
  if (hopBody.until > prev.until) throw new WarrantUcanError('warrant_widen_until');

  const prevUcan = warrant.hops.length > 0 ? (warrant.hops[warrant.hops.length - 1] as WarrantHop).ucan : undefined;
  const ucan = await mintUcan(parent.keypair, child.keypair.did, { 'warrant/spend': ['delegate'] }, {
    lifetimeSec: ucanLifetimeSec(hopBody.until, now),
    facts: [{ warrant: { agent_id: hopBody.agent_id, max_cents: hopBody.max_cents, until: hopBody.until } }],
    proofs: prevUcan ? [prevUcan] : [],
  });

  return {
    v: 1,
    kind: 'spl-narrow',
    authority: warrant.authority,
    hops: [...warrant.hops, { ...hopBody, ucan }],
  };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export type VerifyMode = 'signed' | 'legacy';

export interface VerifyOk {
  ok: true;
  mode: VerifyMode;
  body: WarrantBody;
  hops: number;
}

export interface VerifyFail {
  ok: false;
  error: string;
}

export type VerifyResult = VerifyOk | VerifyFail;

function fail(error: string): VerifyFail {
  return { ok: false, error };
}

/**
 * Verify a warrant.
 *
 * 1. Structural check first (identical semantics to warrant.py): kind/v,
 *    per-hop body validity, chain monotonicity, expiry.
 * 2. No `ucan` on any hop → legacy mode (backward compatible).
 * 3. Some-but-not-all hops signed → fail closed (partial-chain downgrade).
 * 4. All hops signed → full UCAN verification per hop:
 *    signature, expiry, iss/aud binding, facts↔hop binding, numeric
 *    attenuation vs parent caps, delegate capability present.
 *
 * `agentDids` maps agent_id → did:key. The verifier must know each agent's
 * DID out-of-band (e.g. Rider seat registry); DIDs are not derivable from
 * opaque agent_ids.
 */
export async function verifySignedWarrant(
  warrant: unknown,
  agentDids: Record<string, string>,
  nowSec?: number,
): Promise<VerifyResult> {
  const now = nowSec ?? Math.floor(Date.now() / 1000);

  // -- 1. structural (mirror warrant.py) --
  try {
    checkKind(warrant);
  } catch (e) {
    return fail(e instanceof WarrantUcanError ? e.code : 'warrant_invalid');
  }
  const w = warrant as Warrant;
  let chain: WarrantBody[];
  try {
    chain = [checkBody(w.authority), ...w.hops.map(checkBody)];
  } catch (e) {
    return fail(e instanceof WarrantUcanError ? e.code : 'warrant_invalid');
  }
  for (let i = 1; i < chain.length; i++) {
    if (chain[i]!.max_cents > chain[i - 1]!.max_cents) return fail('warrant_widen_cents');
    if (chain[i]!.until > chain[i - 1]!.until) return fail('warrant_widen_until');
  }
  const last = chain[chain.length - 1]!;
  if (now >= last.until) return fail('warrant_expired');

  // -- 2/3. mode dispatch --
  const signedCount = w.hops.filter((h) => typeof (h as WarrantHop).ucan === 'string').length;
  if (signedCount === 0) {
    return { ok: true, mode: 'legacy', body: last, hops: w.hops.length };
  }
  if (signedCount !== w.hops.length) {
    return fail('warrant_partial_ucan');
  }

  // -- 4. UCAN verification per hop --
  let parentCaps: WarrantBody = chain[0]!;
  let parentDid = agentDids[w.authority.agent_id];
  if (!parentDid) return fail('warrant_unknown_did');

  for (let i = 0; i < w.hops.length; i++) {
    const hop = w.hops[i] as WarrantHop;
    const token = hop.ucan as string;
    const childDid = agentDids[hop.agent_id];
    if (!childDid) return fail('warrant_unknown_did');

    const v = await validateUcan(token, { nowSec: now });
    if (!v.valid || !v.payload) return fail(`warrant_ucan_invalid: ${v.reason ?? 'unknown'}`);
    const p = v.payload;

    if (p.iss !== parentDid) return fail('warrant_ucan_issuer_mismatch');
    if (p.aud !== childDid) return fail('warrant_ucan_audience_mismatch');
    if (!ucanGrants(p, 'warrant/spend', 'delegate')) return fail('warrant_ucan_capability');

    // Facts must bind the token to the EXACT hop body (tamper-evidence).
    const fact = (p.fct ?? []).find(
      (f): f is { warrant: WarrantBody } =>
        typeof f === 'object' && f !== null && 'warrant' in f,
    )?.warrant;
    if (
      !fact ||
      fact.agent_id !== hop.agent_id ||
      fact.max_cents !== hop.max_cents ||
      fact.until !== hop.until
    ) {
      return fail('warrant_ucan_facts_mismatch');
    }

    // Numeric attenuation vs the parent's committed caps.
    if (hop.max_cents > parentCaps.max_cents) return fail('warrant_widen_cents');
    if (hop.until > parentCaps.until) return fail('warrant_widen_until');

    parentCaps = hop;
    parentDid = childDid;
  }

  return { ok: true, mode: 'signed', body: last, hops: w.hops.length };
}

/** Re-exported for consumers that only need key management. */
export { generateDidKey };
export type { DidKeyPair };
export { SPEND_CAP };
