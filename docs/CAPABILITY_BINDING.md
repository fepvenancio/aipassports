# Capability Binding — Cryptographic `nearAccountId` Authentication

## The gap this closes

The Shade Agent authenticates every `/vault/*` and `/skills/*` request with a single
shared Bearer token (`IRONCLAW_AGENT_API_KEY`). That token proves *the caller is the
gateway* — it says nothing about *which account* the request may act on. The
`nearAccountId` in the request body was **self-asserted**: the agent derived the
per-user encryption key directly from it (`key_derivation::derive_dek`, account ID as
the HKDF salt) without any proof the caller was entitled to that account.

Consequence: anyone holding the Bearer token — a leaked secret, or any path that can
reach the agent directly, bypassing the gateway — could read or write **any** account's
vault simply by setting `nearAccountId`. The gateway already enforces
`args.nearAccountId === session account` before dispatch, but that check lives *outside*
the TEE trust boundary. The agent trusted it blindly.

## The fix

The gateway now mints a short-lived **Ed25519-signed capability token** that binds the
authenticated NEAR account. The agent verifies the signature against the gateway's
public key and enforces `capability.sub == nearAccountId` inside the enclave. A leaked
Bearer token alone no longer suffices to spoof an account — an attacker would also need
the gateway's Ed25519 signing key, which never leaves the gateway's secret store.

This is deliberately **TEE-offline**: no NEAR RPC egress, no ZDR-firewall change, minimal
enclave footprint. Two independent secrets now guard the boundary (Bearer for transport
authentication, Ed25519 key for identity binding).

```
Client ──NEP-413 wallet sig──▶ Gateway ──verifies, mints capability token──▶ Agent (TEE)
                                  │  Bearer (transport auth)                    │ verifies token
                                  └  X-Aegis-Capability: <token> ──────────────▶ sub == nearAccountId
```

## Token format

```
token        = base64url(payload_json) "." base64url(ed25519_sig)
signed bytes = the ASCII bytes of the first segment, base64url(payload_json)
payload_json = {"sub","team","perm","iat","exp","jti"}   // iat/exp in epoch ms
```

Signing over the already-encoded first segment (not the re-serialized JSON) avoids any
canonicalization mismatch between signer (gateway, `@noble/ed25519`) and verifier
(agent, `ed25519-dalek` `verify_strict`). TTL is 120s; replay defense rides on the short
`exp` window plus the carried `jti` nonce.

## Configuration

| Side    | Variable                   | Value                                              |
|---------|----------------------------|----------------------------------------------------|
| Gateway | `AEGIS_CAP_SIGNING_KEY`    | 32-byte Ed25519 **private** seed (hex). Worker secret. |
| Agent   | `AEGIS_GATEWAY_CAP_PUBKEY` | 32-byte Ed25519 **public** key (hex). Env/secret.  |

Generate a matching keypair (Node, uses the same library the gateway signs with):

```bash
node --input-type=module -e '
import * as ed from "@noble/ed25519";
const seed = crypto.getRandomValues(new Uint8Array(32));
const pub = await ed.getPublicKeyAsync(seed);
const hex = (b) => [...b].map(x=>x.toString(16).padStart(2,"0")).join("");
console.log("AEGIS_CAP_SIGNING_KEY (gateway, secret):", hex(seed));
console.log("AEGIS_GATEWAY_CAP_PUBKEY (agent, public):", hex(pub));
'
```

Then:

```bash
wrangler secret put AEGIS_CAP_SIGNING_KEY     # paste the seed
# Agent: set AEGIS_GATEWAY_CAP_PUBKEY (docker-compose env, or `ironclaw secret put`)
```

## Rollout (both sides, in order)

The feature is **opt-in and fail-safe-by-config**:

1. **Neither set** → legacy bearer-only behavior. The agent logs a prominent
   `SECURITY: ... capability binding DISABLED` warning at startup.
2. **Gateway set, agent unset** → gateway attaches tokens; agent ignores them. Harmless.
3. **Both set** → enforced. The agent rejects requests lacking a valid token
   (`AGENT_ERROR_CAPABILITY_*`) or whose subject mismatches (`AGENT_ERROR_SUBJECT_MISMATCH`).

A present-but-malformed `AEGIS_GATEWAY_CAP_PUBKEY` makes the agent **refuse to start** —
silently degrading to bearer-only would re-open the gap.

To enable in production: set the gateway secret first (step 2, no behavior change), confirm
tokens are attached, then set the agent public key (step 3).

## Scope and follow-ups

- **Covered now:** the three per-user endpoints where a self-asserted account directly
  controls key derivation — `/vault/write`, `/vault/read`, `/skills/execute`.
- **Not yet covered:** team-vault endpoints (`/vault/team/*`). They are partitioned by
  `team_id` and gated by gateway membership checks; the gateway currently does not forward
  a requesting-account subject for them. Extending capability binding there is a clean
  follow-up (forward `requestingAccountId` as the token subject and call
  `enforce_capability_subject` in the team handlers).

## Why this is the right substrate for ZK later

This is the exact seam at which a zero-knowledge credential proof can replace the signed
token: swap `CapabilityVerifier::verify` for a proof verifier (e.g. a Groth16/Semaphore
kernel checking membership in an authorized-set commitment plus a nullifier), keep the
`enforce_*` call sites unchanged, and the agent gains anonymous-but-authorized access
without learning *which* account is calling. Authenticated identity binding is the
prerequisite; ZK privacy is the layer on top. See the ZK assessment for the full picture.
