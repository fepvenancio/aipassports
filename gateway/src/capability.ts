/**
 * @file capability.ts
 * @notice Mints short-lived Ed25519 "capability tokens" that bind a request to an
 *         authenticated NEAR account, so the Shade Agent does not have to trust the
 *         self-asserted `nearAccountId` in the request body.
 *
 * ## Threat closed
 * The gateway↔agent hop authenticates with a single shared Bearer token
 * (`IRONCLAW_AGENT_API_KEY`). That token proves "the caller is the gateway" but
 * says nothing about *which* account the request may act as. Before capability
 * binding, anyone holding that Bearer token (a leak, or any path reaching the agent
 * directly) could read or write ANY account's vault by setting `nearAccountId`,
 * because the TEE derives the per-user key from that field.
 *
 * The gateway already authenticates the caller's NEAR identity (NEP-413 wallet
 * signature → session) and enforces `args.nearAccountId === session account`
 * BEFORE dispatch (see index.ts tools/call boundary check). This module adds a
 * cryptographic carrier of that fact: a token signed with a gateway-only Ed25519
 * key. The agent verifies the signature against the matching public key, so a
 * leaked Bearer token alone can no longer impersonate an account.
 *
 * ## Token format (must match agent/src/capability.rs)
 *   token        = base64url(payload_json) "." base64url(ed25519_sig)
 *   signed bytes = the ASCII bytes of the first segment, base64url(payload_json)
 *   payload_json = {"sub","team","perm","iat","exp","jti"}   // iat/exp in epoch ms
 */

import * as ed from "@noble/ed25519";
import type { Env } from "./types.js";

/** Capability-token lifetime. Kept short — replay defence rides on this window. */
const TOKEN_TTL_MS = 120_000;

/** Worker-secret env var holding the 32-byte Ed25519 signing seed (hex). */
const SIGNING_KEY_ENV = "AEGIS_CAP_SIGNING_KEY";

interface CapabilityOptions {
  readonly team?: string;
  readonly perm?: string;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("hex string has odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("invalid hex");
    out[i] = byte;
  }
  return out;
}

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Mint a capability token for `subject` (the authenticated NEAR account).
 *
 * Returns "" when `AEGIS_CAP_SIGNING_KEY` is unset — legacy mode. In that case the
 * agent must also have capability binding disabled, or it will reject the request.
 * This lets the feature be rolled out by configuring both sides together.
 *
 * @throws if the signing key is present but not a 32-byte hex value.
 */
export async function mintCapabilityToken(
  env: Env,
  subject: string,
  opts?: CapabilityOptions,
): Promise<string> {
  const seedHex = env.AEGIS_CAP_SIGNING_KEY?.trim();
  if (!seedHex) return "";
  if (!subject) throw new Error("mintCapabilityToken: subject is required");

  const seed = hexToBytes(seedHex);
  if (seed.length !== 32) {
    throw new Error(`${SIGNING_KEY_ENV} must be a 32-byte (64 hex char) Ed25519 seed`);
  }

  const now = Date.now();
  const claims = {
    sub: subject,
    team: opts?.team ?? null,
    perm: opts?.perm ?? null,
    iat: now,
    exp: now + TOKEN_TTL_MS,
    jti: crypto.randomUUID(),
  };

  const payloadB64 = base64url(new TextEncoder().encode(JSON.stringify(claims)));
  // Sign over the encoded first segment (avoids JSON canonicalisation ambiguity).
  const sig = await ed.signAsync(new TextEncoder().encode(payloadB64), seed);
  return `${payloadB64}.${base64url(sig)}`;
}

/**
 * Derive the hex public key for a given signing seed. Use this once at setup time
 * to obtain the value for the agent's `AEGIS_GATEWAY_CAP_PUBKEY`.
 *
 *   node -e "import('./capability.js').then(m => m.deriveCapabilityPubKeyHex(SEED).then(console.log))"
 */
export async function deriveCapabilityPubKeyHex(seedHex: string): Promise<string> {
  const pub = await ed.getPublicKeyAsync(hexToBytes(seedHex.trim()));
  return bytesToHex(pub);
}
