import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { mintCapabilityToken, deriveCapabilityPubKeyHex } from "./capability.js";
import type { Env } from "./types.js";

// A fixed 32-byte seed (hex) used as the gateway signing key in these tests.
const SEED_HEX = "0".repeat(63) + "7"; // 32 bytes, deterministic

function envWith(seed?: string): Env {
  // Only the fields touched by capability minting matter here.
  return { AEGIS_CAP_SIGNING_KEY: seed } as unknown as Env;
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

describe("capability token minting", () => {
  it("returns empty string when no signing key is configured (legacy mode)", async () => {
    const token = await mintCapabilityToken(envWith(undefined), "alice.near");
    expect(token).toBe("");
  });

  it("mints a verifiable token whose signature checks against the gateway pubkey", async () => {
    const env = envWith(SEED_HEX);
    const token = await mintCapabilityToken(env, "alice.near");

    // Structure: payloadB64 "." sigB64
    const parts = token.split(".");
    expect(parts.length).toBe(2);
    const payloadB64 = parts[0]!;
    const sigB64 = parts[1]!;

    // Signature must verify over the ASCII bytes of the first segment.
    const pubHex = await deriveCapabilityPubKeyHex(SEED_HEX);
    const pub = Uint8Array.from(
      pubHex.match(/.{2}/g)!.map((h) => Number.parseInt(h, 16)),
    );
    const ok = await ed.verifyAsync(
      b64urlToBytes(sigB64),
      new TextEncoder().encode(payloadB64),
      pub,
    );
    expect(ok).toBe(true);
  });

  it("binds the requested subject and a fresh, future expiry", async () => {
    const env = envWith(SEED_HEX);
    const before = Date.now();
    const token = await mintCapabilityToken(env, "bob.near");
    const payloadB64 = token.split(".")[0]!;
    const claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64)));

    expect(claims.sub).toBe("bob.near");
    expect(claims.exp).toBeGreaterThan(before);
    expect(claims.exp).toBeGreaterThan(claims.iat);
    expect(typeof claims.jti).toBe("string");
    expect(claims.jti.length).toBeGreaterThan(0);
  });

  it("produces unique tokens (distinct nonces) on repeated calls", async () => {
    const env = envWith(SEED_HEX);
    const t1 = await mintCapabilityToken(env, "alice.near");
    const t2 = await mintCapabilityToken(env, "alice.near");
    expect(t1).not.toBe(t2);
  });

  it("rejects a signing key of the wrong length", async () => {
    const env = envWith("abcd"); // 2 bytes, not 32
    await expect(mintCapabilityToken(env, "alice.near")).rejects.toThrow();
  });
});
