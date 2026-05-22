import { describe, it, expect } from "vitest";
import app from "./index";

class MemoryKV {
  store = new Map<string, string>();
  async get(key: string) {
    return this.store.get(key) || null;
  }
  async put(key: string, value: string) {
    this.store.set(key, value);
  }
  async delete(key: string) {
    this.store.delete(key);
  }
}

describe("Worker Gateway Bridge - Security & Routing Tests", () => {
  it("should generate a challenge nonce and store it in CHALLENGES_KV", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();

    const res = await app.request(
      "/auth/challenge",
      {
        method: "POST",
      },
      { CHALLENGES_KV, SESSIONS_KV }
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as { nonce: string };
    expect(body.nonce).toBeDefined();
    expect(typeof body.nonce).toBe("string");
    // Challenge should be Base64URL-encoded (no trailing padding, only valid chars)
    expect(body.nonce).toMatch(/^[a-zA-Z0-9_-]+$/);

    // Verify it was stored in KV
    const stored = await CHALLENGES_KV.get(`challenge:${body.nonce}`);
    expect(stored).toBe("unused");
  });

  it("should enforce session checks on tools/list and reject when no session is provided", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();

    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
        }),
      },
      { CHALLENGES_KV, SESSIONS_KV }
    );

    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toBe("SESSION_MISSING");
  });

  it("should enforce cross-user tenant isolation on tools/call", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();

    // Create a mock active session for "alice.near"
    const sessionId = "test-session-uuid";
    const sessionObj = {
      nearAccountId: "alice.near",
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600 * 1000,
    };
    await SESSIONS_KV.put(`session:${sessionId}`, JSON.stringify(sessionObj));

    // Attempt to invoke a tool for "bob.near" using alice's session token
    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${sessionId}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: "vault_read",
            arguments: {
              nearAccountId: "bob.near", // Tenant boundary cross attempt!
              blobId: "blob123",
              expectedSha256: "a".repeat(64),
            },
          },
        }),
      },
      {
        CHALLENGES_KV,
        SESSIONS_KV,
        IRONCLAW_AGENT_API_KEY: "test-api-key",
        IRONCLAW_AGENT_BASE_URL: "http://localhost:8080",
      }
    );

    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("Unauthorized: nearAccountId in arguments");
  });

  it("should clear the session on /auth/logout", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();

    const sessionId = "logout-session-uuid";
    await SESSIONS_KV.put(
      `session:${sessionId}`,
      JSON.stringify({
        nearAccountId: "alice.near",
        expiresAt: Date.now() + 3600 * 1000,
      })
    );

    const res = await app.request(
      "/auth/logout",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${sessionId}`,
        },
      },
      { CHALLENGES_KV, SESSIONS_KV }
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);

    // Verify it was deleted from KV
    const stored = await SESSIONS_KV.get(`session:${sessionId}`);
    expect(stored).toBeNull();
  });
});
