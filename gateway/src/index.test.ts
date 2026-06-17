import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import app from "./index";

// Mock ed25519 verify function to bypass signature check
vi.mock("@noble/ed25519", () => ({
  verify: () => Promise.resolve(true),
}));

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
  let originalFetch = globalThis.fetch;

  beforeEach(() => {
    // Stub global fetch to return mock responses for NEAR RPC and Shade Agent
    const mockFetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : (input as any).url || "";

      if (url.includes("rpc.testnet.near.org")) {
        if (init?.body) {
          const bodyObj = JSON.parse(init.body as string);
          const methodName = bodyObj?.params?.method_name;

          if (methodName === "get_team_member") {
            let permission = "read";
            try {
              const args = JSON.parse(atob(bodyObj.params.args_base64));
              if (args.account_id === "admin.near" || args.account_id === "alice.near") {
                permission = "admin";
              }
            } catch (e) {}

            return Promise.resolve(new Response(JSON.stringify({
              jsonrpc: "2.0",
              result: {
                permission
              },
              id: bodyObj.id || "team-permission-check"
            })));
          }

          if (methodName === "is_team_member") {
            return Promise.resolve(new Response(JSON.stringify({
              jsonrpc: "2.0",
              result: true, // User is a member
              id: bodyObj.id || "team-auth"
            })));
          }
        }

        // Fallback for view_access_keys
        return Promise.resolve(new Response(JSON.stringify({
          jsonrpc: "2.0",
          result: {
            keys: [
              { public_key: "ed25519:test-public-key" }
            ]
          }
        })));
      }

      if (url.includes("localhost:8080")) {
        // Mock Shade Agent endpoints
        if (url.includes("/vault/team/read")) {
          return Promise.resolve(new Response(JSON.stringify({
            content: "decrypted team vault content"
          })));
        }
        if (url.includes("/vault/team/write")) {
          return Promise.resolve(new Response(JSON.stringify({
            blobId: "CertfedBdBHashBase58Ab",
            contentSha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939"
          })));
        }
        return Promise.resolve(new Response(JSON.stringify({ success: true })));
      }

      return Promise.resolve(new Response(JSON.stringify({ success: true })));
    };
    vi.stubGlobal("fetch", mockFetch);
  });

  afterEach(() => {
    vi.stubGlobal("fetch", originalFetch);
  });

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
              blobId: "CertfedBdBHashBase58Ab",
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

  // ============================================================================
  // TEAM AUTHENTICATION TESTS
  // ============================================================================

  it("should generate a team challenge nonce and store it in CHALLENGES_KV", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();

    const res = await app.request(
      "/auth/team/challenge",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ teamId: "test-team" }),
      },
      { CHALLENGES_KV, SESSIONS_KV }
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as { nonce: string; teamId: string };
    expect(body.nonce).toBeDefined();
    expect(body.teamId).toBe("test-team");
    expect(typeof body.nonce).toBe("string");
    // Challenge should be Base64URL-encoded
    expect(body.nonce).toMatch(/^[a-zA-Z0-9_-]+$/);

    // Verify it was stored in KV with team-specific key
    const stored = await CHALLENGES_KV.get(`team_challenge:test-team:${body.nonce}`);
    expect(stored).toBe("unused");
  });

  it("should create a team session on /auth/team/unlock with valid signature", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();

    // Store a challenge first - must be 32 bytes base64url encoded
    const challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    await CHALLENGES_KV.put(`team_challenge:test-team:${challenge}`, "unused");

    const publicKey = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    const res = await app.request(
      "/auth/team/unlock",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          teamId: "test-team",
          nearAccountId: "alice.near",
          publicKey: publicKey,
          signature: signature,
          challenge: challenge
        }),
      },
      { CHALLENGES_KV, SESSIONS_KV }
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as { sessionId: string; expiresAt: number; teamId: string };
    expect(body.sessionId).toBeDefined();
    expect(body.teamId).toBe("test-team");
    expect(typeof body.expiresAt).toBe("number");

    // Verify team session was stored with fixed prefix format
    const sessionKey = `session:${body.sessionId}`;
    const storedSession = await SESSIONS_KV.get(sessionKey);
    expect(storedSession).toBeDefined();
    const sessionObj = JSON.parse(storedSession!);
    expect(sessionObj.teamId).toBe("test-team");
    expect(sessionObj.nearAccountId).toBe("alice.near");
  });

  it("should enforce team session checks on team tools/call", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();

    // Create a mock team session
    const teamSessionId = "team-session-uuid";
    const sessionObj = {
      teamId: "test-team",
      nearAccountId: "alice.near",
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600 * 1000,
    };
    await SESSIONS_KV.put(`session:${teamSessionId}`, JSON.stringify(sessionObj));

    // Test team vault read with valid team session
    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${teamSessionId}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "team_vault_read",
            arguments: {
              teamId: "test-team",
              slug: "test-doc"
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

    expect(res.status).toBe(200);
  });

  it("should enforce team permission requirements on write operations", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();

    // Create a mock team session with read-only permission
    const teamSessionId = "team-readonly-session";
    const sessionObj = {
      teamId: "test-team",
      nearAccountId: "readonly.near",
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600 * 1000,
    };
    await SESSIONS_KV.put(`session:${teamSessionId}`, JSON.stringify(sessionObj));

    // Try to write with read-only permission
    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${teamSessionId}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "team_vault_write",
            arguments: {
              teamId: "test-team",
              slug: "test-doc",
              content: "test content"
            },
          },
        }),
      },
      {
        CHALLENGES_KV,
        SESSIONS_KV,
        IRONCLAW_AGENT_API_KEY: "test-api-key",
        IRONCLAW_AGENT_BASE_URL: "http://localhost:8080"
      }
    );

    // Should fail with permission denied
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("TEAM_PERMISSION_DENIED");
  });

  it("should handle team member management operations", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();

    // Create a mock admin team session
    const adminSessionId = "admin-team-session";
    const sessionObj = {
      teamId: "test-team",
      nearAccountId: "admin.near",
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600 * 1000,
    };
    await SESSIONS_KV.put(`session:${adminSessionId}`, JSON.stringify(sessionObj));

    // Test team member addition
    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminSessionId}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "team_manage",
            arguments: {
              teamId: "test-team",
              action: "add",
              accountId: "newmember.near",
              permission: "write"
            },
          },
        }),
      },
      {
        CHALLENGES_KV,
        SESSIONS_KV,
        IRONCLAW_AGENT_API_KEY: "test-api-key",
        IRONCLAW_AGENT_BASE_URL: "http://localhost:8080"
      }
    );

    // Should succeed for admin
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: any };
    expect(body.result).toBeDefined();
  });
});
