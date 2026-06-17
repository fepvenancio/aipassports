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

class MockD1Database {
  users: Array<{
    near_account_id: string;
    api_key: string;
    tee_endpoint: string;
    subscription_status?: string;
    storage_used_bytes?: number;
    storage_limit_bytes?: number;
  }> = [];
  firewall_logs: Array<{
    near_account_id: string;
    timestamp: number;
    skill_name: string;
    destination: string;
    rule_triggered: string;
    marker_detected: string | null;
  }> = [];

  prepare(query: string) {
    const self = this;
    return {
      bind(...args: any[]) {
        return {
          async first() {
            const param = args[0];
            if (query.includes("WHERE api_key = ?")) {
              const user = self.users.find(u => u.api_key === param);
              return user ? { near_account_id: user.near_account_id } : null;
            }
            if (query.includes("WHERE near_account_id = ?")) {
              const user = self.users.find(u => u.near_account_id === param);
              return user ? {
                near_account_id: user.near_account_id,
                api_key: user.api_key,
                tee_endpoint: user.tee_endpoint,
                subscription_status: user.subscription_status || "free",
                storage_used_bytes: user.storage_used_bytes || 0,
                storage_limit_bytes: user.storage_limit_bytes || 10485760
              } : null;
            }
            return null;
          },
          async run() {
            if (query.includes("INSERT INTO firewall_audit_logs")) {
              self.firewall_logs.push({
                near_account_id: args[0],
                timestamp: args[1],
                skill_name: args[2],
                destination: args[3],
                rule_triggered: args[4],
                marker_detected: args[5] ?? null
              });
              return { success: true };
            }
            if (query.includes("INSERT INTO users")) {
              self.users.push({
                near_account_id: args[0],
                api_key: args[1],
                tee_endpoint: args[2],
                subscription_status: "free",
                storage_used_bytes: 0,
                storage_limit_bytes: 10485760
              });
              return { success: true };
            }
            if (query.includes("UPDATE users SET subscription_status = ?")) {
              const user = self.users.find(u => u.near_account_id === args[2]);
              if (user) {
                user.subscription_status = args[0];
                user.storage_limit_bytes = args[1];
              }
              return { success: true };
            }
            if (query.includes("UPDATE users SET api_key = ?")) {
              const user = self.users.find(u => u.near_account_id === args[1]);
              if (user) {
                user.api_key = args[0];
              }
              return { success: true };
            }
            if (query.includes("storage_used_bytes = storage_used_bytes + ?")) {
              const user = self.users.find(u => u.near_account_id === args[1]);
              if (user) {
                user.storage_used_bytes = (user.storage_used_bytes || 0) + args[0];
              }
              return { success: true };
            }
            return { success: true };
          }
        };
      }
    };
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
        if (url.includes("/health")) {
          return Promise.resolve(new Response(JSON.stringify({
            success: true,
            status: "healthy"
          })));
        }
        if (url.includes("/attest")) {
          return Promise.resolve(new Response(JSON.stringify({
            success: true,
            error_code: "",
            attestation_status: "TEE_NOT_DETECTED",
            tee_platform: "Unknown",
            message: "Simulated TDX Quote",
            tdx_quote: "SGVsbG8gRnJvbSBBYWdpcyBURUU="
          })));
        }
        if (url.includes("/skills/execute")) {
          // If the prompt contains "leak_marker", mock a firewall block response
          if (init?.body && JSON.parse(init.body as string).prompt?.includes("leak_marker")) {
            return Promise.resolve(new Response(
              JSON.stringify({
                errorCode: "FIREWALL_ERROR_SENSITIVE_CONTENT",
                message: "Egress blocked: prompt contained sensitive word: PRIVATE_KEY"
              }),
              { status: 403 }
            ));
          }
          return Promise.resolve(new Response(JSON.stringify({ success: true, response: "AI result" })));
        }
        return Promise.resolve(new Response(JSON.stringify({ success: true, blobId: "TestBlobId123", contentSha256: "abcdef1234567890", blobSizeBytes: 1024 })));
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

  it("should authenticate a request using a long-lived API key from the D1 database", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();
    const DB = new MockD1Database();
    
    // Provision a user with an API key
    DB.users.push({
      near_account_id: "alice.near",
      api_key: "ak_alice_123456",
      tee_endpoint: "http://localhost:8080"
    });

    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer ak_alice_123456",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
        }),
      },
      {
        CHALLENGES_KV,
        SESSIONS_KV,
        DB,
        IRONCLAW_AGENT_API_KEY: "test-api-key",
        IRONCLAW_AGENT_BASE_URL: "http://localhost:8080"
      }
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: any };
    expect(body.result.tools).toBeDefined();
  });

  it("should dynamically route MCP calls to the user's specific TEE endpoint from the D1 database", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();
    const DB = new MockD1Database();
    
    // Provision a user with a custom TEE agent endpoint URL
    const customUserTeeEndpoint = "http://alice-tee.near.ai";
    DB.users.push({
      near_account_id: "alice.near",
      api_key: "ak_alice_123456",
      tee_endpoint: customUserTeeEndpoint
    });

    // We'll stub fetch to intercept requests to http://alice-tee.near.ai/vault/write
    let routedUrl = "";
    const mockRoutedFetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : (input as any).url || "";
      if (url.includes("alice-tee.near.ai")) {
        routedUrl = url;
        return Promise.resolve(new Response(JSON.stringify({
          blobId: "CertfedBdBHashBase58Ab",
          contentSha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939"
        })));
      }
      return Promise.resolve(new Response(JSON.stringify({ success: true })));
    };
    vi.stubGlobal("fetch", mockRoutedFetch);

    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer ak_alice_123456",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "vault_write",
            arguments: {
              nearAccountId: "alice.near",
              plaintext: "secret data"
            }
          }
        }),
      },
      {
        CHALLENGES_KV,
        SESSIONS_KV,
        DB,
        IRONCLAW_AGENT_API_KEY: "test-api-key",
        IRONCLAW_AGENT_BASE_URL: "http://localhost:8080"
      }
    );

    expect(res.status).toBe(200);
    expect(routedUrl).toContain("http://alice-tee.near.ai/vault/write");
  });

  it("should query and return TEE attestation details during agent_health check", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();
    const DB = new MockD1Database();

    DB.users.push({
      near_account_id: "alice.near",
      api_key: "ak_alice_123456",
      tee_endpoint: "http://localhost:8080"
    });

    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer ak_alice_123456",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "agent_health",
            arguments: {}
          }
        }),
      },
      {
        CHALLENGES_KV,
        SESSIONS_KV,
        DB,
        IRONCLAW_AGENT_API_KEY: "test-api-key",
        IRONCLAW_AGENT_BASE_URL: "http://localhost:8080"
      }
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.result.content[0].text).toBeDefined();
    
    const healthResult = JSON.parse(body.result.content[0].text);
    expect(healthResult.healthy).toBe(true);
    expect(healthResult.attestation).toBeDefined();
    expect(healthResult.attestation.success).toBe(true);
    expect(healthResult.attestation.status).toBe("TEE_NOT_DETECTED");
    expect(healthResult.attestation.quote).toBe("SGVsbG8gRnJvbSBBYWdpcyBURUU=");
  });

  it("should write a log to D1 when a skill execution is blocked by the ZDR firewall", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();
    const DB = new MockD1Database();

    DB.users.push({
      near_account_id: "alice.near",
      api_key: "ak_alice_123456",
      tee_endpoint: "http://localhost:8080"
    });

    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer ak_alice_123456",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "zdr_check",
            arguments: {
              nearAccountId: "alice.near",
              skillName: "chat_helper",
              prompt: "here is my leak_marker",
              destination: "https://api.openai.com/v1/chat/completions"
            }
          }
        }),
      },
      {
        CHALLENGES_KV,
        SESSIONS_KV,
        DB,
        IRONCLAW_AGENT_API_KEY: "test-api-key",
        IRONCLAW_AGENT_BASE_URL: "http://localhost:8080"
      }
    );

    // Should return 200/OK containing the structured firewallBlock error, or return isError in the tool call response
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    const toolResult = JSON.parse(body.result.content[0].text);
    expect(toolResult.success).toBe(false);
    expect(toolResult.firewallBlock).toBe(true);

    // Verify D1 has recorded the block
    expect(DB.firewall_logs.length).toBe(1);
    expect(DB.firewall_logs[0]!.near_account_id).toBe("alice.near");
    expect(DB.firewall_logs[0]!.skill_name).toBe("chat_helper");
    expect(DB.firewall_logs[0]!.rule_triggered).toBe("SENSITIVE_CONTENT_BLOCKED");
    expect(DB.firewall_logs[0]!.marker_detected).toBe("PRIVATE_KEY");
  });

  it("should handle user registration and profile lookup on the control plane", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();
    const DB = new MockD1Database();

    // Create a mock active session for "alice.near"
    const sessionId = "test-session-uuid";
    const sessionObj = {
      nearAccountId: "alice.near",
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600 * 1000,
    };
    await SESSIONS_KV.put(`session:${sessionId}`, JSON.stringify(sessionObj));

    // 1. Get profile - should return 404 USER_NOT_REGISTERED
    const resGet1 = await app.request(
      "/api/user",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${sessionId}`,
        },
      },
      { CHALLENGES_KV, SESSIONS_KV, DB }
    );
    expect(resGet1.status).toBe(404);
    const get1Body = await resGet1.json() as any;
    expect(get1Body.error).toBe("USER_NOT_REGISTERED");

    // 2. Register - should return 200 OK with new API key
    const resReg = await app.request(
      "/api/register",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${sessionId}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          teeEndpoint: "https://alice-tee.near.ai"
        })
      },
      { CHALLENGES_KV, SESSIONS_KV, DB }
    );
    expect(resReg.status).toBe(200);
    const regBody = await resReg.json() as any;
    expect(regBody.success).toBe(true);
    expect(regBody.apiKey).toContain("ak_aegis_");
    expect(regBody.subscriptionStatus).toBe("free");
    expect(regBody.teeEndpoint).toBe("https://alice-tee.near.ai");

    // Verify D1 row exists
    expect(DB.users.length).toBe(1);
    expect(DB.users[0]!.near_account_id).toBe("alice.near");
    expect(DB.users[0]!.api_key).toBe(regBody.apiKey);

    // 3. Get profile again - should return 200 OK
    const resGet2 = await app.request(
      "/api/user",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${sessionId}`,
        },
      },
      { CHALLENGES_KV, SESSIONS_KV, DB }
    );
    expect(resGet2.status).toBe(200);
    const get2Body = await resGet2.json() as any;
    expect(get2Body.success).toBe(true);
    expect(get2Body.nearAccountId).toBe("alice.near");
    expect(get2Body.apiKey).toBe(regBody.apiKey);
  });

  it("should handle billing upgrades and API key regeneration", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();
    const DB = new MockD1Database();

    const sessionId = "test-session-uuid";
    const sessionObj = {
      nearAccountId: "alice.near",
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600 * 1000,
    };
    await SESSIONS_KV.put(`session:${sessionId}`, JSON.stringify(sessionObj));

    // Register user first
    DB.users.push({
      near_account_id: "alice.near",
      api_key: "ak_old_key",
      tee_endpoint: "https://alice-tee.near.ai"
    });

    // 1. Upgrade subscription to developer tier
    const resSub = await app.request(
      "/api/billing/subscribe",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${sessionId}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          tier: "developer"
        })
      },
      { CHALLENGES_KV, SESSIONS_KV, DB }
    );
    expect(resSub.status).toBe(200);
    const subBody = await resSub.json() as any;
    expect(subBody.success).toBe(true);
    expect(subBody.subscriptionStatus).toBe("developer");
    expect(subBody.storageLimitBytes).toBe(524288000);

    // 2. Regenerate API key
    const resKey = await app.request(
      "/api/keys/generate",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${sessionId}`,
        },
      },
      { CHALLENGES_KV, SESSIONS_KV, DB }
    );
    expect(resKey.status).toBe(200);
    const keyBody = await resKey.json() as any;
    expect(keyBody.apiKey).toContain("ak_aegis_");
    expect(keyBody.apiKey).not.toBe("ak_old_key");
  });

  it("should block vault_write when storage quota is exceeded", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();
    const DB = new MockD1Database();

    // Create a user with exhausted storage (10MB used of 10MB limit)
    DB.users.push({
      near_account_id: "alice.near",
      api_key: "ak_test",
      tee_endpoint: "http://localhost:8080",
      subscription_status: "free",
      storage_used_bytes: 10485760, // 10MB — exactly at limit
      storage_limit_bytes: 10485760,
    });

    // Create session
    const sessionId = "quota-test-session";
    await SESSIONS_KV.put(
      `session:${sessionId}`,
      JSON.stringify({
        nearAccountId: "alice.near",
        createdAt: Date.now(),
        expiresAt: Date.now() + 3600000,
      })
    );

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
          id: "quota-1",
          method: "tools/call",
          params: {
            name: "vault_write",
            arguments: {
              nearAccountId: "alice.near",
              entryType: "wiki",
              identifier: "test",
              plaintext: "hello",
            },
          },
        }),
      },
      {
        CHALLENGES_KV,
        SESSIONS_KV,
        DB,
        IRONCLAW_AGENT_API_KEY: "test",
        IRONCLAW_AGENT_BASE_URL: "http://localhost:8080",
      }
    );

    expect(res.status).toBe(403);
    const body = (await res.json()) as any;
    expect(body.error.message).toContain("QUOTA_EXCEEDED");
  });

  it("should allow vault_write and increment storage when under quota", async () => {
    const CHALLENGES_KV = new MemoryKV();
    const SESSIONS_KV = new MemoryKV();
    const DB = new MockD1Database();

    // Create a user with room to write (5MB used of 10MB limit)
    DB.users.push({
      near_account_id: "alice.near",
      api_key: "ak_test",
      tee_endpoint: "http://localhost:8080",
      subscription_status: "free",
      storage_used_bytes: 5242880, // 5MB
      storage_limit_bytes: 10485760, // 10MB
    });

    // Create session
    const sessionId = "meter-test-session";
    await SESSIONS_KV.put(
      `session:${sessionId}`,
      JSON.stringify({
        nearAccountId: "alice.near",
        createdAt: Date.now(),
        expiresAt: Date.now() + 3600000,
      })
    );

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
          id: "meter-1",
          method: "tools/call",
          params: {
            name: "vault_write",
            arguments: {
              nearAccountId: "alice.near",
              entryType: "wiki",
              identifier: "test",
              plaintext: "hello world",
            },
          },
        }),
      },
      {
        CHALLENGES_KV,
        SESSIONS_KV,
        DB,
        IRONCLAW_AGENT_API_KEY: "test",
        IRONCLAW_AGENT_BASE_URL: "http://localhost:8080",
      }
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.result).toBeDefined();

    // Verify storage usage was incremented
    const user = DB.users.find(u => u.near_account_id === "alice.near");
    expect(user).toBeDefined();
    // The mock agent returns blobSizeBytes: 1024
    expect(user!.storage_used_bytes).toBe(5242880 + 1024);
  });
});
