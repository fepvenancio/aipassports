import crypto from 'crypto';
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema
} from "@modelcontextprotocol/sdk/types.js";
import { SessionManager } from "./SessionManager.js";
import { RateLimiter } from "./RateLimiter.js";
import { ExecuteToolUseCase } from "../../Application/UseCases/ExecuteToolUseCase.js";
import { BuiltinTools } from "../../Application/Constants/BuiltinTools.js";

/**
 * @title McpSseServer
 * @notice HTTP transport for the Sovereign AI Passport with per-session isolation.
 * @dev Each authenticated user gets their own Vault, MCP Server, and transport.
 *      Vault persistence uses VaultRepository with per-user DEK encryption.
 */

/* //////////////////////////////////////////////////////////////
                          MCP SSE SERVER
//////////////////////////////////////////////////////////////*/

export class McpSseServer {
  #app;
  #vaultRepository;
  #verifier;
  #skillExecutor;
  #sessionManager;

  /**
   * @param {IVaultRepository} vaultRepository - Repository for loading/saving vaults per user (uses DEK).
   * @param {IIdentityVerifier} verifier - Identity validation port.
   * @param {SkillExecutor} skillExecutor - LLM-backed skill executor.
   * @param {object} [options]
   * @param {number} [options.sessionTtlMs=3600000] - Session TTL (default 1 hour).
   * @param {number} [options.maxSessions=1024] - Maximum concurrent sessions.
   * @param {string[]} [options.corsOrigins=[]] - Allowed CORS origins.
   */
  constructor(vaultRepository, verifier, skillExecutor, options = {}) {
    this.#vaultRepository = vaultRepository;
    this.#verifier = verifier;
    this.#skillExecutor = skillExecutor;

    this.#sessionManager = new SessionManager({
      ttlMs: options.sessionTtlMs,
      maxSessions: options.maxSessions,
      onExpired: (session) => {
        console.error(`[SESSION_EXPIRED] ${session.ownerId}`);
      },
    });

    const unlockLimiter = new RateLimiter({ maxRequests: 5, windowMs: 60_000 });
    const messageLimiter = new RateLimiter({ maxRequests: 100, windowMs: 60_000 });

    this.#app = express();
    this.#app.set('trust proxy', 1);
    this.#app.use(express.json({ limit: '100kb' }));

    // CORS
    const allowedOrigins = options.corsOrigins ?? [];
    if (allowedOrigins.length > 0) {
      this.#app.use((req, res, next) => {
        const origin = req.headers.origin;
        if (allowedOrigins.includes(origin)) {
          res.setHeader('Access-Control-Allow-Origin', origin);
          res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
          res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-session-id');
          res.setHeader('Access-Control-Max-Age', '86400');
        }
        if (req.method === 'OPTIONS') {
          return res.sendStatus(204);
        }
        next();
      });
    }

    // Security headers
    this.#app.use((req, res, next) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Cache-Control', 'no-store');
      next();
    });

    this._setupRoutes(unlockLimiter, messageLimiter);
  }

  /* //////////////////////////////////////////////////////////////
                          REST ROUTES
  //////////////////////////////////////////////////////////////*/

  _setupRoutes(unlockLimiter, messageLimiter) {
    /**
     * @notice Identity Challenge Route.
     * Generates a cryptographic challenge for WebAuthn/Passkey ceremonies.
     */
    this.#app.post("/auth/challenge", (req, res) => {
      const challenge = crypto.randomBytes(32).toString('base64url');
      res.status(200).json({ challenge, timeout: 60000 });
    });

    /**
     * @notice Identity Unlock Route (FR-4.2).
     * Validates JWT assertion, loads user vault, creates session.
     */
    this.#app.post("/auth/unlock", unlockLimiter.middleware(), async (req, res) => {
      try {
        const { token, publicKey } = req.body;

        if (!token || !publicKey) {
          return res.status(400).json({ error: "MISSING_CREDENTIALS" });
        }

        const isValid = await this.#verifier.verifyAssertion(token, publicKey);

        if (!isValid) {
          return res.status(401).json({ error: "UNAUTHORIZED_IDENTITY_ASSERTION_FAILED" });
        }

        // Generate ownerId securely from the public key hash as per Domain invariants
        // (This prevents an attacker from supplying an arbitrary JWT payload
        //  while using their own public key to pass signature verification)
        const ownerId = crypto.createHash('sha256').update(publicKey).digest('hex');

        if (!ownerId) {
          return res.status(401).json({ error: "INVALID_TOKEN: could not derive identity from public key" });
        }

        // Load or create the user's vault
        const vault = await this.#vaultRepository.load(ownerId);
        const sessionId = this.#sessionManager.create(ownerId, vault);

        // Persist vault state on unlock
        await this.#vaultRepository.save(ownerId, vault.toJSON());

        res.status(200).json({ status: "UNLOCKED", vaultId: ownerId, sessionId });
      } catch (error) {
        console.error("[AUTH_ERROR]", error.message);
        res.status(500).json({ error: "INTERNAL_AUTH_ERROR" });
      }
    });

    /**
     * @notice SSE Connection Endpoint.
     */
    this.#app.get("/mcp/sse", async (req, res) => {
      const sessionId = req.headers['x-session-id'];
      const session = this.#sessionManager.get(sessionId);

      if (!session) {
        return res.status(401).json({ error: "UNAUTHORIZED_IDENTITY_ASSERTION_REQUIRED" });
      }

      try {
        const mcpServer = new Server(
          { name: "ai-passport-server", version: "2.0.0" },
          { capabilities: { tools: {}, resources: {} } }
        );

        const executeToolUseCase = new ExecuteToolUseCase(this.#skillExecutor);
        this._registerMcpHandlers(mcpServer, session.vault, executeToolUseCase);

        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => sessionId,
        });

        await mcpServer.connect(transport);

        session.server = mcpServer;
        session.transport = transport;

        console.error(`[SESSION_CONNECTED] owner=${session.ownerId}`);

        res.on('close', () => {
          console.error(`[SESSION_DISCONNECTED] owner=${session.ownerId}`);
        });

        await transport.handleRequest(req, res);
      } catch (error) {
        console.error("[SSE_CONNECT_ERROR]", error.message);
        if (!res.headersSent) {
          res.status(500).json({ error: "TRANSPORT_SETUP_FAILED" });
        }
      }
    });

    /**
     * @notice MCP Message Endpoint.
     */
    this.#app.post("/mcp/messages", messageLimiter.middleware(), async (req, res) => {
      const sessionId = req.headers['x-session-id'] ?? req.body?.session_id;
      const session = this.#sessionManager.get(sessionId);

      if (!session || !session.transport) {
        return res.status(401).json({ error: "UNAUTHORIZED_IDENTITY_ASSERTION_REQUIRED" });
      }

      try {
        await session.transport.handleRequest(req, res);
      } catch (error) {
        console.error("[MCP_MESSAGE_ERROR]", error.message);
        if (!res.headersSent) {
          res.status(500).json({ error: "MESSAGE_PROCESSING_FAILED" });
        }
      }
    });

    /**
     * @notice Health check endpoint.
     */
    this.#app.get("/health", (req, res) => {
      res.status(200).json({
        status: "ok",
        sessions: this.#sessionManager.size,
        uptime: process.uptime(),
      });
    });
  }

  /* //////////////////////////////////////////////////////////////
                          MCP HANDLERS
  //////////////////////////////////////////////////////////////*/

  _registerMcpHandlers(mcpServer, vault, executeToolUseCase) {
    mcpServer.setRequestHandler(ListToolsRequestSchema, async () => {
      const userSkills = vault.skills.map(skill => ({
        name: skill.id,
        description: skill.description,
        inputSchema: skill.schema
      }));
      return { tools: [...BuiltinTools, ...userSkills] };
    });

    mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const result = await executeToolUseCase.execute(vault, name, args || {});

        // Persist vault state after mutations via VaultRepository (per-user DEK)
        if (name.startsWith('wiki/') || name.startsWith('skill/')) {
          await this.#vaultRepository.save(vault.ownerId, vault.toJSON());
        }

        return {
          content: [{ type: "text", text: typeof result.result === 'string' ? result.result : JSON.stringify(result) }]
        };
      } catch (error) {
        return {
          content: [{ type: "text", text: error.message }],
          isError: true
        };
      }
    });

    mcpServer.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: vault.wikiPages.map(page => ({
        uri: `wiki://${page.slug}`,
        name: page.slug,
        mimeType: "text/markdown",
        description: `Sovereign knowledge entry: ${page.slug}`
      }))
    }));

    mcpServer.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      try {
        const uri = new URL(request.params.uri);
        if (uri.protocol !== 'wiki:') {
          return { contents: [] };
        }

        const slug = uri.hostname || uri.pathname.replace(/^\/\//, '');
        const page = vault.wikiPages.find(p => p.slug === slug);

        if (!page) {
          return { contents: [] };
        }

        return {
          contents: [{
            uri: request.params.uri,
            mimeType: "text/markdown",
            text: page.content
          }]
        };
      } catch {
        return { contents: [] };
      }
    });
  }

  /* //////////////////////////////////////////////////////////////
                            LIFECYCLE
  //////////////////////////////////////////////////////////////*/

  async start(port = 8080) {
    return new Promise((resolve) => {
      this.#app.listen(port, () => {
        console.error(`🚀 Streamable HTTP Gateway live at http://localhost:${port}`);
        resolve();
      });
    });
  }

  shutdown() {
    this.#sessionManager.shutdown();
  }
}