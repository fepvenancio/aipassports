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

/**
 * @title McpSseServer
 * @notice HTTP transport for the Sovereign AI Passport with per-session isolation.
 * @dev Each authenticated user gets their own Vault, MCP Server, and transport.
 */

/* //////////////////////////////////////////////////////////////
                          MCP SSE SERVER
//////////////////////////////////////////////////////////////*/

export class McpSseServer {
  #app;
  #vaultRepository;
  #verifier;
  #syncService;
  #proxyClient;
  #sessionManager;

  /**
   * @param {IVaultRepository} vaultRepository - Repository for loading/saving vaults per user.
   * @param {IIdentityVerifier} verifier - Identity validation port.
   * @param {SyncService} syncService - The sync orchestrator.
   * @param {IOutboundProxy} proxyClient - The security firewall proxy.
   * @param {object} [options]
   * @param {number} [options.sessionTtlMs=3600000] - Session TTL (default 1 hour).
   * @param {number} [options.maxSessions=1024] - Maximum concurrent sessions.
   * @param {string[]} [options.corsOrigins=[]] - Allowed CORS origins.
   */
  constructor(vaultRepository, verifier, syncService, proxyClient, options = {}) {
    this.#vaultRepository = vaultRepository;
    this.#verifier = verifier;
    this.#syncService = syncService;
    this.#proxyClient = proxyClient;

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

    this._setupRoutes();
  }

  /* //////////////////////////////////////////////////////////////
                          REST ROUTES
  //////////////////////////////////////////////////////////////*/

  _setupRoutes() {
    /**
     * @notice Identity Challenge Route.
     * Generates a short-lived cryptographic challenge for WebAuthn.
     */
    this.#app.post("/auth/challenge", (req, res) => {
      // In production, this would be stored in a temporary cache (Redis/Memcached)
      const challenge = crypto.randomBytes(32).toString('base64');
      res.status(200).json({
        challenge,
        userPublicKeyId: "mock-public-key-id",
        timeout: 60000
      });
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

        // Extract ownerId from JWT payload
        const [, payloadB64] = token.split('.');
        let ownerId;
        try {
          const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
          ownerId = payload.sub ?? payload.iss ?? 'unknown';
        } catch {
          ownerId = 'unknown';
        }

        // Load or create the user's vault
        const vault = await this.#vaultRepository.load(ownerId);
        const sessionId = this.#sessionManager.create(ownerId, vault);

        // Trigger immediate sync on unlock
        this.#syncService.immediateSync(ownerId, vault.toJSON());

        res.status(200).json({ status: "UNLOCKED", vaultId: ownerId, sessionId });
      } catch (error) {
        console.error("[AUTH_ERROR]", error.message);
        res.status(500).json({ error: "INTERNAL_AUTH_ERROR" });
      }
    });

    /**
     * @notice SSE Connection Endpoint.
     * Creates per-session MCP server and streamable HTTP transport.
     */
    this.#app.get("/mcp/sse", async (req, res) => {
      const sessionId = req.headers['x-session-id'];
      const session = this.#sessionManager.get(sessionId);

      if (!session) {
        return res.status(401).json({ error: "UNAUTHORIZED_IDENTITY_ASSERTION_REQUIRED" });
      }

      try {
        // Create a dedicated MCP server for this session
        const mcpServer = new Server(
          { name: "ai-passport-server", version: "1.0.0" },
          { capabilities: { tools: {}, resources: {} } }
        );

        this._registerMcpHandlers(mcpServer, session.vault);

        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => sessionId,
        });

        await mcpServer.connect(transport);

        // Store server and transport in session
        session.server = mcpServer;
        session.transport = transport;

        console.error(`[SSE_SESSION_CONNECTED] owner=${session.ownerId} session=${sessionId}`);

        // Handle connection close
        res.on('close', () => {
          console.error(`[SSE_SESSION_DISCONNECTED] owner=${session.ownerId} session=${sessionId}`);
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
     * Routes JSON-RPC frames to the session's dedicated server.
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

  /**
   * @notice Registers MCP request handlers for a specific session's vault.
   * @param {Server} mcpServer - The MCP server instance.
   * @param {Vault} vault - The user's vault aggregate.
   */
  _registerMcpHandlers(mcpServer, vault) {
    mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: vault.skills.map(skill => ({
        name: skill.id,
        description: skill.description,
        inputSchema: skill.schema
      }))
    }));

    mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      const skill = vault.skills.find(s => s.id === name);

      if (!skill) {
        return {
          content: [{ type: "text", text: `ERROR: Skill not found: ${name}` }],
          isError: true
        };
      }

      return {
        content: [{
          type: "text",
          text: `SUCCESS: Invoked ${skill.name}. Execution would happen in a live TEE.`
        }]
      };
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
          return {
            contents: []
          };
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

  /**
   * @notice Boots the Express server on the specified port.
   * @param {number} port
   */
  async start(port = 8080) {
    return new Promise((resolve) => {
      this.#app.listen(port, () => {
        console.error(`🚀 Streamable HTTP Gateway live at http://localhost:${port}`);
        resolve();
      });
    });
  }

  /**
   * @notice Gracefully shuts down the server and all sessions.
   */
  shutdown() {
    this.#sessionManager.shutdown();
    unlockLimiter.destroy();
    messageLimiter.destroy();
  }
}