import crypto from 'crypto';
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { 
  ListToolsRequestSchema, 
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema
} from "@modelcontextprotocol/sdk/types.js";

/**
 * @title McpSseServer
 * @notice HTTP/SSE transport for the Sovereign AI Passport.
 * @dev Implements passwordless JWT assertion unlocking and SSE streaming.
 */

/* //////////////////////////////////////////////////////////////
                          MCP SSE SERVER
//////////////////////////////////////////////////////////////*/

export class McpSseServer {
  #app;
  #server;
  #vault;
  #verifier;
  #syncService;
  #proxyClient;
  #sessions;

  /**
   * @param {Vault} vault - The domain aggregate.
   * @param {IIdentityVerifier} verifier - Identity validation port.
   * @param {SyncService} syncService - The sync orchestrator.
   * @param {IOutboundProxy} proxyClient - The security firewall proxy.
   */
  constructor(vault, verifier, syncService, proxyClient) {
    this.#vault = vault;
    this.#verifier = verifier;
    this.#syncService = syncService;
    this.#proxyClient = proxyClient;
    this.#sessions = new Map(); // sessionId -> { transport, authenticated }
    this.#app = express();
    this.#app.use(express.json());

    this.#server = new Server(
      { name: "ai-passport-sse-server", version: "1.0.0" },
      { capabilities: { tools: {}, resources: {} } }
    );

    this._setupMcpHandlers();
    this._setupRoutes();
  }

  /* //////////////////////////////////////////////////////////////
                          MCP LOGIC
  //////////////////////////////////////////////////////////////*/

  _setupMcpHandlers() {
    this.#server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.#vault.skills.map(skill => ({
        name: skill.id,
        description: skill.description,
        inputSchema: skill.schema
      }))
    }));

    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => {
      return { content: [{ type: "text", text: `SSE execution of ${request.params.name}` }] };
    });

    this.#server.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: this.#vault.wikiPages.map(page => ({
        uri: `wiki://${page.slug}`,
        name: page.slug,
        mimeType: "text/markdown"
      }))
    }));
  }

  /* //////////////////////////////////////////////////////////////
                        AUTH MIDDLEWARE
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Express middleware enforcing identity verification on protected routes.
   * @dev Rejects requests that lack a valid session with authentication.
   */
  _requireAuth(req, res, next) {
    const sessionId = req.headers['x-session-id'];
    const session = this.#sessions.get(sessionId);

    if (!sessionId || !session || !session.authenticated) {
      return res.status(401).json({ error: "UNAUTHORIZED_IDENTITY_ASSERTION_REQUIRED" });
    }

    next();
  }

  /* //////////////////////////////////////////////////////////////
                          REST ROUTES
  //////////////////////////////////////////////////////////////*/

  _setupRoutes() {
    /**
     * @notice Identity Unlock Route (FR-4.2).
     * Validates Passkey-derived JWT assertion before allowing transport hydration.
     * Returns a session ID that must be used for subsequent requests.
     */
    this.#app.post("/auth/unlock", async (req, res) => {
      try {
        const { token, publicKey } = req.body;

        if (!token || !publicKey) {
          return res.status(400).json({ error: "MISSING_CREDENTIALS" });
        }

        const isValid = await this.#verifier.verifyAssertion(token, publicKey);

        if (isValid) {
          const sessionId = crypto.randomUUID();
          this.#sessions.set(sessionId, { authenticated: true, createdAt: Date.now() });

          // Trigger immediate sync on unlock
          this.#syncService.immediateSync(this.#vault.ownerId, this.#vault.toJSON());

          res.status(200).json({ status: "UNLOCKED", vaultId: this.#vault.ownerId, sessionId });
        } else {
          res.status(401).json({ error: "UNAUTHORIZED_IDENTITY_ASSERTION_FAILED" });
        }
      } catch (error) {
        console.error("[AUTH_ERROR]", error.message);
        res.status(500).json({ error: "INTERNAL_AUTH_ERROR" });
      }
    });

    /**
     * @notice SSE Connection Endpoint.
     * Establishes the persistent event stream. Requires prior authentication.
     */
    this.#app.get("/mcp/sse", async (req, res) => {
      const sessionId = req.headers['x-session-id'];
      const session = this.#sessions.get(sessionId);

      if (!sessionId || !session || !session.authenticated) {
        return res.status(401).json({ error: "UNAUTHORIZED_IDENTITY_ASSERTION_REQUIRED" });
      }

      console.error("[SSE_CONNECTION_INITIATED]", sessionId);
      const transport = new SSEServerTransport("/mcp/messages", res);
      this.#sessions.get(sessionId).transport = transport;

      try {
        await this.#server.connect(transport);
      } catch (error) {
        console.error("[SSE_CONNECT_ERROR]", error.message);
      }
    });

    /**
     * @notice MCP Message Endpoint.
     * Receives JSON-RPC frames to be processed by the server.
     */
    this.#app.post("/mcp/messages", async (req, res) => {
      const sessionId = req.headers['x-session-id'];
      const session = this.#sessions.get(sessionId);

      if (!sessionId || !session || !session.authenticated || !session.transport) {
        return res.status(401).json({ error: "UNAUTHORIZED_IDENTITY_ASSERTION_REQUIRED" });
      }

      await session.transport.handlePostMessage(req, res);
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
    this.#app.listen(port, () => {
      console.error(`🚀 SSE Gateway live at http://localhost:${port}`);
    });
  }
}