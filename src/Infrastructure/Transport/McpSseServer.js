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
 * @dev Implements passwordless WebAuthn unlocking and SSE streaming.
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
  #transport;
  #isLocked;

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
    this.#isLocked = true; // MUST be locked by default
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
    this.#server.setRequestHandler(ListToolsRequestSchema, async () => {
      this._checkLock();
      return {
        tools: this.#vault.skills.map(skill => ({
          name: skill.id,
          description: skill.description,
          inputSchema: skill.schema
        }))
      };
    });

    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => {
      this._checkLock();
      // Logic for tool execution
      return { content: [{ type: "text", text: `SSE execution of ${request.params.name}` }] };
    });

    this.#server.setRequestHandler(ListResourcesRequestSchema, async () => {
      this._checkLock();
      return {
        resources: this.#vault.wikiPages.map(page => ({
          uri: `wiki://${page.slug}`,
          name: page.slug,
          mimeType: "text/markdown"
        }))
      };
    });
  }

  /* //////////////////////////////////////////////////////////////
                          REST ROUTES
  //////////////////////////////////////////////////////////////*/

  _setupRoutes() {
    /**
     * @notice Identity Unlock Route (FR-4.2).
     * Validates Passkey assertion before allowing transport hydration.
     */
    this.#app.post("/auth/unlock", async (req, res) => {
      try {
        const { token, publicKey, dek } = req.body;
        const isValid = await this.#verifier.verifyAssertion(token, publicKey);

        if (isValid) {
          this.#isLocked = false; // Transition to UNLOCKED state
          // Trigger immediate sync on unlock to ensure cloud is current
          if (dek) {
            this.#syncService.immediateSync(this.#vault.ownerId, this.#vault.toJSON(), Buffer.from(dek, 'hex'));
          }
          res.status(200).json({ status: "UNLOCKED", vaultId: this.#vault.ownerId });
        } else {
          res.status(401).json({ error: "UNAUTHORIZED_IDENTITY_ASSERTION_FAILED" });
        }
      } catch (error) {
        res.status(500).json({ error: "INTERNAL_AUTH_ERROR" });
      }
    });

    /**
     * @notice SSE Connection Endpoint.
     * Establishes the persistent persistent event stream.
     */
    this.#app.get("/mcp/sse", async (req, res) => {
      console.error("[SSE_CONNECTION_INITIATED]");
      this.#transport = new SSEServerTransport("/mcp/messages", res);
      await this.#server.connect(this.#transport);
    });

    /**
     * @notice MCP Message Endpoint.
     * Receives JSON-RPC frames to be processed by the server.
     */
    this.#app.post("/mcp/messages", async (req, res) => {
      if (this.#transport) {
        await this.#transport.handlePostMessage(req, res);
      } else {
        res.status(400).json({ error: "TRANSPORT_NOT_INITIALIZED" });
      }
    });
  }

  /* //////////////////////////////////////////////////////////////
                            HELPERS
  //////////////////////////////////////////////////////////////*/

  _checkLock() {
    if (this.#isLocked) {
      throw new Error("SECURITY_ERROR_VAULT_LOCKED: Biometric assertion required.");
    }
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
