import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ErrorCode,
  McpError
} from "@modelcontextprotocol/sdk/types.js";
import { Vault } from "../../Domain/Aggregates/Vault.js";
import { ExecuteToolUseCase } from "../../Application/UseCases/ExecuteToolUseCase.js";
import { BuiltinTools } from "../../Application/Constants/BuiltinTools.js";

/**
 * @title McpStdioServer
 * @notice MCP translator for the Sovereign AI Passport over stdio.
 * @dev Single-user mode. Supports skill execution, wiki management, and vault persistence.
 */

/* //////////////////////////////////////////////////////////////
                          MCP STDIO SERVER
//////////////////////////////////////////////////////////////*/

export class McpStdioServer {
  #server;
  #vault;
  #vaultRepository;
  #executeToolUseCase;

  /**
   * @param {Vault} vault - The hydrated domain aggregate.
   * @param {IVaultRepository} vaultRepository - Repository for persisting vault mutations.
   * @param {SkillExecutor|null} skillExecutor - LLM-backed skill executor (null for local-only).
   */
  constructor(vault, vaultRepository, skillExecutor = null) {
    if (!(vault instanceof Vault)) {
      throw new Error('INFRA_ERROR_TRANSPORT_INVALID_VAULT_INSTANCE');
    }

    this.#vault = vault;
    this.#vaultRepository = vaultRepository;
    this.#executeToolUseCase = new ExecuteToolUseCase(skillExecutor);

    this.#server = new Server(
      { name: "ai-passport-server", version: "2.0.0" },
      { capabilities: { tools: {}, resources: {} } }
    );

    this._setupHandlers();
  }

  _setupHandlers() {
    /**
     * List tools: built-in management tools + user-defined skills from vault.
     */
    this.#server.setRequestHandler(ListToolsRequestSchema, async () => {
      const userSkills = this.#vault.skills.map(skill => ({
        name: skill.id,
        description: skill.description,
        inputSchema: skill.schema
      }));

      return { tools: [...BuiltinTools, ...userSkills] };
    });

    /**
     * Call tool: route to ExecuteToolUseCase, persist mutations.
     */
    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const result = await this.#executeToolUseCase.execute(this.#vault, name, args || {});

        // Persist vault state after mutations via VaultRepository (uses per-user DEK)
        if (name.startsWith('wiki/') || name.startsWith('skill/')) {
          await this.#vaultRepository.save(this.#vault.ownerId, this.#vault.toJSON());
        }

        return {
          content: [{ type: "text", text: typeof result.result === 'string' ? result.result : JSON.stringify(result) }]
        };
      } catch (error) {
        if (error.message.startsWith('USE_CASE_ERROR')) {
          return {
            content: [{ type: "text", text: error.message }],
            isError: true
          };
        }
        return {
          content: [{ type: "text", text: `EXECUTION_ERROR: ${error.message}` }],
          isError: true
        };
      }
    });

    /**
     * List resources: wiki pages.
     */
    this.#server.setRequestHandler(ListResourcesRequestSchema, async () => {
      return {
        resources: this.#vault.wikiPages.map(page => ({
          uri: `wiki://${page.slug}`,
          name: page.slug,
          mimeType: "text/markdown",
          description: `Sovereign knowledge entry: ${page.slug}`
        }))
      };
    });

    /**
     * Read resource: wiki page content.
     */
    this.#server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      try {
        const uri = new URL(request.params.uri);
        if (uri.protocol !== 'wiki:') {
          throw new McpError(ErrorCode.InvalidParams, "Unsupported protocol");
        }

        const slug = uri.hostname || uri.pathname.replace(/^\/\//, '');
        const page = this.#vault.wikiPages.find(p => p.slug === slug);

        if (!page) {
          throw new McpError(ErrorCode.ResourceNotFound, `Wiki page not found: ${slug}`);
        }

        return {
          contents: [{
            uri: request.params.uri,
            mimeType: "text/markdown",
            text: page.content
          }]
        };
      } catch (error) {
        if (error instanceof McpError) throw error;
        throw new McpError(ErrorCode.InternalError, error.message);
      }
    });
  }

  /**
   * @notice Starts the server using stdio transport.
   */
  async start() {
    try {
      const transport = new StdioServerTransport();
      await this.#server.connect(transport);
      console.error("AI Passport MCP Server established over stdio.");
    } catch (error) {
      console.error("FATAL: Failed to start MCP Server", error);
      process.exit(1);
    }
  }

  /**
   * @notice Closes the MCP server.
   */
  async close() {
    await this.#server.close();
  }
}