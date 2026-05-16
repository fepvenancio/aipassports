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

/**
 * @title McpStdioServer
 * @notice Production-grade MCP translator for the Sovereign AI Passport.
 * @dev Bridges the VaultAggregate to the Antigravity Host over JSON-RPC 2.0 stdio.
 */

/* //////////////////////////////////////////////////////////////
                          MCP STDIO SERVER
//////////////////////////////////////////////////////////////*/

export class McpStdioServer {
  #server;
  #vault;
  #executeToolUseCase;

  /**
   * @param {Vault} vault - The hydrated domain aggregate.
   */
  constructor(vault) {
    if (!(vault instanceof Vault)) {
      throw new Error('INFRA_ERROR_TRANSPORT_INVALID_VAULT_INSTANCE');
    }

    this.#vault = vault;
    this.#executeToolUseCase = new ExecuteToolUseCase();

    this.#server = new Server(
      {
        name: "ai-passport-server",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
          resources: {},
        },
      }
    );

    this._setupHandlers();
  }

  /* //////////////////////////////////////////////////////////////
                            TOOL HANDLERS
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Initializes request handlers for tools and resources.
   */
  _setupHandlers() {
    /**
     * @notice FR-1.3: Progressive Disclosure.
     * Maps internal Skills to MCP Tools metadata.
     */
    this.#server.setRequestHandler(ListToolsRequestSchema, async () => {
      try {
        return {
          tools: this.#vault.skills.map(skill => ({
            name: skill.id,
            description: skill.description,
            inputSchema: skill.schema
          }))
        };
      } catch (error) {
        throw new McpError(ErrorCode.InternalError, "Failed to list tools");
      }
    });

    /**
     * @notice Handles tool execution requests via ExecuteToolUseCase.
     */
    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const result = await this.#executeToolUseCase.execute(this.#vault, name, args);
        return {
          content: [
            {
              type: "text",
              text: `SUCCESS: Invoked ${result.skillName}. Execution triggered.`
            }
          ]
        };
      } catch (error) {
        if (error.message === 'USE_CASE_ERROR_SKILL_NOT_FOUND') {
          throw new McpError(ErrorCode.MethodNotFound, `Skill not found: ${name}`);
        }
        return {
          content: [{ type: "text", text: `EXECUTION_ERROR: ${error.message}` }],
          isError: true
        };
      }
    });

    /* //////////////////////////////////////////////////////////////
                          RESOURCE HANDLERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Maps internal Wiki nodes to MCP Resources.
     */
    this.#server.setRequestHandler(ListResourcesRequestSchema, async () => {
      try {
        return {
          resources: this.#vault.wikiPages.map(page => ({
            uri: `wiki://${page.slug}`,
            name: page.slug,
            mimeType: "text/markdown",
            description: `Sovereign knowledge entry: ${page.slug}`
          }))
        };
      } catch (error) {
        throw new McpError(ErrorCode.InternalError, "Failed to list resources");
      }
    });

    /**
     * @notice Reads a specific wiki resource.
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
          contents: [
            {
              uri: request.params.uri,
              mimeType: "text/markdown",
              text: page.content
            }
          ]
        };
      } catch (error) {
        if (error instanceof McpError) throw error;
        throw new McpError(ErrorCode.InternalError, error.message);
      }
    });
  }

  /* //////////////////////////////////////////////////////////////
                            LIFECYCLE
  //////////////////////////////////////////////////////////////*/

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