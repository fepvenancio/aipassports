/**
 * @title BuiltinTools
 * @notice MCP tool definitions that are always available regardless of vault contents.
 * @dev These tools manage wiki pages and skills directly on the vault.
 */

export const BUILTIN_TOOLS = [
  {
    name: "wiki/create",
    description: "Create a new wiki page in the sovereign vault.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string", description: "Unique page identifier (e.g., 'solidity-patterns')." },
        content: { type: "string", description: "Markdown content of the page." },
        metadata: { type: "object", description: "Optional metadata (e.g., { confidence: 1.0 })." }
      },
      required: ["slug", "content"]
    }
  },
  {
    name: "wiki/update",
    description: "Update an existing wiki page in the sovereign vault.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string", description: "Page identifier to update." },
        content: { type: "string", description: "New markdown content." },
        metadata: { type: "object", description: "Optional updated metadata." }
      },
      required: ["slug", "content"]
    }
  },
  {
    name: "wiki/read",
    description: "Read a wiki page from the sovereign vault by slug.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string", description: "Page identifier to read." }
      },
      required: ["slug"]
    }
  },
  {
    name: "skill/register",
    description: "Register a new skill in the sovereign vault.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Unique skill identifier." },
        name: { type: "string", description: "Human-readable skill name." },
        description: { type: "string", description: "Skill description for LLM invocation." },
        schema: { type: "object", description: "JSON Schema for the skill parameters." }
      },
      required: ["id", "name", "description"]
    }
  },
  {
    name: "skill/remove",
    description: "Remove a skill from the sovereign vault.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Skill identifier to remove." }
      },
      required: ["id"]
    }
  }
];