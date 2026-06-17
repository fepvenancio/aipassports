/**
 * @file tools.ts
 * @notice MCP tool manifest for the Aegis IronClaw Shade Agent.
 *
 * Exposes four tools:
 *   - vault_read     : Retrieve and decrypt a vault entry from Walrus.
 *   - vault_write    : Encrypt and persist data to Walrus under a NEAR identity.
 *   - zdr_check      : Execute an AI skill call through the ZDR egress firewall.
 *   - agent_health   : Pre-flight health check against the Shade Agent.
 */

import type { McpTool } from "./types.js";

/* //////////////////////////////////////////////////////////////
                         TOOL MANIFEST
//////////////////////////////////////////////////////////////*/

export const TOOLS: readonly McpTool[] = [
  {
    name: "agent_health",
    description:
      "Check that the IronClaw Shade Agent is reachable and healthy before " +
      "performing any vault operations. Always run this first in a new session.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "vault_write",
    description:
      "Encrypt plaintext data and persist it to Walrus decentralised storage " +
      "under a NEAR account identity. The enclave applies AES-256-GCM encryption " +
      "using a key derived from the user's NEAR account ID inside the TEE. " +
      "Returns a blobId and contentSha256 which must be saved to retrieve the data later.",
    inputSchema: {
      type: "object",
      properties: {
        nearAccountId: {
          type: "string",
          description:
            "The user's NEAR account ID (e.g. alice.near). " +
            "1–64 chars, only [a-z0-9._-], no leading/trailing separator.",
        },
        plaintext: {
          type: "string",
          description: "The raw data to encrypt and store. Do not pre-encrypt.",
        },
        epochs: {
          type: "number",
          description:
            "Storage duration in Walrus epochs (1 epoch ≈ 1 week). " +
            "Default: 26 (≈ 6 months). Maximum: 52 (≈ 1 year).",
          default: 26,
        },
      },
      required: ["nearAccountId", "plaintext"],
    },
  },
  {
    name: "vault_read",
    description:
      "Download and decrypt a vault entry from Walrus. Verifies integrity " +
      "via SHA-256 hash comparison inside the TEE before returning plaintext. " +
      "Requires the blobId and contentSha256 returned by a prior vault_write call.",
    inputSchema: {
      type: "object",
      properties: {
        nearAccountId: {
          type: "string",
          description: "The NEAR account ID that owns the vault entry.",
        },
        blobId: {
          type: "string",
          description: "The Walrus blob ID returned by vault_write.",
        },
        expectedSha256: {
          type: "string",
          description:
            "The SHA-256 content hash returned by vault_write. " +
            "Used to detect corruption or tampering.",
        },
      },
      required: ["nearAccountId", "blobId", "expectedSha256"],
    },
  },
  {
    name: "zdr_check",
    description:
      "Execute an AI skill prompt through the IronClaw ZDR (Zero Data Residue) " +
      "egress firewall. The firewall audits the prompt for sensitive content markers " +
      "and verifies the destination URL is on the enclave allowlist before the " +
      "request exits the enclave. Returns the AI model response or a firewall block reason.",
    inputSchema: {
      type: "object",
      properties: {
        nearAccountId: {
          type: "string",
          description: "The NEAR account ID initiating the skill execution.",
        },
        skillName: {
          type: "string",
          description: "The name of the skill to execute (for audit logging).",
        },
        prompt: {
          type: "string",
          description: "The prompt to send to the AI model through the firewall.",
        },
        model: {
          type: "string",
          description: "The AI model to call (e.g. gpt-4o, claude-opus-4-5).",
          default: "gpt-4o",
        },
        destination: {
          type: "string",
          description:
            "The target AI API endpoint URL. Must be on the enclave allowlist " +
            "(e.g. https://api.openai.com).",
        },
      },
      required: ["nearAccountId", "skillName", "prompt", "destination"],
    },
  },
  {
    name: "team_vault_write",
    description: "Write to a team's shared vault. Requires team membership with write or admin permission.",
    inputSchema: {
      type: "object",
      properties: {
        teamId: { type: "string", description: "The team ID" },
        slug: { type: "string", description: "The entry slug" },
        content: { type: "string", description: "The content to store" },
        metadata: { type: "object", description: "Optional metadata" }
      },
      required: ["teamId", "slug", "content"]
    }
  },
  {
    name: "team_vault_read",
    description: "Read from a team's shared vault. Requires team membership with read permission.",
    inputSchema: {
      type: "object",
      properties: {
        teamId: { type: "string", description: "The team ID" },
        slug: { type: "string", description: "The entry slug" }
      },
      required: ["teamId", "slug"]
    }
  },
  {
    name: "team_manage",
    description: "Manage team members and permissions. Requires admin permission.",
    inputSchema: {
      type: "object",
      properties: {
        teamId: { 
          type: "string", 
          description: "The team ID" 
        },
        action: { 
          type: "string", 
          enum: ["add", "remove", "update_permission"], 
          description: "The action to perform" 
        },
        accountId: { type: "string", description: "The account ID to add/remove/update" },
        permission: { 
          type: "string", 
          enum: ["read", "write", "admin"], 
          description: "The permission to set (for add/update_permission)" 
        }
      },
      required: ["teamId", "action", "accountId"]
    }
  },
] as const;
