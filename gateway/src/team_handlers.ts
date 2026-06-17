/**
 * @file team_handlers.ts
 * @notice Team-specific handlers for MCP tool calls.
 *
 * Security hardening applied (audit cycle 2026-06-17):
 *   AUDIT-I3 — Replaced three hand-rolled `fetch()` + Bearer injection blocks with the
 *              shared `callShadeAgent()` helper imported from dispatcher.ts.
 *              Previously each handler duplicated the full fetch/error-parse logic,
 *              producing inconsistent error shapes and a maintenance footgun.
 *              Now all Shade Agent calls go through a single code path.
 */

import type { Env, McpToolCallResult } from "./types.js";
import { callShadeAgent } from "./dispatcher.js";

/* //////////////////////////////////////////////////////////////
                        TEAM HANDLERS
//////////////////////////////////////////////////////////////// */

/**
 * @notice Write to a team vault entry through the Shade Agent.
 */
export async function handleTeamVaultWrite(
  env: Env,
  args: Record<string, unknown>,
): Promise<McpToolCallResult> {
  const { teamId, slug, content, metadata } = args;

  if (typeof teamId !== "string" || typeof slug !== "string" || typeof content !== "string") {
    return errorResult("INVALID_ARGS", "teamId, slug and content must be strings.");
  }

  try {
    const result = await callShadeAgent({
      env,
      path: "/vault/team/write",
      body: {
        teamId,
        slug,
        content,
        metadata: typeof metadata === "object" ? metadata : undefined,
      },
    }) as { blobId: string; contentSha256: string; blobSizeBytes?: number };

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          success: true,
          blobId: result.blobId,
          contentSha256: result.contentSha256,
          blobSizeBytes: result.blobSizeBytes ?? 0,
        }),
      }],
    };
  } catch (e) {
    return errorResult("TEAM_VAULT_WRITE_FAILED", String(e));
  }
}

/**
 * @notice Read from a team vault entry through the Shade Agent.
 */
export async function handleTeamVaultRead(
  env: Env,
  args: Record<string, unknown>,
): Promise<McpToolCallResult> {
  const { teamId, slug } = args;

  if (typeof teamId !== "string" || typeof slug !== "string") {
    return errorResult("INVALID_ARGS", "teamId and slug must be strings.");
  }

  try {
    const result = await callShadeAgent({
      env,
      path: "/vault/team/read",
      body: { teamId, slug },
    }) as { content: string };

    return {
      content: [{
        type: "text",
        text: JSON.stringify({ success: true, content: result.content }),
      }],
    };
  } catch (e) {
    return errorResult("TEAM_VAULT_READ_FAILED", String(e));
  }
}

/**
 * @notice Manage team operations through the Shade Agent.
 */
export async function handleTeamManage(
  env: Env,
  args: Record<string, unknown>,
): Promise<McpToolCallResult> {
  const { teamId, action, accountId, permission } = args;

  if (typeof teamId !== "string" || typeof action !== "string" || typeof accountId !== "string") {
    return errorResult("INVALID_ARGS", "teamId, action and accountId must be strings.");
  }

  // Map action to the specific Shade Agent endpoint and body
  let path: string;
  const body: Record<string, unknown> = { teamId, accountId };

  switch (action) {
    case "add":
      path = "/team/add_member";
      body.permission = permission;
      break;
    case "remove":
      path = "/team/remove_member";
      break;
    case "update_permission":
      path = "/team/update_permission";
      body.permission = permission;
      break;
    default:
      return errorResult("INVALID_ACTION", `Unknown action: ${action}`);
  }

  try {
    const result = await callShadeAgent({ env, path, body });
    return {
      content: [{ type: "text", text: JSON.stringify(result) }],
    };
  } catch (e) {
    return errorResult("TEAM_MANAGE_FAILED", String(e));
  }
}

/* //////////////////////////////////////////////////////////////
                        HELPERS
//////////////////////////////////////////////////////////////// */

function errorResult(code: string, detail: string): McpToolCallResult {
  return {
    content: [{
      type: "text",
      text: JSON.stringify({ success: false, errorCode: code, detail }),
    }],
    isError: true,
  };
}