import { Vault } from './Domain/Aggregates/Vault.js';
import { Skill } from './Domain/Entities/Skill.js';
import { WikiPage } from './Domain/Entities/WikiPage.js';
import { McpStdioServer } from './Infrastructure/Transport/McpStdioServer.js';
import { McpSseServer } from './Infrastructure/Transport/McpSseServer.js';
import { WebAuthnVerifier } from './Infrastructure/Crypto/WebAuthnVerifier.js';

/**
 * @title Main Entry Point
 * @notice Boots the local alpha AI Passport server.
 */

async function main() {
  /* //////////////////////////////////////////////////////////////
                          MOCK HYDRATION
  //////////////////////////////////////////////////////////////*/
  
  // In a real scenario, this would be loaded via SyncVaultUseCase
  const mockSkill = new Skill(
    "calculate-risk",
    "Calculate Risk",
    "Analyzes the security risk of a specific smart contract address.",
    {
      type: "object",
      properties: {
        address: { type: "string", description: "The Ethereum address to audit." }
      },
      required: ["address"]
    }
  );

  const mockWiki = new WikiPage(
    "index",
    "# Sovereign AI Passport Wiki\n\n## Core Principles\n- Total Portability\n- Zero Trust Architecture\n- Hardware-Enforced Privacy",
    { confidence: 1.0 }
  );

  const vault = new Vault("user-0xdeadbeef", [mockSkill], [mockWiki]);

  /* //////////////////////////////////////////////////////////////
                          START TRANSPORT
  //////////////////////////////////////////////////////////////*/

  const transportArg = process.argv.find(arg => arg.startsWith('--transport='));
  const transport = transportArg ? transportArg.split('=')[1] : 'stdio';

  if (transport === 'sse') {
    const verifier = new WebAuthnVerifier();
    const cryptoEngine = new AESGCMEngine(crypto.randomBytes(32)); // Placeholder for actual master key
    
    // Determine which storage to use based on env
    const storage = process.env.R2_ACCOUNT_ID 
      ? new (await import('./Infrastructure/Storage/CloudflareR2Adapter.js')).CloudflareR2Adapter()
      : new (await import('./Infrastructure/Storage/LocalFileSystemAdapter.js')).LocalFileSystemAdapter();

    const syncService = new (await import('./Application/Services/SyncService.js')).SyncService(storage, cryptoEngine);
    const proxyClient = new (await import('./Infrastructure/Transport/ZdrProxyClient.js')).ZdrProxyClient();
    const sseServer = new McpSseServer(vault, verifier, syncService, proxyClient);
    
    console.error("🚀 Project Aegis: Booting SSE Gateway...");
    await sseServer.start(8080);
  } else {
    const stdioServer = new McpStdioServer(vault);
    console.error("🚀 Project Aegis: Booting Stdio Server...");
    await stdioServer.start();
  }
}

main().catch(error => {
  console.error("FATAL_BOOT_ERROR:", error);
  process.exit(1);
});
