import crypto from 'crypto';
import { Vault } from './Domain/Aggregates/Vault.js';
import { Skill } from './Domain/Entities/Skill.js';
import { WikiPage } from './Domain/Entities/WikiPage.js';
import { McpStdioServer } from './Infrastructure/Transport/McpStdioServer.js';
import { McpSseServer } from './Infrastructure/Transport/McpSseServer.js';
import { JwtAssertionVerifier } from './Infrastructure/Crypto/JwtAssertionVerifier.js';
import { AESGCMEngine } from './Infrastructure/Crypto/AESGCMEngine.js';
import { VaultRepository } from './Infrastructure/Storage/VaultRepository.js';
import { LocalFileSystemAdapter } from './Infrastructure/Storage/LocalFileSystemAdapter.js';
import { SyncService } from './Application/Services/SyncService.js';

/**
 * @title Main Entry Point
 * @notice Boots the AI Passport server.
 * @dev SSE mode uses per-session vault hydration; stdio mode uses a default vault.
 */

let sseServer = null;
let syncService = null;

async function main() {
  const transportArg = process.argv.find(arg => arg.startsWith('--transport='));
  const transport = transportArg ? transportArg.split('=')[1] : 'stdio';

  /* //////////////////////////////////////////////////////////////
                    SHARED INFRASTRUCTURE
  //////////////////////////////////////////////////////////////*/

  const masterKey = crypto.randomBytes(32);
  const cryptoEngine = new AESGCMEngine(masterKey);

  const storage = process.env.R2_ACCOUNT_ID
    ? new (await import('./Infrastructure/Storage/CloudflareR2Adapter.js')).CloudflareR2Adapter()
    : new LocalFileSystemAdapter();

  syncService = new SyncService(storage, cryptoEngine);
  const vaultRepository = new VaultRepository(storage, cryptoEngine);

  /* //////////////////////////////////////////////////////////////
                        COORDINATED SHUTDOWN
  //////////////////////////////////////////////////////////////*/

  const shutdown = async (signal) => {
    console.error(`\n[SHUTDOWN] Received ${signal}, flushing state...`);
    if (syncService) await syncService.destroy();
    if (sseServer) sseServer.shutdown();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  /* //////////////////////////////////////////////////////////////
                          START TRANSPORT
  //////////////////////////////////////////////////////////////*/

  if (transport === 'sse') {
    const verifier = new JwtAssertionVerifier();
    const { ZdrProxyClient } = await import('./Infrastructure/Transport/ZdrProxyClient.js');
    const proxyClient = new ZdrProxyClient();

    sseServer = new McpSseServer(vaultRepository, verifier, syncService, proxyClient, {
      corsOrigins: process.env.CORS_ORIGINS?.split(',') ?? [],
    });

    console.error("🚀 Project Aegis: Booting Streamable HTTP Gateway...");
    await sseServer.start(8080);
  } else {
    // Stdio: single-user mode, load or create a default vault
    const ownerId = process.env.OWNER_ID ?? 'local-user';
    let vault;

    try {
      vault = await vaultRepository.load(ownerId);
      console.error(`✅ Loaded vault for ${ownerId}`);
    } catch {
      vault = new Vault(ownerId);
      console.error(`✅ Created new vault for ${ownerId}`);
    }

    const stdioServer = new McpStdioServer(vault);
    console.error("🚀 Project Aegis: Booting Stdio Server...");
    await stdioServer.start();
  }
}

main().catch(error => {
  console.error("FATAL_BOOT_ERROR:", error);
  process.exit(1);
});