import crypto from 'crypto';
import { Vault } from './Domain/Aggregates/Vault.js';
import { McpStdioServer } from './Infrastructure/Transport/McpStdioServer.js';
import { McpSseServer } from './Infrastructure/Transport/McpSseServer.js';
import { JwtAssertionVerifier } from './Infrastructure/Crypto/JwtAssertionVerifier.js';
import { AESGCMEngine } from './Infrastructure/Crypto/AESGCMEngine.js';
import { KeyDerivation } from './Infrastructure/Crypto/KeyDerivation.js';
import { VaultRepository } from './Infrastructure/Storage/VaultRepository.js';
import { LocalFileSystemAdapter } from './Infrastructure/Storage/LocalFileSystemAdapter.js';
import { SyncService } from './Application/Services/SyncService.js';
import { SkillExecutor } from './Application/Services/SkillExecutor.js';

/**
 * @title Main Entry Point
 * @notice Boots the AI Passport server.
 * @dev SSE mode uses per-session vault hydration; stdio mode uses a default vault.
 *      Key derivation uses HKDF from a server pepper for persistent per-user DEKs.
 */

let sseServer = null;
let stdioServer = null;
let syncService = null;

async function main() {
  const transportArg = process.argv.find(arg => arg.startsWith('--transport='));
  const transport = transportArg ? transportArg.split('=')[1] : 'stdio';

  /* //////////////////////////////////////////////////////////////
                    SHARED INFRASTRUCTURE
  //////////////////////////////////////////////////////////////*/

  // 1. Load or generate server pepper (persists across restarts)
  const pepper = await KeyDerivation.loadOrGenerate();
  const keyDerivation = new KeyDerivation(pepper);

  // 2. Master key is still needed for AESGCMEngine constructor (used as fallback)
  const masterKey = crypto.randomBytes(32);
  const cryptoEngine = new AESGCMEngine(masterKey);

  // 3. Storage adapter
  const storage = process.env.R2_ACCOUNT_ID
    ? new (await import('./Infrastructure/Storage/CloudflareR2Adapter.js')).CloudflareR2Adapter()
    : new LocalFileSystemAdapter();

  // 4. Sync service (for debounced background sync) and vault repository (for DEK-encrypted persistence)
  syncService = new SyncService(storage, cryptoEngine);
  const vaultRepository = new VaultRepository(storage, cryptoEngine, keyDerivation);

  /* //////////////////////////////////////////////////////////////
                        COORDINATED SHUTDOWN
  //////////////////////////////////////////////////////////////*/

  const shutdown = async (signal) => {
    console.error(`\n[SHUTDOWN] Received ${signal}, flushing state...`);
    try {
      if (syncService) await syncService.flush();
      if (syncService) syncService.destroy();
      if (sseServer) sseServer.shutdown();
      if (stdioServer) await stdioServer.close();
    } catch (error) {
      console.error('[SHUTDOWN_ERROR]', error.message);
    }
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
    const skillExecutor = new SkillExecutor(proxyClient);

    sseServer = new McpSseServer(vaultRepository, verifier, skillExecutor, {
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

    // Stdio mode: zdr proxy for LLM calls (configured via env)
    let skillExecutor = null;
    if (process.env.LLM_ENDPOINT_URL) {
      const { ZdrProxyClient } = await import('./Infrastructure/Transport/ZdrProxyClient.js');
      skillExecutor = new SkillExecutor(new ZdrProxyClient());
    }

    stdioServer = new McpStdioServer(vault, vaultRepository, skillExecutor);
    console.error("🚀 Project Aegis: Booting Stdio Server...");
    await stdioServer.start();
  }
}

main().catch(error => {
  console.error("FATAL_BOOT_ERROR:", error);
  process.exit(1);
});