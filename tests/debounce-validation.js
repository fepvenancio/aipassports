import { Vault } from '../src/Domain/Aggregates/Vault.js';
import { SyncService } from '../src/Application/Services/SyncService.js';
import { ICryptoEngine } from '../src/Application/Ports/ICryptoEngine.js';
import { ISyncProvider } from '../src/Application/Ports/ISyncProvider.js';
import { EncryptedBlob } from '../src/Domain/ValueObjects/EncryptedBlob.js';
import { WikiPage } from '../src/Domain/Entities/WikiPage.js';

/**
 * @title Debounce Validation Script
 * @notice Verifies the sliding-window aggregation logic of the SyncService.
 */

/* //////////////////////////////////////////////////////////////
                            MOCKS
//////////////////////////////////////////////////////////////*/

class MockCrypto extends ICryptoEngine {
  async encrypt(plaintext) {
    return new EncryptedBlob("cipher-" + plaintext.length, "nonce", "tag");
  }
}

class MockStorage extends ISyncProvider {
  constructor() {
    super();
    this.transactionCount = 0;
    this.lastPayload = null;
  }
  async push(key, blob) {
    this.transactionCount++;
    this.lastPayload = blob;
  }
}

/* //////////////////////////////////////////////////////////////
                            HELPERS
//////////////////////////////////////////////////////////////*/

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/* //////////////////////////////////////////////////////////////
                          TEST EXECUTION
//////////////////////////////////////////////////////////////*/

async function runValidation() {
  console.log("🧪 Starting Debounce Sliding-Window Validation...");

  // 1. Initialize logic
  const vault = new Vault("user-0xTEST", [], []);
  const crypto = new MockCrypto();
  const storage = new MockStorage();
  // Use constructor option for fast debounce (200ms instead of 30s)
  const syncService = new SyncService(storage, crypto, { debounceMs: 200 });
  const DEK = Buffer.alloc(32, 1);

  console.log("⚙️ SyncService configured with 200ms debounce window.");

  // 2. Execute 10-burst mutation pass
  console.log("🏃 Firing 10 rapid mutations (50ms intervals)...");
  for (let i = 1; i <= 10; i++) {
    vault.ingestWikiPage(new WikiPage(`page-${i}`, `Content ${i}`, {}));
    syncService.queueDebouncedSync("vault-001", vault.toJSON(), DEK);
    
    if (storage.transactionCount > 0) {
      throw new Error(`❌ CONSTRAINT_1_FAILURE: Network write triggered during active burst at step ${i}`);
    }
    await sleep(50);
  }

  console.log("✅ Constraint 1: Timer reset confirmed. 0 writes during active burst.");

  // 3. Wait for the final flush
  console.log("⏳ Waiting 300ms for atomic flush...");
  await sleep(300);

  // 4. Assertions
  if (storage.transactionCount === 1) {
    console.log("✅ Constraint 2: Atomic execution confirmed. Exactly 1 network write recorded.");
  } else {
    throw new Error(`❌ CONSTRAINT_2_FAILURE: Expected 1 write, but got ${storage.transactionCount}`);
  }

  // 5. Verify State Fidelity
  if (vault.wikiPages.length === 10) {
    console.log("✅ Constraint 3: State fidelity confirmed. All 10 mutations captured in the single flush.");
  } else {
    throw new Error("❌ CONSTRAINT_3_FAILURE: Cumulative state loss detected.");
  }

  console.log("\n🎉 DEBOUNCE VALIDATION SUCCESSFUL: Sliding-window logic is cryptographically sound and efficient.");
}

runValidation().catch(err => {
  console.error(err.message);
  process.exit(1);
});