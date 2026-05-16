import crypto from 'crypto';
import { AESGCMEngine } from './src/Infrastructure/Crypto/AESGCMEngine.js';
import { LocalFileSystemAdapter } from './src/Infrastructure/Storage/LocalFileSystemAdapter.js';
import { EncryptedBlob } from './src/Domain/ValueObjects/EncryptedBlob.js';
import path from 'path';
import os from 'os';
import { promises as fs } from 'fs';

async function runSmokeTest() {
  console.log("🚀 Starting Project Aegis Smoke Test...");
  
  // 1. Setup - Create a 32-byte master key
  const masterKey = crypto.randomBytes(32);
  const cryptoEngine = new AESGCMEngine(masterKey);
  
  // Use a temporary directory for smoke testing to avoid polluting actual ~/.ai-passport
  const testStoragePath = path.join(os.tmpdir(), 'aegis-smoke-test-' + Date.now());
  const storage = new LocalFileSystemAdapter(testStoragePath);
  
  console.log("✅ Crypto Engine: Master Key initialized.");

  try {
    // 2. Simulate raw wiki markdown content
    const rawContent = "# [[ERC-4626]] Security\nConfidence is high.";
    console.log("📝 Original Content:", rawContent);

    // 3. Encrypt data
    const encryptedBlob = await cryptoEngine.encrypt(rawContent);
    console.log("✅ Crypto Engine: Encryption successful (GCM Auth Tag appended).");
    console.log("🔐 Ciphertext:", encryptedBlob.ciphertext.substring(0, 20) + "...");

    // 4. Persist to local mock storage
    const storageKey = "vault-001.json";
    await storage.push(storageKey, encryptedBlob);
    console.log("✅ Storage Adapter: Encrypted payload written to local disk.");

    // 5. Retrieve from storage
    const retrievedBlob = await storage.pull(storageKey);
    console.log("✅ Storage Adapter: Encrypted payload retrieved from disk.");

    // 6. Decrypt data
    const decryptedContent = await cryptoEngine.decrypt(retrievedBlob);
    
    if (decryptedContent === rawContent) {
      console.log("🎉 SUCCESS: Data round-trip is cryptographically sound!");
    } else {
      throw new Error("FAILURE: Decrypted content mismatch.");
    }

    // 7. Test the Nuke Switch
    console.log("🧨 Testing Nuke Switch...");
    await storage.nuke();
    
    try {
      await fs.access(testStoragePath);
      console.error("❌ FAILURE: Storage directory still exists after nuke.");
    } catch (e) {
      console.log("✅ Storage Nuke: Directory successfully deleted.");
    }

    await cryptoEngine.nuke();
    console.log("✅ Crypto Nuke: Master key shredded.");

  } catch (error) {
    console.error("💥 Smoke Test Failed:", error.message);
    process.exit(1);
  } finally {
    // Cleanup if directory still exists
    await fs.rm(testStoragePath, { recursive: true, force: true }).catch(() => {});
  }
}

runSmokeTest();
