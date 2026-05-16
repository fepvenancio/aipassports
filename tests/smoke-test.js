import crypto from 'crypto';
import { AESGCMEngine } from '../src/Infrastructure/Crypto/AESGCMEngine.js';
import { LocalFileSystemAdapter } from '../src/Infrastructure/Storage/LocalFileSystemAdapter.js';
import { KeyDerivation } from '../src/Infrastructure/Crypto/KeyDerivation.js';
import { VaultRepository } from '../src/Infrastructure/Storage/VaultRepository.js';
import { Vault } from '../src/Domain/Aggregates/Vault.js';
import { Skill } from '../src/Domain/Entities/Skill.js';
import { WikiPage } from '../src/Domain/Entities/WikiPage.js';
import { EncryptedBlob } from '../src/Domain/ValueObjects/EncryptedBlob.js';
import path from 'path';
import os from 'os';
import { promises as fs } from 'fs';

async function runSmokeTest() {
  console.log("🚀 Starting Project Aegis Smoke Test...");
  
  const masterKey = crypto.randomBytes(32);
  const cryptoEngine = new AESGCMEngine(masterKey);
  const testStoragePath = path.join(os.tmpdir(), 'aegis-smoke-test-' + Date.now());
  const storage = new LocalFileSystemAdapter(testStoragePath);
  
  console.log("✅ Crypto Engine: Master Key initialized.");

  try {
    // 1. Encrypt/Decrypt round-trip
    const rawContent = "# [[ERC-4626]] Security\nConfidence is high.";
    console.log("📝 Original Content:", rawContent);

    const encryptedBlob = await cryptoEngine.encrypt(rawContent);
    console.log("✅ Crypto Engine: Encryption successful (GCM Auth Tag appended).");
    console.log("🔐 Ciphertext:", encryptedBlob.ciphertext.substring(0, 20) + "...");

    await storage.push("vault-001.json", encryptedBlob);
    console.log("✅ Storage Adapter: Encrypted payload written to local disk.");

    const retrievedBlob = await storage.pull("vault-001.json");
    console.log("✅ Storage Adapter: Encrypted payload retrieved from disk.");

    const decryptedContent = await cryptoEngine.decrypt(retrievedBlob);
    
    if (decryptedContent === rawContent) {
      console.log("🎉 SUCCESS: Data round-trip is cryptographically sound!");
    } else {
      throw new Error("FAILURE: Decrypted content mismatch.");
    }

    // 2. Nuke switch
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

    // 3. Key Derivation persistence across "restarts"
    console.log("\n🔑 Testing Key Derivation persistence across restarts...");
    const keyTestDir = path.join(os.tmpdir(), 'aegis-key-test-' + Date.now());
    await fs.mkdir(keyTestDir, { recursive: true });

    // Boot 1: generate pepper
    const pepper = await KeyDerivation.loadOrGenerate(keyTestDir);
    const kd = new KeyDerivation(pepper);
    const dek1 = kd.deriveDEK('user-0xdeadbeef');
    console.log("✅ KeyDerivation: Pepper generated and DEK derived.");

    // Boot 2: load same pepper, verify DEK is identical
    const pepper2 = await KeyDerivation.loadOrGenerate(keyTestDir);
    const kd2 = new KeyDerivation(pepper2);
    const dek2 = kd2.deriveDEK('user-0xdeadbeef');

    if (Buffer.from(dek1).toString('hex') === Buffer.from(dek2).toString('hex')) {
      console.log("✅ Key Derivation: Same user produces same DEK across boots.");
    } else {
      throw new Error("FAILURE: DEK not deterministic across boots!");
    }

    // Different user = different DEK
    const dek3 = kd.deriveDEK('different-user');
    if (Buffer.from(dek1).toString('hex') !== Buffer.from(dek3).toString('hex')) {
      console.log("✅ Key Derivation: Different users produce different DEKs.");
    } else {
      throw new Error("FAILURE: Different users produced same DEK!");
    }

    // 4. Vault round-trip with DEK
    console.log("\n📦 Testing Vault persistence with per-user DEK...");
    const vaultTestDir = path.join(os.tmpdir(), 'aegis-vault-test-' + Date.now());
    const vaultStorage = new LocalFileSystemAdapter(vaultTestDir);
    const vaultEngine = new AESGCMEngine(crypto.randomBytes(32));
    const vaultRepo = new VaultRepository(vaultStorage, vaultEngine, kd);

    const vault = await vaultRepo.load('test-user');
    console.log("✅ VaultRepository: Loaded fresh vault for test-user.");

    vault.createWikiPage('solidity', '# Solidity Patterns', { confidence: 1.0 });
    vault.addSkill(new Skill('audit', 'Audit Contract', 'Analyzes smart contract security', { type: 'object' }));
    await vaultRepo.save('test-user', vault.toJSON());
    console.log("✅ VaultRepository: Saved vault with wiki and skill.");

    // Reload with a different engine instance (simulating reboot)
    const vaultEngine2 = new AESGCMEngine(crypto.randomBytes(32));
    const kdReloaded = new KeyDerivation(pepper);
    const vaultRepo2 = new VaultRepository(vaultStorage, vaultEngine2, kdReloaded);
    const loadedVault = await vaultRepo2.load('test-user');

    if (loadedVault.wikiPages.length === 1 && loadedVault.skills.length === 1) {
      console.log("✅ VaultRepository: Vault decrypted successfully with per-user DEK.");
    } else {
      throw new Error(`FAILURE: Vault round-trip failed. Got ${loadedVault.wikiPages.length} wiki, ${loadedVault.skills.length} skills.`);
    }

    // Cleanup
    await fs.rm(keyTestDir, { recursive: true, force: true }).catch(() => {});
    await fs.rm(vaultTestDir, { recursive: true, force: true }).catch(() => {});

  } catch (error) {
    console.error("💥 Smoke Test Failed:", error.message);
    process.exit(1);
  } finally {
    await fs.rm(testStoragePath, { recursive: true, force: true }).catch(() => {});
  }
}

runSmokeTest();