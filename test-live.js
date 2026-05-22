import crypto from 'crypto';

async function testLiveApi() {
  const endpoint = 'https://api.aipassports.xyz'; // Or the IP if DNS isn't working
  
  // 1. Generate ES256 Keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  // 2. Create JWT Assertion
  const header = { alg: 'ES256', typ: 'JWT' };
  const payload = { sub: 'e2e-test-user', exp: Math.floor(Date.now() / 1000) + 3600 };
  
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  
  const sign = crypto.createSign('SHA256');
  sign.update(`${headerB64}.${payloadB64}`);
  const signatureB64 = sign.sign(privateKey).toString('base64url');
  
  const token = `${headerB64}.${payloadB64}.${signatureB64}`;

  // 3. Call /auth/unlock
  console.log('Calling /auth/unlock...');
  const response = await fetch(`${endpoint}/auth/unlock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, publicKey })
  });

  const data = await response.json();
  console.log('Status:', response.status);
  console.log('Response:', data);
  
  if (data.sessionId) {
     console.log('SUCCESS: Authenticated and Vault is active!');
  }
}

testLiveApi().catch(console.error);
