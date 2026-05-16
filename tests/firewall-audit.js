import { ZdrProxyClient } from '../src/Infrastructure/Transport/ZdrProxyClient.js';
import assert from 'assert';

/**
 * @title Security Firewall Audit
 * @notice Validates ZDR enforcement and endpoint blocking.
 */

async function runAudit() {
  console.log("🛡️ Starting Security Firewall Audit...");
  
  const proxy = new ZdrProxyClient();

  /* //////////////////////////////////////////////////////////////
                          GLOBAL FETCH MOCK
  //////////////////////////////////////////////////////////////*/
  
  let fetchCallCount = 0;
  let lastFetchParams = null;

  // Mock globalThis.fetch to intercept outgoing calls
  globalThis.fetch = async (url, options) => {
    fetchCallCount++;
    lastFetchParams = { url, options };
    return new Response(JSON.stringify({ status: "success" }), { 
      status: 200, 
      headers: { "Content-Type": "application/json" } 
    });
  };

  try {
    /* //////////////////////////////////////////////////////////////
                TEST CASE 1: COMPLIANT REWRITE (OPENAI)
    //////////////////////////////////////////////////////////////*/
    console.log("🔍 Auditing OpenAI ZDR Enforcement...");
    
    const openAiUrl = 'https://api.openai.com/v1/chat/completions';
    const rawBody = { model: 'gpt-4', messages: [{ role: 'user', content: 'test' }] };
    
    await proxy.fetch(openAiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rawBody)
    });

    const interceptedBody = JSON.parse(lastFetchParams.options.body);
    assert.strictEqual(interceptedBody.store, false, "OpenAI request must have 'store: false' injected.");
    assert.strictEqual(fetchCallCount, 1, "Underlying fetch should have been called once.");
    
    console.log("✅ OpenAI ZDR Wall: PASSED (store: false injected)");

    /* //////////////////////////////////////////////////////////////
                TEST CASE 2: COMPLIANT HEADER INJECTION (ANTHROPIC)
    //////////////////////////////////////////////////////////////*/
    console.log("🔍 Auditing Anthropic Header Injection...");
    
    const anthropicUrl = 'https://api.anthropic.com/v1/messages';
    await proxy.fetch(anthropicUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'claude-3' })
    });

    const interceptedHeaders = lastFetchParams.options.headers;
    assert.strictEqual(interceptedHeaders['x-anthropic-zdr'], 'true', "Anthropic request must have ZDR header.");
    assert.strictEqual(fetchCallCount, 2, "Underlying fetch should have been called twice.");
    
    console.log("✅ Anthropic ZDR Wall: PASSED (Header injected)");

    /* //////////////////////////////////////////////////////////////
                TEST CASE 3: BLACK-HOLE DROP (UNVERIFIED)
    //////////////////////////////////////////////////////////////*/
    console.log("🔍 Auditing Black-Hole Drop (Unverified Endpoint)...");
    
    const forbiddenUrl = 'https://arbitrary-unvetted-llm-endpoint.com/v1/predict';
    const response = await proxy.fetch(forbiddenUrl, {
      method: 'POST',
      body: JSON.stringify({ data: 'sensitive' })
    });

    assert.strictEqual(response.status, 403, "Unverified endpoint must return 403 Forbidden.");
    assert.strictEqual(fetchCallCount, 2, "Underlying fetch must NOT be called for unverified endpoints.");
    
    const errorBody = await response.json();
    assert.strictEqual(errorBody.error, "SECURITY_POLICY_VIOLATION", "Should return specific policy violation error.");
    
    console.log("✅ Unverified Egress Wall: PASSED (403 Connection Dropped)");

    /* //////////////////////////////////////////////////////////////
                            FINAL VERDICT
    //////////////////////////////////////////////////////////////*/
    console.log("\n🎊 FIREWALL AUDIT SUCCESSFUL: Your outbound transport boundaries are LOCKED DOWN.");
    process.exit(0);

  } catch (error) {
    console.error("\n💥 Firewall Audit Failed:", error.message);
    process.exit(1);
  }
}

runAudit();
