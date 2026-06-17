# Team Integration Test

This document describes the team integration test script that verifies the complete team workflow end-to-end.

## Overview

The `test_team_integration.sh` script automates the testing of the entire team functionality stack:

1. **NEAR Sandbox**: Local NEAR testnet for contract deployment
2. **Backend Contract**: Team management smart contract
3. **Agent**: Mock IronClaw agent for encryption/decryption
4. **Gateway**: Local Hono gateway for MCP protocol
5. **Integration Tests**: curl commands testing team operations

## Prerequisites

Before running the integration test, ensure you have the following tools installed:

- **Rust toolchain**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **near-cli-rs**: `cargo install near-cli-rs`
- **wrangler**: `pnpm add -g wrangler`
- **pnpm**: `npm install -g pnpm`

## Running the Test

```bash
# Make the script executable
chmod +x test_team_integration.sh

# Run the integration test
./test_team_integration.sh
```

## What the Test Does

### 1. NEAR Sandbox Setup
- Starts a local NEAR sandbox network
- Creates a test account (`aegis.testnet`)
- Builds and deploys the backend contract with team support

### 2. Agent Setup
- Builds the Rust agent
- Starts the agent in mock mode (no real TEE encryption)
- Listens on port 8080

### 3. Gateway Setup
- Installs dependencies
- Creates `.env` file with test configuration
- Starts the gateway using `wrangler dev`
- Listens on port 8787

### 4. Team Operations Tests

The script runs a series of curl commands to test:

1. **Team Creation**: Creates a new team with unique ID
2. **Member Addition**: Adds members to the team with different permissions
3. **Team Vault Write**: Writes data to the team's shared vault
4. **Team Vault Read**: Reads data from the team's shared vault
5. **Permission Enforcement**: Verifies read/write permissions work correctly

## Test Output

The script provides color-coded output:

- **Yellow**: Informational messages and step descriptions
- **Green**: Success indicators (✓)
- **Red**: Error messages and failures

## Cleanup

The script automatically cleans up background processes when:
- The test completes successfully
- The test fails
- You press Ctrl+C to interrupt

Cleanup includes killing:
- NEAR sandbox processes
- Agent processes
- Gateway processes

## Expected Results

When all components are working correctly, you should see:

```
✓ NEAR Sandbox and contract deployed
✓ Agent started on port 8080
✓ Gateway started on port 8787
✓ Team created successfully
✓ Member added successfully
✓ Team vault write successful
✓ Team vault read successful
✓ All tests passed!
```

## Troubleshooting

### Missing Tools
If you see "command not found" errors:
```bash
# Install the missing tool as indicated in the error message
# For example:
cargo install near-cli-rs
```

### Port Conflicts
If ports 8080 or 8787 are in use:
```bash
# Find and kill processes using the ports
lsof -i :8080
lsof -i :8787
kill -9 <PID>
```

### Contract Deployment Issues
If contract deployment fails:
```bash
# Check sandbox logs
near sandbox logs

# Try redeploying
cd backend
near contract deploy aegis.testnet \
  use-file target/wasm32-unknown-unknown/release/backend.wasm \
  with-init-call new json-args '{}' \
  prepaid-gas '100.0 Tgas' \
  attached-deposit '0 NEAR' \
  network-config sandbox sign-with-keychain send
```

## Development Notes

### Mock Agent
The test uses a mock agent that simulates the IronClaw TEE functionality without actual hardware encryption. This allows testing the complete workflow without requiring IronClaw developer access.

### Test Data
- Teams are created with unique IDs based on timestamp
- Test accounts use the `.testnet` suffix
- All test data is ephemeral and cleaned up automatically

### Extending the Test
To add more test cases:
1. Edit `test_team_integration.sh`
2. Add new curl commands following the existing pattern
3. Ensure proper error handling and output formatting

## Security Notes

- The mock agent uses a test API key (`test-api-key-123`)
- Never use test API keys in production
- The sandbox network is isolated and does not use real NEAR tokens
- All test data is local and not persisted

## Related Documentation

- [DEPLOYMENT.md](docs/DEPLOYMENT.md) - Production deployment guide
- [backend/README.md](backend/README.md) - Backend contract details
- [agent/README.md](agent/README.md) - Agent implementation details
- [gateway/README.md](gateway/README.md) - Gateway setup and configuration
