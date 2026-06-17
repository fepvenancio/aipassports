#!/bin/bash

# Team Integration Test Script
# =============================
# 
# This script tests the complete team workflow:
# 1. Start local NEAR sandbox
# 2. Deploy the backend contract
# 3. Start the Agent in mock mode
# 4. Start the Gateway locally
# 5. Run curl commands to test team operations
#
# Prerequisites:
# - Rust toolchain (cargo, rustup)
# - near-cli-rs (cargo install near-cli-rs)
# - wrangler (pnpm add -g wrangler)
# - pnpm
#
# Usage:
# chmod +x test_team_integration.sh
# ./test_team_integration.sh

set -e  # Exit on error
set -o pipefail  # Fail if any command in pipeline fails

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BACKEND_DIR="backend"
AGENT_DIR="agent"
GATEWAY_DIR="gateway"
NEAR_ACCOUNT="aegis.testnet"
GATEWAY_PORT=8787
AGENT_PORT=8080

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    pkill -f "wrangler dev" || true
    pkill -f "cargo run" || true
    pkill -f "near sandbox" || true
    echo -e "${GREEN}Cleanup complete${NC}"
}

# Trap Ctrl+C and cleanup
trap cleanup EXIT

echo -e "${YELLOW}Team Integration Test${NC}"
echo -e "=======================${NC}"
echo -e "This script tests the complete team workflow end-to-end.\n"

echo -e "${YELLOW}Prerequisites Check${NC}"
echo -e "---------------------"

# Check required tools
MISSING_TOOLS=0

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Rust/cargo not found${NC}"
    MISSING_TOOLS=1
else
    echo -e "${GREEN}✓ Rust/cargo installed${NC}"
fi

if ! command -v near &> /dev/null; then
    echo -e "${RED}❌ near-cli-rs not found${NC}"
    echo -e "   Install with: cargo install near-cli-rs"
    MISSING_TOOLS=1
else
    echo -e "${GREEN}✓ near-cli-rs installed${NC}"
fi

if ! command -v wrangler &> /dev/null; then
    echo -e "${RED}❌ wrangler not found${NC}"
    echo -e "   Install with: pnpm add -g wrangler"
    MISSING_TOOLS=1
else
    echo -e "${GREEN}✓ wrangler installed${NC}"
fi

if ! command -v pnpm &> /dev/null; then
    echo -e "${RED}❌ pnpm not found${NC}"
    echo -e "   Install with: npm install -g pnpm"
    MISSING_TOOLS=1
else
    echo -e "${GREEN}✓ pnpm installed${NC}"
fi

if [ $MISSING_TOOLS -eq 1 ]; then
    echo -e "\n${RED}Please install missing tools and try again.${NC}"
    exit 1
fi

echo -e "\n${YELLOW}All prerequisites satisfied!${NC}"
echo -e "${YELLOW}Starting integration test...${NC}"

# Step 1: Start NEAR Sandbox
echo -e "\n${YELLOW}Step 1/5: Starting NEAR Sandbox...${NC}"
cd $BACKEND_DIR

# Start sandbox
near sandbox start --home ~/.near/sandbox &> /dev/null &
SANDBOX_PID=$!
echo "Waiting for sandbox to initialize..."
sleep 5

# Create test account
near account create-account sponsor-by-faucnet-service $NEAR_ACCOUNT \
  autogenerate-new-keypair save-to-keychain \
  network-config sandbox &> /dev/null

# Build and deploy contract
echo "Building contract..."
cargo build --target wasm32-unknown-unknown --release &> /dev/null

echo "Deploying contract..."
near contract deploy $NEAR_ACCOUNT \
  use-file target/wasm32-unknown-unknown/release/backend.wasm \
  with-init-call new json-args '{}' \
  prepaid-gas '100.0 Tgas' \
  attached-deposit '0 NEAR' \
  network-config sandbox sign-with-keychain send &> /dev/null

echo -e "${GREEN}✓ NEAR Sandbox and contract deployed${NC}"

# Step 2: Start Agent (mock mode)
echo -e "\n${YELLOW}Step 2/5: Starting Agent...${NC}"
cd ../$AGENT_DIR

# Build agent if needed
if [ ! -f "target/debug/shade-agent" ]; then
    echo "Building agent..."
    cargo build &> /dev/null
fi

# Start agent in mock mode
IRONCLAW_AGENT_API_KEY="test-api-key-123" \
    LLM_API_KEY="mock-llm-key" \
    cargo run -- --mock-mode --port $AGENT_PORT &> /dev/null &
AGENT_PID=$!
echo "Waiting for agent to start..."
sleep 3

echo -e "${GREEN}✓ Agent started on port $AGENT_PORT${NC}"

# Step 3: Start Gateway
echo -e "\n${YELLOW}Step 3/5: Starting Gateway...${NC}"
cd ../$GATEWAY_DIR

# Create .env file
cat > .env << EOF
IRONCLAW_AGENT_API_KEY=test-api-key-123
IRONCLAW_AGENT_BASE_URL=http://localhost:$AGENT_PORT
NEAR_RPC_URL=http://localhost:3030
AEGIS_CONTRACT_ID=$NEAR_ACCOUNT
CORS_ORIGINS=http://localhost:5173
EOF

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    pnpm install &> /dev/null
fi

# Start gateway
wrangler dev --local --port $GATEWAY_PORT &> /dev/null &
GATEWAY_PID=$!
echo "Waiting for gateway to start..."
sleep 5

echo -e "${GREEN}✓ Gateway started on port $GATEWAY_PORT${NC}"

# Step 4: Run Team Integration Tests
echo -e "\n${YELLOW}Step 4/5: Running Team Integration Tests...${NC}"

# Generate unique team ID
TEAM_ID="test-team-$(date +%s)"
MEMBER_ACCOUNT="alice.testnet"

# Test 1: Create a team
echo -e "\n${YELLOW}Test 1: Creating team $TEAM_ID...${NC}"
curl -X POST "http://localhost:$GATEWAY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "create_team",
            "arguments": {
                "teamId": "'