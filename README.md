# Project Aegis: The Sovereign AI Passport

[![Security: TEE-Shielded](https://img.shields.io/badge/Security-TEE--Shielded-blueviolet)](https://github.com/fepvenancio/aipassports)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Architecture: DDD](https://img.shields.io/badge/Architecture-DDD-green)](docs/ARCH.md)

Project Aegis is a decoupled, provider-agnostic context layer that abstracts a user’s long-term memory, skills, and configurations away from proprietary AI vendor silos. It establishes a hardware-enforced, zero-trust boundary for agentic intelligence.

---

## 🏛️ Core Architecture

Project Aegis is built on **Domain-Driven Design (DDD)** principles, ensuring the core business logic remains stateless and isolated from infrastructure concerns.

*   **Stateless Domain Aggregates:** Manages skills and memory without side effects.
*   **Asymmetric Identity:** Passwordless authentication via WebAuthn/Passkeys.
*   **Hybrid Sync Engine:** Sub-5ms latency with debounced Cloudflare R2 persistence.
*   **ZDR Firewall:** Byte-level enforcement of Zero Data Retention policies for outbound LLM calls.
*   **Hardware Enclave:** Optimized for serverless Trusted Execution Environments (TEE) using AMD SEV-SNP.

## 🚀 Quick Start (Local Alpha)

### 1. Requirements
*   Node.js 22+
*   pnpm
*   Docker (for containerized execution)

### 2. Installation
```bash
pnpm install
```

### 3. Running Stdio Server
```bash
node src/main.js --transport=stdio
```

### 4. Running SSE Gateway
```bash
node src/main.js --transport=sse
```

## 📚 Documentation

Detailed technical specifications following **RFC-2119** are located in the `/docs` directory:

*   [**Architecture Overview**](docs/ARCH.md) - System-wide design and layer boundaries.
*   [**Identity Specification**](docs/IDENTITY.md) - WebAuthn and JWT verification logic.
*   [**Sync Engine Specification**](docs/SYNC.md) - Hybrid write-behind and debounce strategies.
*   [**Firewall Specification**](docs/FIREWALL.md) - ZDR enforcement and compliance registry.
*   [**Deployment Specification**](docs/DEPLOYMENT.md) - TEE staging and TCB measurement.

## 🛡️ Security

Project Aegis assumes a **Zero-Trust** posture. All outbound network traffic is proxied, all stored data is client-side encrypted (AES-256-GCM), and the runtime memory is protected by hardware-level encryption when deployed in a supported TEE.

---

*“Sovereignty through silicon physics.”*
