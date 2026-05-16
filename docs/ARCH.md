# ARCH-001: Architecture Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. System Overview

Project Aegis SHALL implement a Domain-Driven Design (DDD) architectural pattern. The system MUST maintain a strict separation between Domain, Application, and Infrastructure layers.

## 2. Layering Constraints

### 2.1 Domain Layer
- The Domain layer MUST NOT have any dependencies on external frameworks or infrastructure-specific modules.
- Domain logic SHALL be implemented using pure ES Modules.
- Aggregates MUST encapsulate business invariants and coordinate state transitions.

### 2.2 Application Layer
- The Application layer SHALL coordinate domain objects and invoke infrastructure through Ports (Abstract Interfaces).
- Use Cases MUST represent distinct business operations (e.g., `SyncVault`).

### 2.3 Infrastructure Layer
- All I/O operations (Filesystem, Network, Crypto) MUST be implemented in the Infrastructure layer.
- Infrastructure adapters MUST implement the corresponding Port interfaces defined in the Application layer.

## 3. Communication Protocol

### 3.1 Model Context Protocol (MCP)
- The system MUST expose capabilities via the Model Context Protocol (MCP) v1.0.
- Servers SHALL support both `stdio` and `sse` (Server-Sent Events) transport modes.
- JSON-RPC 2.0 MUST be used for all MCP communication.

## 4. Security Model

- The system SHALL follow a Zero-Trust architecture.
- All persistent data MUST be client-side encrypted using AES-256-GCM.
- Outbound LLM calls MUST pass through a compliance proxy (ZDR Firewall).
