# DEPLOY-001: Confidential Deployment Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Runtime Environment

Project Aegis SHALL be deployed within a serverless Trusted Execution Environment (TEE) (e.g., Azure ACI with AMD SEV-SNP).

## 2. Enclave Hardening

### 2.1 Memory Encryption
- The deployment manifest MUST activate hardware-enforced memory isolation (Confidential SKU).
- Application memory SHALL be encrypted at rest and in transit within the processor registers.

### 2.2 Privilege Isolation
- The container MUST run as a non-root user (`aegisuser`).
- Root privileges SHOULD be dropped immediately after the container boot sequence.

## 3. Remote Attestation

### 3.1 TCB Measurement
- Before deployment, a measurement of the Trusted Computing Base (TCB) MUST be performed.
- The TCB measurement SHALL include hashes of the container images and the application source code.

### 3.2 CCE Policy
- A Confidential Computing Enforcement (CCE) policy MUST be generated and embedded in the deployment manifest.
- The CCE policy SHALL prevent the container from booting if the runtime measurement mismatches the pre-calculated hash.

## 4. Secret Management

- Credentials (e.g., R2 API keys) MUST NOT be stored in plaintext.
- Secrets MUST be injected as `secureValue` parameters, decryptable only within the hardware enclave after successful attestation.
