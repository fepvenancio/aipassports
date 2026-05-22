# IronClaw DCAP Integration Guide (C-04)

> **Status:** PENDING. The `/attest` endpoint currently returns `HTTP 503` with
> `attestationStatus: TEE_DETECTED_QUOTE_PENDING | TEE_NOT_DETECTED`.
> This document describes exactly what must be implemented to close C-04 and
> promote the endpoint to return a verifiable Intel TDX Quote (`ATTESTED`).

---

## Background

The IronClaw Shade Agent runs inside an Azure Container Instances (ACI) Confidential
container backed by AMD SEV-SNP hardware. The hardware generates cryptographic
measurements of the running software (the `MEASUREMENT` register). These measurements
can be fetched as a **TDX Quote** and verified by any third party against Intel's
DCAP (Data Center Attestation Primitives) collateral service.

Until a verifiable quote is returned, **no external caller can cryptographically
prove** that they are talking to the genuine IronClaw enclave and not an impersonator.

---

## What Needs to Be Built

### Step 1 — Add `az-dcap-client` to the Docker image

The `az-dcap-client` library is the Azure-specific DCAP plugin that hooks into the
Intel DCAP runtime on ACI Confidential instances.

```dockerfile
# In agent/Dockerfile, before the final stage:
RUN apt-get update && apt-get install -y \
    libsgx-dcap-ql \
    az-dcap-client \
    && rm -rf /var/lib/apt/lists/*
```

The Azure DCAP endpoint is pre-configured in ACI Confidential containers via
`AZDCAP_COLLATERAL_VERSION` and will resolve Intel's PCK certificate automatically.

---

### Step 2 — Add the `tdx-attest` or `az-snp-vtpm` Rust crate

Two viable Rust crates for quote generation:

| Crate | Notes |
|---|---|
| `tdx-attest` | Intel's official TDX attestation crate. Wraps `/dev/tdx_guest` ioctl. |
| `snp-sdk` (AMD) | AMD-specific. For pure SEV-SNP without TDX. |
| `azure-snp-vtpm` | Azure-specific. Reads the SNP report from the vTPM device exposed by ACI. |

**Recommended for Azure ACI Confidential:** use the **vTPM path** (`/dev/tpm0`).
Azure ACI Confidential containers expose a virtual TPM that contains the SNP report
without requiring kernel driver access to `/dev/tdx_guest`.

Add to `agent/Cargo.toml`:

```toml
[dependencies]
# Choose ONE:
# tdx-attest = "0.1"          # Intel TDX path (bare-metal TDX)
# az-snp-report = "0.1"       # Azure vTPM SNP path (ACI Confidential)
```

---

### Step 3 — Wire the Quote into `attest_handler`

Replace the current stub with a real quote fetch:

```rust
use az_snp_report::get_snp_report;   // or equivalent crate

async fn attest_handler() -> impl IntoResponse {
    let platform = detect_tee_platform();

    match get_snp_report(/* report_data: [u8; 64] */ &[0u8; 64]) {
        Ok(report_bytes) => {
            let quote_b64 = base64::encode(&report_bytes);
            (
                StatusCode::OK,
                Json(AttestResponse {
                    success: true,
                    error_code: "",
                    attestation_status: "ATTESTED",
                    tee_platform: platform,
                    message: "Verifiable SNP report returned. Verify against AMD VCEK.",
                    tdx_quote: Some(quote_b64),
                    dcap_version: "1.0.0",
                }),
            )
        }
        Err(e) => {
            error!("C-04: Failed to generate SNP report: {:?}", e);
            // Fall back to current 503 behaviour
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AttestResponse {
                    success: false,
                    error_code: "ATTEST_C04_REPORT_FAILED",
                    attestation_status: "TEE_DETECTED_QUOTE_FAILED",
                    tee_platform: platform,
                    message: "TEE detected but report generation failed. Check DCAP driver.",
                    tdx_quote: None,
                    dcap_version: "0.0.0",
                }),
            )
        }
    }
}
```

---

### Step 4 — Caller Verification (Adapter Side)

Once `/attest` returns a real quote, adapters (Skill Pack, MCP Bridge) must verify it
before trusting any vault data. Verification flow:

```
1. GET /attest → receive SNP report bytes (base64-encoded in `tdxQuote`)
2. Decode base64 → raw SNP report struct
3. Fetch AMD VCEK certificate from:
   https://kdsintf.amd.com/vcek/v1/{platform}/{product}/{tcbVersion}
4. Verify the SNP report signature against the VCEK certificate.
5. Check the `MEASUREMENT` field matches the expected IronClaw binary hash.
6. Only proceed with vault operations if verification passes.
```

For the Skill Pack, verification can be deferred to a local `aegis verify` CLI command.
For the MCP Bridge, verification should run on first tool call and cache the result
for the session duration.

---

## Expected Timeline to Close C-04

| Task | Estimate |
|---|---|
| Add `az-dcap-client` to Dockerfile | 1 hour |
| Integrate `az-snp-report` crate | 2–4 hours |
| Wire into `attest_handler` | 1 hour |
| Test inside ACI Confidential (requires deployment) | 2–4 hours |
| Add verification logic to Skill Pack + MCP Bridge | 4 hours |
| **Total** | **~1–2 days** |

---

## Security Notes

- The **report data** field (64 bytes passed to `get_snp_report`) should be bound to
  the session — e.g. a SHA-256 hash of the caller's public key or nonce. This prevents
  quote replay attacks.
- The `MEASUREMENT` register must be published and pinned in the Skill Pack and MCP
  Bridge to allow clients to reject a quote from a modified binary.
- Do not use the `attestation_status` field from the HTTP response as a trust signal —
  always verify the raw quote cryptographically.

---

## References

- [Azure Confidential Containers attestation](https://learn.microsoft.com/azure/confidential-computing/confidential-containers)
- [AMD SEV-SNP attestation](https://www.amd.com/en/developer/sev.html)
- [Intel DCAP overview](https://github.com/intel/SGXDataCenterAttestationPrimitives)
- [az-dcap-client (GitHub)](https://github.com/microsoft/Azure-DCAP-Client)
