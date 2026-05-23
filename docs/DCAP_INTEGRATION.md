# IronClaw DCAP Integration Guide (C-04)

> **Status:** PENDING. The `/attest` endpoint currently returns `HTTP 503` with
> `attestationStatus: TEE_DETECTED_QUOTE_PENDING | TEE_NOT_DETECTED`.
> This document describes exactly what must be implemented to close C-04 and
> promote the endpoint to return a verifiable Intel TDX Quote (`ATTESTED`) natively on the NEAR TEE Network.

---

## Background

The IronClaw Shade Agent runs inside a secure Intel TDX (Trust Domain Extensions) hardware enclave on the NEAR TEE Network. The hardware generates cryptographic measurements of the running software (the `MEASUREMENT` register, e.g., MRTD). These measurements can be fetched as a **TDX Quote** and verified by any third party against Intel's DCAP (Data Center Attestation Primitives) collateral service.

Until a verifiable quote is returned, **no external caller can cryptographically prove** that they are talking to the genuine IronClaw enclave and not an impersonator.

---

## What Needs to Be Built

### Step 1 — Add Intel DCAP Libraries to the Container

To generate TDX Quotes, the container environment needs the standard Intel SGX/TDX attestation libraries.

```dockerfile
# In agent/Dockerfile, before the final stage:
RUN apt-get update && apt-get install -y \
    libsgx-dcap-ql \
    libsgx-dcap-default-qpl \
    && rm -rf /var/lib/apt/lists/*
```

The Intel Quote Provider Library (QPL) will resolve Intel's PCK certificate collateral automatically by querying the NEAR TEE network's local caching service or standard attestation endpoints.

---

### Step 2 — Add the `tdx-attest` Rust Crate

We use the standard Intel TDX guest attestation Rust crate, which interacts directly with the Linux guest driver interface `/dev/tdx_guest` to retrieve the TDREPORT.

Add to `agent/Cargo.toml`:

```toml
[dependencies]
tdx-attest = "0.1"          # Intel TDX guest attestation crate
```

---

### Step 3 — Wire the Quote into `attest_handler`

Replace the stub in `agent/src/main.rs` with a real quote fetch from the TDX guest driver device:

```rust
use tdx_attest::{get_tdx_report, get_tdx_quote}; // Reference-only example crate API

async fn attest_handler() -> impl IntoResponse {
    let platform = detect_tee_platform();

    // 1. Generate local TDREPORT with user-provided or session-bound report data (nonce)
    let report_data = [0u8; 64]; 
    match get_tdx_report(&report_data) {
        Ok(tdreport) => {
            // 2. Request the verifiable DCAP Quote from the local TDX Quote Generation Service (QGS)
            match get_tdx_quote(&tdreport) {
                Ok(quote_bytes) => {
                    let quote_b64 = base64::encode(&quote_bytes);
                    (
                        StatusCode::OK,
                        Json(AttestResponse {
                            success: true,
                            error_code: "",
                            attestation_status: "ATTESTED",
                            tee_platform: platform,
                            message: "Verifiable Intel TDX Quote returned. Verify against Intel PCS.",
                            tdx_quote: Some(quote_b64),
                            dcap_version: "1.0.0",
                        }),
                    ).into_response()
                }
                Err(e) => {
                    error!("C-04: Failed to convert TDREPORT to DCAP Quote: {:?}", e);
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(AttestResponse {
                            success: false,
                            error_code: "ATTEST_C04_QUOTE_FAILED",
                            attestation_status: "TEE_DETECTED_QUOTE_FAILED",
                            tee_platform: platform,
                            message: "Intel TDX hardware found but Quote Generation Service (QGS) failed.",
                            tdx_quote: None,
                            dcap_version: "0.0.0",
                        }),
                    ).into_response()
                }
            }
        }
        Err(e) => {
            error!("C-04: Failed to generate local TDREPORT via /dev/tdx_guest: {:?}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AttestResponse {
                    success: false,
                    error_code: "ATTEST_C04_REPORT_FAILED",
                    attestation_status: "TEE_DETECTED_REPORT_FAILED",
                    tee_platform: platform,
                    message: "Intel TDX hardware found but TDREPORT generation failed. Check /dev/tdx_guest driver.",
                    tdx_quote: None,
                    dcap_version: "0.0.0",
                }),
            ).into_response()
        }
    }
}
```

---

### Step 4 — Caller Verification (Adapter Side)

Once `/attest` returns a real quote, adapters (Skill Pack, MCP Bridge) must verify it before trusting any vault data. The verification flow is as follows:

```
1. GET /attest → receive Intel TDX Quote bytes (base64-encoded in `tdxQuote`)
2. Decode base64 → raw DCAP Quote structure
3. Fetch Intel PCK certificates & CRLs from the Intel Provisioning Certificate Service (PCS)
4. Cryptographically verify the Quote signature chain up to the Intel Root CA
5. Check the `MRTD` and `MRCONFIGID` fields to ensure the running binary's measurement matches the approved Shade Agent hash.
6. Check that the `REPORT_DATA` field matches the hash of the caller's session nonce (preventing replay attacks).
7. Only proceed with vault reads/writes if verification passes.
```

For the local Skill Pack, verification can be run as a CLI command (`aegis verify`).
For the MCP Bridge, verification should execute on the first tool call of a session and cache the result.

---

## Expected Timeline to Close C-04

| Task | Estimate |
|---|---|
| Configure Intel QPL & DCAP packages in Dockerfile | 1 hour |
| Integrate `tdx-attest` or equivalent guest driver bindings | 3 hours |
| Wire into `attest_handler` | 1 hour |
| Test inside NEAR TEE Network node | 2–4 hours |
| Add verification logic to Skill Pack & MCP Bridge | 4 hours |
| **Total** | **~1 day** |

---

## References

- [Intel Trust Domain Extensions (TDX) Resource Center](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html)
- [Intel SGX Data Center Attestation Primitives (DCAP)](https://github.com/intel/SGXDataCenterAttestationPrimitives)
- [Intel TDX Guest Attestation Driver (Linux Kernel)](https://docs.kernel.org/arch/x86/tdx.html)
