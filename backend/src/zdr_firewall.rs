use serde::{Deserialize, Serialize};

// //////////////////////////////////////////////////////////////
//                  ZERO DATA RETENTION FIREWALL
// //////////////////////////////////////////////////////////////

/// @title OutboundPayload
/// @notice Represents a data payload requesting to be dispatched outside the TEE boundary.
#[derive(Serialize, Deserialize, Debug)]
pub struct OutboundPayload {
    /// @notice The raw string payload to be transmitted.
    pub data: String,
    /// @notice The target URL or provider endpoint.
    pub destination: String,
    /// @notice Unix timestamp marking the payload request time.
    pub timestamp: u64,
}

impl OutboundPayload {
    // //////////////////////////////////////////////////////////////
    //                          VALIDATION
    // //////////////////////////////////////////////////////////////

    /// @notice Validates an outbound payload against the ComplianceRegistry rules.
    /// @dev Intended to be imported by the off-chain TEE agent to locally validate egress.
    /// @param allowed_destinations A list of approved destinations.
    /// @return true if the payload destination is in the allowed list and contains no sensitive markers.
    pub fn is_compliant(&self, allowed_destinations: &[String]) -> bool {
        if !allowed_destinations.contains(&self.destination) {
            return false;
        }

        // Zero Data Retention rule: prevent covert leak of private keys, seeds, or tokens.
        // We perform a case-insensitive check to avoid bypasses via casing manipulation.
        let data_upper = self.data.to_uppercase();
        let sensitive_markers = [
            "PRIVATE_KEY",
            "MNEMONIC",
            "SECRET_TOKEN",
            "SECRET_KEY",
            "PASSWORD",
            "API_KEY",
            "PASSPHRASE",
        ];
        
        for marker in sensitive_markers.iter() {
            if data_upper.contains(marker) {
                return false;
            }
        }

        true
    }
}
