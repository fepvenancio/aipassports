use near_sdk::{env, near, PanicOnDefault};

mod vault;
pub mod zdr_firewall;

use vault::{Skill, VaultAggregate, WikiPage};

// //////////////////////////////////////////////////////////////
//                      MAIN ENTRY POINT
// //////////////////////////////////////////////////////////////

/// @title Aegis Backend Smart Contract
/// @notice The entry point for the Project Aegis NEAR Smart Contract.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct AegisContract {
    /// @notice Sovereign, encrypted vault storage state.
    pub vault: VaultAggregate,
}

#[near]
impl AegisContract {
    // //////////////////////////////////////////////////////////////
    //                      INITIALIZATION
    // //////////////////////////////////////////////////////////////

    /// @notice Initializes the contract with the predecessor as the owner.
    #[init]
    pub fn new() -> Self {
        let owner_id = env::predecessor_account_id();
        Self {
            vault: VaultAggregate::new(owner_id),
        }
    }

    // //////////////////////////////////////////////////////////////
    //                      VAULT OPERATIONS
    // //////////////////////////////////////////////////////////////

    /// @notice Adds an encrypted wiki page to the vault.
    pub fn add_wiki_page(&mut self, page_id: String, content_hash: String, encrypted_payload: String) {
        let page = WikiPage {
            content_hash,
            encrypted_payload,
        };
        self.vault.add_wiki_page(page_id, page);
    }

    /// @notice Adds an encrypted skill config to the vault.
    pub fn add_skill(&mut self, skill_id: String, encrypted_config: String) {
        let skill = Skill {
            skill_id: skill_id.clone(),
            encrypted_config,
        };
        self.vault.add_skill(skill_id, skill);
    }

    /// @notice Retrieves a wiki page from the vault.
    pub fn get_wiki_page(&self, page_id: String) -> Option<WikiPage> {
        self.vault.get_wiki_page(&page_id).cloned()
    }

    /// @notice Retrieves a skill from the vault.
    pub fn get_skill(&self, skill_id: String) -> Option<Skill> {
        self.vault.get_skill(&skill_id).cloned()
    }
}

// //////////////////////////////////////////////////////////////
//                          UNIT TESTS
// //////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, AccountId};
    use zdr_firewall::OutboundPayload;

    /// Helper to generate a clean VM context for tests.
    fn get_context(predecessor: AccountId) -> near_sdk::VMContext {
        VMContextBuilder::new()
            .predecessor_account_id(predecessor)
            .build()
    }

    #[test]
    fn test_initialization() {
        let owner: AccountId = "owner.near".parse().unwrap();
        testing_env!(get_context(owner.clone()));

        let contract = AegisContract::new();
        assert_eq!(contract.vault.owner_id, owner);
    }

    #[test]
    fn test_add_and_retrieve_wiki_page() {
        let owner: AccountId = "owner.near".parse().unwrap();
        testing_env!(get_context(owner.clone()));

        let mut contract = AegisContract::new();
        
        let page_id = "erc4626-audit".to_string();
        let content_hash = "sha256-hash-signature".to_string();
        let encrypted_payload = "cipher-blob-goes-here".to_string();

        contract.add_wiki_page(page_id.clone(), content_hash.clone(), encrypted_payload.clone());

        let retrieved = contract.get_wiki_page(page_id).expect("Should find page");
        assert_eq!(retrieved.content_hash, content_hash);
        assert_eq!(retrieved.encrypted_payload, encrypted_payload);
    }

    #[test]
    fn test_add_and_retrieve_skill() {
        let owner: AccountId = "owner.near".parse().unwrap();
        testing_env!(get_context(owner.clone()));

        let mut contract = AegisContract::new();
        
        let skill_id = "security-scanner".to_string();
        let encrypted_config = "encrypted-json-schema-string".to_string();

        contract.add_skill(skill_id.clone(), encrypted_config.clone());

        let retrieved = contract.get_skill(skill_id).expect("Should find skill");
        assert_eq!(retrieved.skill_id, "security-scanner");
        assert_eq!(retrieved.encrypted_config, encrypted_config);
    }

    #[test]
    #[should_panic(expected = "VAULT_ERROR_UNAUTHORIZED")]
    fn test_unauthorized_add_wiki_page() {
        let owner: AccountId = "owner.near".parse().unwrap();
        testing_env!(get_context(owner));

        let mut contract = AegisContract::new();

        // Change context to attacker
        let attacker: AccountId = "attacker.near".parse().unwrap();
        testing_env!(get_context(attacker));

        contract.add_wiki_page("illegal-page".to_string(), "hash".to_string(), "payload".to_string());
    }

    #[test]
    #[should_panic(expected = "VAULT_ERROR_UNAUTHORIZED")]
    fn test_unauthorized_get_wiki_page() {
        let owner: AccountId = "owner.near".parse().unwrap();
        testing_env!(get_context(owner));

        let mut contract = AegisContract::new();
        contract.add_wiki_page("page".to_string(), "hash".to_string(), "payload".to_string());

        // Change context to attacker
        let attacker: AccountId = "attacker.near".parse().unwrap();
        testing_env!(get_context(attacker));

        let _ = contract.get_wiki_page("page".to_string());
    }

    #[test]
    #[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
    fn test_invalid_identifier_validation() {
        let owner: AccountId = "owner.near".parse().unwrap();
        testing_env!(get_context(owner));

        let mut contract = AegisContract::new();
        // ID is empty / spaces
        contract.add_wiki_page("   ".to_string(), "hash".to_string(), "payload".to_string());
    }

    #[test]
    fn test_zdr_firewall_compliance_audit() {
        let allowed = vec!["https://api.openai.com/v1/chat/completions".to_string()];

        // 1. Compliant payload
        let p1 = OutboundPayload {
            data: "Assess this solidity vault standard".to_string(),
            destination: "https://api.openai.com/v1/chat/completions".to_string(),
            timestamp: 123456,
        };
        assert!(p1.is_compliant(&allowed));

        // 2. Non-compliant destination
        let p2 = OutboundPayload {
            data: "Assess this solidity vault standard".to_string(),
            destination: "https://evil.exfiltration.endpoint".to_string(),
            timestamp: 123456,
        };
        assert!(!p2.is_compliant(&allowed));

        // 3. Sensitive markers leak (Uppercase)
        let p3 = OutboundPayload {
            data: "Here is my PRIVATE_KEY = 0xabcdef".to_string(),
            destination: "https://api.openai.com/v1/chat/completions".to_string(),
            timestamp: 123456,
        };
        assert!(!p3.is_compliant(&allowed));

        // 4. Sensitive markers leak (Lowercase covert exfiltration)
        let p4 = OutboundPayload {
            data: "my seed phrase mnemonic is secret".to_string(),
            destination: "https://api.openai.com/v1/chat/completions".to_string(),
            timestamp: 123456,
        };
        assert!(!p4.is_compliant(&allowed));

        // 5. Supplementary markers leak
        let p5 = OutboundPayload {
            data: "api_key value goes here".to_string(),
            destination: "https://api.openai.com/v1/chat/completions".to_string(),
            timestamp: 123456,
        };
        assert!(!p5.is_compliant(&allowed));
    }
}
