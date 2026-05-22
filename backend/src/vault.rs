use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId};

/// @title WikiPage
/// @notice Represents an encrypted wiki page stored on-chain.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct WikiPage {
    /// @notice SHA-256 integrity hash of the raw markdown content.
    pub content_hash: String,
    /// @notice The encrypted payload, ciphered with the user's per-session DEK.
    pub encrypted_payload: String,
}

/// @title Skill
/// @notice Represents an encrypted skill configuration stored on-chain.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Skill {
    /// @notice Unique identifier of the custom LLM skill.
    pub skill_id: String,
    /// @notice JSON schema structure defining input parameters, encrypted.
    pub encrypted_config: String,
}

// //////////////////////////////////////////////////////////////
//                          VAULT STATE
// //////////////////////////////////////////////////////////////

/// @title VaultAggregate
/// @notice Manages the storage of encrypted WikiPages and Skills state natively on-chain.
#[near(serializers = [borsh])]
pub struct VaultAggregate {
    /// @notice Cryptographic owner of this sovereign vault.
    pub owner_id: AccountId,
    /// @notice Persistent map of page IDs to their encrypted contents.
    pub wiki_pages: LookupMap<String, WikiPage>,
    /// @notice Persistent map of skill IDs to their encrypted configurations.
    pub skills: LookupMap<String, Skill>,
}

impl VaultAggregate {
    /// @notice Initializes a new VaultAggregate.
    pub fn new(owner_id: AccountId) -> Self {
        Self {
            owner_id,
            wiki_pages: LookupMap::new(b"w"),
            skills: LookupMap::new(b"s"),
        }
    }

    /// @notice Ensures that only the cryptographic owner of the NEAR account can unlock or modify the Vault state.
    pub fn assert_owner(&self) {
        require!(
            env::predecessor_account_id() == self.owner_id,
            "VAULT_ERROR_UNAUTHORIZED"
        );
    }

    /// @notice Internal validation helper to ensure storage keys meet structural invariants.
    fn _check_id_valid(&self, id: &str) {
        require!(
            !id.trim().is_empty() && id.len() <= 128,
            "VAULT_ERROR_INVALID_IDENTIFIER"
        );
    }

    /// @notice Stores an encrypted wiki page.
    pub fn add_wiki_page(&mut self, page_id: String, page: WikiPage) {
        self.assert_owner();
        self._check_id_valid(&page_id);
        self.wiki_pages.insert(page_id, page);
    }

    /// @notice Stores an encrypted skill config.
    pub fn add_skill(&mut self, skill_id: String, skill: Skill) {
        self.assert_owner();
        self._check_id_valid(&skill_id);
        self.skills.insert(skill_id, skill);
    }

    /// @notice Retrieves a wiki page.
    pub fn get_wiki_page(&self, page_id: &String) -> Option<&WikiPage> {
        self.assert_owner();
        self.wiki_pages.get(page_id)
    }

    /// @notice Retrieves a skill.
    pub fn get_skill(&self, skill_id: &String) -> Option<&Skill> {
        self.assert_owner();
        self.skills.get(skill_id)
    }
}
