use near_sdk::store::LookupMap;
use near_sdk::{env, near, AccountId, PanicOnDefault, Promise};

mod vault;
pub mod zdr_firewall;

use vault::VaultPointer;

#[near(serializers = [borsh])]
#[derive(near_sdk::BorshStorageKey)]
pub enum StorageKey {
    WikiPointers,
    SkillPointers,
    WikiSlugLists,
    SkillIdLists,
}

// //////////////////////////////////////////////////////////////
//                        MAIN ENTRY POINT
// //////////////////////////////////////////////////////////////

/// @title Aegis Shared Multi-User Smart Contract
/// @notice The entry point for the Project Aegis NEAR Smart Contract.
/// @dev Implements a stateless, secure multi-tenant pointer index partitioned via composite keys.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct AegisContract {
    /// @notice Partitioned mapping of wiki page composite keys ("{account_id}:{slug}") to their Walrus pointers.
    wiki_pointers: LookupMap<String, VaultPointer>,

    /// @notice Partitioned mapping of skill composite keys ("{account_id}:{skill_id}") to their Walrus pointers.
    skill_pointers: LookupMap<String, VaultPointer>,

    /// @notice Tracks the list of wiki slugs owned by each AccountId for enumeration.
    wiki_slug_lists: LookupMap<AccountId, Vec<String>>,

    /// @notice Tracks the list of skill IDs owned by each AccountId for enumeration.
    skill_id_lists: LookupMap<AccountId, Vec<String>>,
}

#[near]
impl AegisContract {
    // //////////////////////////////////////////////////////////////
    //                      INITIALIZATION
    // //////////////////////////////////////////////////////////////

    /// @notice Initializes the contract. Called once by the operator at deployment.
    #[init]
    pub fn new() -> Self {
        Self {
            wiki_pointers: LookupMap::new(StorageKey::WikiPointers),
            skill_pointers: LookupMap::new(StorageKey::SkillPointers),
            wiki_slug_lists: LookupMap::new(StorageKey::WikiSlugLists),
            skill_id_lists: LookupMap::new(StorageKey::SkillIdLists),
        }
    }

    // //////////////////////////////////////////////////////////////
    //                      MUTATION METHODS
    // //////////////////////////////////////////////////////////////

    /// @notice Creates or updates a wiki page pointer for the signing account.
    /// @dev Validates slug, blob_id, and hash. Calculates storage byte expansion and refunds surplus deposits.
    #[payable]
    pub fn update_wiki_pointer(&mut self, slug: String, blob_id: String, content_sha256: String) {
        let caller = env::predecessor_account_id();
        
        // Structural validations
        vault::validate_identifier(&slug);
        vault::validate_blob_id(&blob_id);
        vault::validate_content_sha256(&content_sha256);

        let composite_key = format!("{}:{}", caller.as_str(), slug);

        // Storage tracking before write
        let initial_storage = env::storage_usage();
        let is_new = !self.wiki_pointers.contains_key(&composite_key);

        let pointer = VaultPointer {
            blob_id,
            content_sha256,
            updated_at_ms: env::block_timestamp_ms(),
        };
        self.wiki_pointers.insert(composite_key, pointer);

        // Update enumeration list if a new key is added
        if is_new {
            let mut list = self.wiki_slug_lists.get(&caller).cloned().unwrap_or_default();
            list.push(slug);
            self.wiki_slug_lists.insert(caller.clone(), list);
        }

        // Process storage costs
        let final_storage = env::storage_usage();
        self._reconcile_storage_deposit(caller, initial_storage, final_storage);
    }

    /// @notice Deletes a wiki page pointer and programmatically refunds its storage stake to the caller.
    pub fn remove_wiki_pointer(&mut self, slug: String) {
        let caller = env::predecessor_account_id();
        vault::validate_identifier(&slug);

        let composite_key = format!("{}:{}", caller.as_str(), slug);

        if !self.wiki_pointers.contains_key(&composite_key) {
            env::panic_str("VAULT_ERROR_NOT_FOUND");
        }

        // Storage tracking before delete
        let initial_storage = env::storage_usage();

        self.wiki_pointers.remove(&composite_key);

        // Remove slug from the enumeration list
        if let Some(mut list) = self.wiki_slug_lists.get(&caller).cloned() {
            if let Some(pos) = list.iter().position(|x| x == &slug) {
                list.swap_remove(pos);
                if list.is_empty() {
                    self.wiki_slug_lists.remove(&caller);
                } else {
                    self.wiki_slug_lists.insert(caller.clone(), list);
                }
            }
        }

        // Process storage refund
        let final_storage = env::storage_usage();
        self._refund_released_storage(caller, initial_storage, final_storage);
    }

    /// @notice Creates or updates a skill pointer for the signing account.
    #[payable]
    pub fn update_skill_pointer(&mut self, skill_id: String, blob_id: String, content_sha256: String) {
        let caller = env::predecessor_account_id();
        
        // Structural validations
        vault::validate_identifier(&skill_id);
        vault::validate_blob_id(&blob_id);
        vault::validate_content_sha256(&content_sha256);

        let composite_key = format!("{}:{}", caller.as_str(), skill_id);

        // Storage tracking before write
        let initial_storage = env::storage_usage();
        let is_new = !self.skill_pointers.contains_key(&composite_key);

        let pointer = VaultPointer {
            blob_id,
            content_sha256,
            updated_at_ms: env::block_timestamp_ms(),
        };
        self.skill_pointers.insert(composite_key, pointer);

        // Update enumeration list if a new key is added
        if is_new {
            let mut list = self.skill_id_lists.get(&caller).cloned().unwrap_or_default();
            list.push(skill_id);
            self.skill_id_lists.insert(caller.clone(), list);
        }

        // Process storage costs
        let final_storage = env::storage_usage();
        self._reconcile_storage_deposit(caller, initial_storage, final_storage);
    }

    /// @notice Deletes a skill pointer and programmatically refunds its storage stake to the caller.
    pub fn remove_skill_pointer(&mut self, skill_id: String) {
        let caller = env::predecessor_account_id();
        vault::validate_identifier(&skill_id);

        let composite_key = format!("{}:{}", caller.as_str(), skill_id);

        if !self.skill_pointers.contains_key(&composite_key) {
            env::panic_str("VAULT_ERROR_NOT_FOUND");
        }

        // Storage tracking before delete
        let initial_storage = env::storage_usage();

        self.skill_pointers.remove(&composite_key);

        // Remove from enumeration list
        if let Some(mut list) = self.skill_id_lists.get(&caller).cloned() {
            if let Some(pos) = list.iter().position(|x| x == &skill_id) {
                list.swap_remove(pos);
                if list.is_empty() {
                    self.skill_id_lists.remove(&caller);
                } else {
                    self.skill_id_lists.insert(caller.clone(), list);
                }
            }
        }

        // Process storage refund
        let final_storage = env::storage_usage();
        self._refund_released_storage(caller, initial_storage, final_storage);
    }

    // //////////////////////////////////////////////////////////////
    //                      VIEW METHODS
    // //////////////////////////////////////////////////////////////

    /// @notice Fetches a single wiki page pointer. Returns None if not found.
    pub fn get_wiki_pointer(&self, account_id: AccountId, slug: String) -> Option<VaultPointer> {
        let composite_key = format!("{}:{}", account_id.as_str(), slug);
        self.wiki_pointers.get(&composite_key).cloned()
    }

    /// @notice Fetches a single skill pointer. Returns None if not found.
    pub fn get_skill_pointer(&self, account_id: AccountId, skill_id: String) -> Option<VaultPointer> {
        let composite_key = format!("{}:{}", account_id.as_str(), skill_id);
        self.skill_pointers.get(&composite_key).cloned()
    }

    /// @notice Returns a paginated list of wiki slugs for an account, with limit capped at 100.
    pub fn list_wiki_slugs(&self, account_id: AccountId, from_index: u64, limit: u64) -> Vec<String> {
        let actual_limit = u64::min(limit, 100) as usize;
        let start = from_index as usize;
        
        if let Some(list) = self.wiki_slug_lists.get(&account_id) {
            let len = list.len();
            if start >= len {
                return Vec::new();
            }
            let end = usize::min(start + actual_limit, len);
            list[start..end].to_vec()
        } else {
            Vec::new()
        }
    }

    /// @notice Returns a paginated list of skill IDs for an account, with limit capped at 100.
    pub fn list_skill_ids(&self, account_id: AccountId, from_index: u64, limit: u64) -> Vec<String> {
        let actual_limit = u64::min(limit, 100) as usize;
        let start = from_index as usize;
        
        if let Some(list) = self.skill_id_lists.get(&account_id) {
            let len = list.len();
            if start >= len {
                return Vec::new();
            }
            let end = usize::min(start + actual_limit, len);
            list[start..end].to_vec()
        } else {
            Vec::new()
        }
    }

    // //////////////////////////////////////////////////////////////
    //                      INTERNAL UTILITIES
    // //////////////////////////////////////////////////////////////

    /// @notice Internal utility to reconcile storage costs.
    /// @dev Calculates bytes added, enforces deposit attached, and transfers excess back to user.
    fn _reconcile_storage_deposit(&self, caller: AccountId, initial: u64, final_st: u64) {
        if final_st > initial {
            let bytes_added = final_st - initial;
            let required_deposit = env::storage_byte_cost().as_yoctonear().checked_mul(bytes_added as u128).unwrap();
            let attached_deposit = env::attached_deposit().as_yoctonear();
            
            if attached_deposit < required_deposit {
                env::panic_str("VAULT_ERROR_INSUFFICIENT_DEPOSIT");
            }
            
            let excess = attached_deposit - required_deposit;
            if excess > 0 {
                Promise::new(caller).transfer(near_sdk::NearToken::from_yoctonear(excess));
            }
        } else {
            let attached_deposit = env::attached_deposit();
            if attached_deposit.as_yoctonear() > 0 {
                Promise::new(caller).transfer(attached_deposit);
            }
        }
    }

    /// @notice Internal utility to calculate released bytes and refund locked NEAR stake.
    fn _refund_released_storage(&self, caller: AccountId, initial: u64, final_st: u64) {
        if initial > final_st {
            let bytes_freed = initial - final_st;
            let released_stake = env::storage_byte_cost().as_yoctonear().checked_mul(bytes_freed as u128).unwrap();
            if released_stake > 0 {
                Promise::new(caller).transfer(near_sdk::NearToken::from_yoctonear(released_stake));
            }
        }
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

    fn get_context(predecessor: AccountId, attached_deposit: u128) -> near_sdk::VMContext {
        VMContextBuilder::new()
            .predecessor_account_id(predecessor)
            .attached_deposit(near_sdk::NearToken::from_yoctonear(attached_deposit))
            .build()
    }

    #[test]
    fn test_initialization() {
        let owner: AccountId = "owner.near".parse().unwrap();
        testing_env!(get_context(owner.clone(), 0));

        let _contract = AegisContract::new();
    }

    #[test]
    fn test_update_and_retrieve_wiki_pointer() {
        let alice: AccountId = "alice.near".parse().unwrap();
        // High deposit attached to prevent deposit failures
        testing_env!(get_context(alice.clone(), 100_000_000_000_000_000_000_000));

        let mut contract = AegisContract::new();
        
        let slug = "erc4626-standard".to_string();
        let blob_id = "certified-blob-id-walrus-hash".to_string();
        let content_sha256 = "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string();

        contract.update_wiki_pointer(slug.clone(), blob_id.clone(), content_sha256.clone());

        let retrieved = contract.get_wiki_pointer(alice.clone(), slug).expect("Should find pointer");
        assert_eq!(retrieved.blob_id, blob_id);
        assert_eq!(retrieved.content_sha256, content_sha256);
    }

    #[test]
    fn test_multi_user_isolation() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 100_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();
        contract.update_wiki_pointer("shared-slug".to_string(), "blob-alice".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());

        // Bob tries to read Alice's data via Bob's identity context
        let bob: AccountId = "bob.near".parse().unwrap();
        testing_env!(get_context(bob.clone(), 100_000_000_000_000_000_000_000));
        
        let retrieved_as_bob = contract.get_wiki_pointer(bob.clone(), "shared-slug".to_string());
        assert!(retrieved_as_bob.is_none(), "Bob should not see a pointer under his own prefix");

        // Bob tries to read Alice's pointer by supplying Alice's account ID (allowed since view calls are public)
        let retrieved_as_public = contract.get_wiki_pointer(alice.clone(), "shared-slug".to_string()).unwrap();
        assert_eq!(retrieved_as_public.blob_id, "blob-alice");

        // Bob tries to delete Alice's pointer
        testing_env!(get_context(bob.clone(), 0));
    }

    #[test]
    #[should_panic(expected = "VAULT_ERROR_NOT_FOUND")]
    fn test_unauthorized_delete_reverts() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 100_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();
        contract.update_wiki_pointer("shared-slug".to_string(), "blob-alice".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());

        // Bob tries to delete the pointer "shared-slug"
        let bob: AccountId = "bob.near".parse().unwrap();
        testing_env!(get_context(bob.clone(), 0));
        
        // This must panic because there is no entry under "bob.near:shared-slug"
        contract.remove_wiki_pointer("shared-slug".to_string());
    }

    #[test]
    #[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
    fn test_slug_casing_validation() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 100_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();
        contract.update_wiki_pointer("Upper-Case".to_string(), "blob".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());
    }

    #[test]
    #[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
    fn test_slug_character_validation() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 100_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();
        contract.update_wiki_pointer("slug:with:colons".to_string(), "blob".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());
    }

    #[test]
    #[should_panic(expected = "VAULT_ERROR_INVALID_HASH")]
    fn test_invalid_sha256_length() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 100_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();
        contract.update_wiki_pointer("slug".to_string(), "blob".to_string(), "short-hash".to_string());
    }

    #[test]
    fn test_pagination_and_lists() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 500_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();

        contract.update_wiki_pointer("slug-1".to_string(), "blob".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());
        contract.update_wiki_pointer("slug-2".to_string(), "blob".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());
        contract.update_wiki_pointer("slug-3".to_string(), "blob".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());

        let list_all = contract.list_wiki_slugs(alice.clone(), 0, 10);
        assert_eq!(list_all.len(), 3);
        assert!(list_all.contains(&"slug-1".to_string()));

        let page_1 = contract.list_wiki_slugs(alice.clone(), 0, 2);
        assert_eq!(page_1.len(), 2);

        let page_2 = contract.list_wiki_slugs(alice.clone(), 2, 2);
        assert_eq!(page_2.len(), 1);

        let out_of_bounds = contract.list_wiki_slugs(alice.clone(), 10, 2);
        assert!(out_of_bounds.is_empty());
    }

    #[test]
    fn test_zdr_firewall_compliance_audit() {
        let allowed = vec!["https://api.openai.com/v1/chat/completions".to_string()];

        let p1 = OutboundPayload {
            data: "Assess this solidity vault standard".to_string(),
            destination: "https://api.openai.com/v1/chat/completions".to_string(),
            timestamp: 123456,
        };
        assert!(p1.is_compliant(&allowed));

        let p2 = OutboundPayload {
            data: "Assess this solidity vault standard".to_string(),
            destination: "https://evil.exfiltration.endpoint".to_string(),
            timestamp: 123456,
        };
        assert!(!p2.is_compliant(&allowed));

        let p3 = OutboundPayload {
            data: "Here is my PRIVATE_KEY = 0xabcdef".to_string(),
            destination: "https://api.openai.com/v1/chat/completions".to_string(),
            timestamp: 123456,
        };
        assert!(!p3.is_compliant(&allowed));
    }
}
