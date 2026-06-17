use near_sdk::store::LookupMap;
use near_sdk::{env, near, AccountId, PanicOnDefault, Promise};

mod vault;
#[cfg(test)]
mod vault_tests;
#[cfg(test)]
mod team_tests;
pub mod zdr_firewall;

use vault::VaultPointer;

/// @notice Team metadata stored on-chain.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct TeamMetadata {
    /// @notice Unique team identifier (alphanumeric + hyphen/underscore).
    pub team_id: String,
    /// @notice Human-readable team name.
    pub name: String,
    /// @notice Unix timestamp in milliseconds when the team was created.
    pub created_at: u64,
    /// @notice NEAR account ID of the team creator.
    pub created_by: AccountId,
}

/// @notice Permission level for team members.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    Read,
    Write,
    Admin,
}

/// @notice Team member record with permissions and metadata.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct TeamMember {
    /// @notice NEAR account ID of the team member.
    pub account_id: AccountId,
    /// @notice Permission level (Read, Write, Admin).
    pub permission: Permission,
    /// @notice Unix timestamp in milliseconds when the member joined.
    pub joined_at: u64,
    /// @notice NEAR account ID of the member who added this user.
    pub added_by: AccountId,
}

#[near(serializers = [borsh])]
#[derive(near_sdk::BorshStorageKey)]
pub enum StorageKey {
    WikiPointers,
    SkillPointers,
    WikiSlugLists,
    SkillIdLists,
    TeamPointers,
    TeamWikiPointers,
    TeamSkillPointers,
    TeamWikiSlugLists,
    TeamSkillIdLists,
    TeamMembers,
}

// //////////////////////////////////////////////////////////////
//                        MAIN ENTRY POINT
// //////////////////////////////////////////////////////////////

/// @title Aegis Shared Multi-User Smart Contract
/// @notice The entry point for the Project Aegis NEAR Smart Contract.
/// @dev Implements a stateless, secure multi-tenant pointer index partitioned via composite keys.
///
/// Security hardening applied (audit cycle 2026-05-22 round 2):
///   F-02           — MAX_ENTRIES_PER_USER=1000 cap on wiki/skill Vec growth.
///                    Prevents storage staking attack + gas exhaustion via unbounded iteration.
///   F-06           — from_index cast from u64 → usize via safe checked_cast, panicking
///                    with a clear error on WASM32 overflow (u64 > usize::MAX on 32-bit).
///   MEDIUM-P2-5    — checked_mul().unwrap() replaced with checked_mul().unwrap_or_else(||
///                    panic_str("VAULT_ERROR_DEPOSIT_OVERFLOW")). Explicit overflow message.
///   P3-6           — VaultPointer now includes `version: u8` as first Borsh field.
///   P3-7           — validate_blob_id enforces base58 alphabet (no printable ASCII garbage).
///   P3-8           — Promise refunds log via env::log_str before dispatch for auditability.
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

    /// @notice Mapping of team IDs to team metadata.
    team_pointers: LookupMap<String, TeamMetadata>,

    /// @notice Partitioned mapping of team wiki page composite keys ("{team_id}:{slug}") to their Walrus pointers.
    team_wiki_pointers: LookupMap<String, VaultPointer>,

    /// @notice Partitioned mapping of team skill composite keys ("{team_id}:{skill_id}") to their Walrus pointers.
    team_skill_pointers: LookupMap<String, VaultPointer>,

    /// @notice Tracks the list of wiki slugs owned by each team for enumeration.
    team_wiki_slug_lists: LookupMap<String, Vec<String>>,

    /// @notice Tracks the list of skill IDs owned by each team for enumeration.
    team_skill_id_lists: LookupMap<String, Vec<String>>,

    /// @notice Mapping of team IDs to lists of team members with their permissions.
    team_members: LookupMap<String, Vec<TeamMember>>,
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
            team_pointers: LookupMap::new(StorageKey::TeamPointers),
            team_wiki_pointers: LookupMap::new(StorageKey::TeamWikiPointers),
            team_skill_pointers: LookupMap::new(StorageKey::TeamSkillPointers),
            team_wiki_slug_lists: LookupMap::new(StorageKey::TeamWikiSlugLists),
            team_skill_id_lists: LookupMap::new(StorageKey::TeamSkillIdLists),
            team_members: LookupMap::new(StorageKey::TeamMembers),
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

        let is_new = !self.wiki_pointers.contains_key(&composite_key);

        // F-02: Enforce max-entries cap before inserting a new entry.
        // Prevents unbounded Vec growth via repeated calls.
        if is_new {
            let current_count = self.wiki_slug_lists
                .get(&caller)
                .map_or(0, |v| v.len());
            if current_count >= vault::MAX_ENTRIES_PER_USER {
                env::panic_str("VAULT_ERROR_MAX_ENTRIES_REACHED");
            }
        }

        // Calculate storage byte changes manually
        let mut bytes_added = 0u64;
        let mut bytes_freed = 0u64;

        if is_new {
            // New key-value pair in wiki_pointers
            let key_size = 1 + 4 + composite_key.len() as u64;
            // version(1) + blob_id(4 + len) + content_sha256(4 + 64) + updated_at_ms(8)
            let val_size = 1 + 4 + blob_id.len() as u64 + 4 + content_sha256.len() as u64 + 8;
            bytes_added += key_size + val_size + 40;

            // Adding slug to wiki_slug_lists
            let has_list = self.wiki_slug_lists.contains_key(&caller);
            if !has_list {
                let list_key_size = 1 + 4 + caller.as_str().len() as u64;
                let list_val_size = 4 + 4 + slug.len() as u64;
                bytes_added += list_key_size + list_val_size + 40;
            } else {
                bytes_added += 4 + slug.len() as u64;
            }
        } else {
            // Updating existing pointer in wiki_pointers. Only blob_id length can change.
            let old_pointer = self.wiki_pointers.get(&composite_key).unwrap();
            let new_len = blob_id.len() as u64;
            let old_len = old_pointer.blob_id.len() as u64;
            if new_len > old_len {
                bytes_added += new_len - old_len;
            } else if old_len > new_len {
                bytes_freed += old_len - new_len;
            }
        }

        let pointer = VaultPointer {
            version: 1,
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

        // Process storage costs and refunds
        if bytes_added > bytes_freed {
            self._reconcile_storage_deposit(caller, bytes_added - bytes_freed);
        } else {
            let net_freed = bytes_freed - bytes_added;
            if net_freed > 0 {
                self._refund_released_storage(caller.clone(), net_freed);
            }
            let attached_deposit = env::attached_deposit();
            if attached_deposit.as_yoctonear() > 0 {
                env::log_str(&format!(
                    "VAULT_REFUND: returning {} yoctoNEAR full deposit to {} (no net storage added)",
                    attached_deposit.as_yoctonear(), caller
                ));
                Promise::new(caller).transfer(attached_deposit);
            }
        }
    }

    /// @notice Deletes a wiki page pointer and programmatically refunds its storage stake to the caller.
    pub fn remove_wiki_pointer(&mut self, slug: String) {
        let caller = env::predecessor_account_id();
        vault::validate_identifier(&slug);

        let composite_key = format!("{}:{}", caller.as_str(), slug);

        if !self.wiki_pointers.contains_key(&composite_key) {
            env::panic_str("VAULT_ERROR_NOT_FOUND");
        }

        let pointer = self.wiki_pointers.get(&composite_key).unwrap();
        let mut bytes_freed = 0u64;

        // Removing key-value pair in wiki_pointers
        let key_size = 1 + 4 + composite_key.len() as u64;
        let val_size = pointer.serialized_size();
        bytes_freed += key_size + val_size + 40;

        // Remove slug from the enumeration list
        if let Some(mut list) = self.wiki_slug_lists.get(&caller).cloned() {
            if let Some(pos) = list.iter().position(|x| x == &slug) {
                list.swap_remove(pos);
                if list.is_empty() {
                    self.wiki_slug_lists.remove(&caller);
                    // Freeing entire list entry
                    let list_key_size = 1 + 4 + caller.as_str().len() as u64;
                    let list_val_size = 4 + 4 + slug.len() as u64;
                    bytes_freed += list_key_size + list_val_size + 40;
                } else {
                    self.wiki_slug_lists.insert(caller.clone(), list);
                    // Freeing single element from Vec
                    bytes_freed += 4 + slug.len() as u64;
                }
            }
        }

        self.wiki_pointers.remove(&composite_key);

        // Process storage refund
        self._refund_released_storage(caller, bytes_freed);
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

        let is_new = !self.skill_pointers.contains_key(&composite_key);

        // F-02: Enforce max-entries cap before inserting a new entry.
        if is_new {
            let current_count = self.skill_id_lists
                .get(&caller)
                .map_or(0, |v| v.len());
            if current_count >= vault::MAX_ENTRIES_PER_USER {
                env::panic_str("VAULT_ERROR_MAX_ENTRIES_REACHED");
            }
        }

        // Calculate storage byte changes manually
        let mut bytes_added = 0u64;
        let mut bytes_freed = 0u64;

        if is_new {
            // New key-value pair in skill_pointers
            let key_size = 1 + 4 + composite_key.len() as u64;
            // version(1) + blob_id(4 + len) + content_sha256(4 + 64) + updated_at_ms(8)
            let val_size = 1 + 4 + blob_id.len() as u64 + 4 + content_sha256.len() as u64 + 8;
            bytes_added += key_size + val_size + 40;

            // Adding skill_id to skill_id_lists
            let has_list = self.skill_id_lists.contains_key(&caller);
            if !has_list {
                let list_key_size = 1 + 4 + caller.as_str().len() as u64;
                let list_val_size = 4 + 4 + skill_id.len() as u64;
                bytes_added += list_key_size + list_val_size + 40;
            } else {
                bytes_added += 4 + skill_id.len() as u64;
            }
        } else {
            // Updating existing pointer in skill_pointers. Only blob_id length can change.
            let old_pointer = self.skill_pointers.get(&composite_key).unwrap();
            let new_len = blob_id.len() as u64;
            let old_len = old_pointer.blob_id.len() as u64;
            if new_len > old_len {
                bytes_added += new_len - old_len;
            } else if old_len > new_len {
                bytes_freed += old_len - new_len;
            }
        }

        let pointer = VaultPointer {
            version: 1,
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

        // Process storage costs and refunds
        if bytes_added > bytes_freed {
            self._reconcile_storage_deposit(caller, bytes_added - bytes_freed);
        } else {
            let net_freed = bytes_freed - bytes_added;
            if net_freed > 0 {
                self._refund_released_storage(caller.clone(), net_freed);
            }
            let attached_deposit = env::attached_deposit();
            if attached_deposit.as_yoctonear() > 0 {
                env::log_str(&format!(
                    "VAULT_REFUND: returning {} yoctoNEAR full deposit to {} (no net storage added)",
                    attached_deposit.as_yoctonear(), caller
                ));
                Promise::new(caller).transfer(attached_deposit);
            }
        }
    }

    /// @notice Deletes a skill pointer and programmatically refunds its storage stake to the caller.
    pub fn remove_skill_pointer(&mut self, skill_id: String) {
        let caller = env::predecessor_account_id();
        vault::validate_identifier(&skill_id);

        let composite_key = format!("{}:{}", caller.as_str(), skill_id);

        if !self.skill_pointers.contains_key(&composite_key) {
            env::panic_str("VAULT_ERROR_NOT_FOUND");
        }

        let pointer = self.skill_pointers.get(&composite_key).unwrap();
        let mut bytes_freed = 0u64;

        // Removing key-value pair in skill_pointers
        let key_size = 1 + 4 + composite_key.len() as u64;
        let val_size = pointer.serialized_size();
        bytes_freed += key_size + val_size + 40;

        // Remove from enumeration list
        if let Some(mut list) = self.skill_id_lists.get(&caller).cloned() {
            if let Some(pos) = list.iter().position(|x| x == &skill_id) {
                list.swap_remove(pos);
                if list.is_empty() {
                    self.skill_id_lists.remove(&caller);
                    // Freeing entire list entry
                    let list_key_size = 1 + 4 + caller.as_str().len() as u64;
                    let list_val_size = 4 + 4 + skill_id.len() as u64;
                    bytes_freed += list_key_size + list_val_size + 40;
                } else {
                    self.skill_id_lists.insert(caller.clone(), list);
                    // Freeing single element from Vec
                    bytes_freed += 4 + skill_id.len() as u64;
                }
            }
        }

        self.skill_pointers.remove(&composite_key);

        // Process storage refund
        self._refund_released_storage(caller, bytes_freed);
    }

    // //////////////////////////////////////////////////////////////
    //                      TEAM VAULT METHODS
    // //////////////////////////////////////////////////////////////

    /// @notice Creates or updates a wiki page pointer for a team.
    /// @dev Validates inputs, enforces team write permission, and handles storage costs.
    /// @param team_id The team that owns the wiki page.
    /// @param slug Unique identifier for the wiki page.
    /// @param blob_id Walrus blob ID where the encrypted content is stored.
    /// @param content_sha256 SHA-256 hash of the original plaintext.
    #[payable]
    pub fn update_team_wiki_pointer(&mut self, team_id: String, slug: String, blob_id: String, content_sha256: String) {
        let caller = env::predecessor_account_id();
        
        // Validate inputs
        vault::validate_team_id(&team_id);
        vault::validate_identifier(&slug);
        vault::validate_blob_id(&blob_id);
        vault::validate_content_sha256(&content_sha256);
        
        // Validate team write permission
        self.validate_team_write_permission(&team_id, &caller);
        
        let composite_key = format!("{}:{}", team_id, slug);

        let is_new = !self.team_wiki_pointers.contains_key(&composite_key);

        // Enforce max-entries cap before inserting a new entry
        if is_new {
            let current_count = self.team_wiki_slug_lists
                .get(&team_id)
                .map_or(0, |v| v.len());
            if current_count >= vault::MAX_ENTRIES_PER_USER {
                env::panic_str("VAULT_ERROR_MAX_ENTRIES_REACHED");
            }
        }

        // Calculate storage byte changes manually
        let mut bytes_added = 0u64;
        let mut bytes_freed = 0u64;

        if is_new {
            // New key-value pair in team_wiki_pointers
            let key_size = 1 + 4 + composite_key.len() as u64;
            // version(1) + blob_id(4 + len) + content_sha256(4 + 64) + updated_at_ms(8)
            let val_size = 1 + 4 + blob_id.len() as u64 + 4 + content_sha256.len() as u64 + 8;
            bytes_added += key_size + val_size + 40;

            // Adding slug to team_wiki_slug_lists
            let has_list = self.team_wiki_slug_lists.contains_key(&team_id);
            if !has_list {
                let list_key_size = 1 + 4 + team_id.len() as u64;
                let list_val_size = 4 + 4 + slug.len() as u64;
                bytes_added += list_key_size + list_val_size + 40;
            } else {
                bytes_added += 4 + slug.len() as u64;
            }
        } else {
            // Updating existing pointer in team_wiki_pointers. Only blob_id length can change.
            let old_pointer = self.team_wiki_pointers.get(&composite_key).unwrap();
            let new_len = blob_id.len() as u64;
            let old_len = old_pointer.blob_id.len() as u64;
            if new_len > old_len {
                bytes_added += new_len - old_len;
            } else if old_len > new_len {
                bytes_freed += old_len - new_len;
            }
        }

        let pointer = VaultPointer {
            version: 1,
            blob_id,
            content_sha256,
            updated_at_ms: env::block_timestamp_ms(),
        };
        self.team_wiki_pointers.insert(composite_key, pointer);

        // Update enumeration list if a new key is added
        if is_new {
            let mut list = self.team_wiki_slug_lists.get(&team_id).cloned().unwrap_or_default();
            list.push(slug);
            self.team_wiki_slug_lists.insert(team_id.clone(), list);
        }

        // Process storage costs and refunds
        if bytes_added > bytes_freed {
            self._reconcile_storage_deposit(caller, bytes_added - bytes_freed);
        } else {
            let net_freed = bytes_freed - bytes_added;
            if net_freed > 0 {
                self._refund_released_storage(caller.clone(), net_freed);
            }
            let attached_deposit = env::attached_deposit();
            if attached_deposit.as_yoctonear() > 0 {
                env::log_str(&format!(
                    "VAULT_REFUND: returning {} yoctoNEAR full deposit to {} (no net storage added)",
                    attached_deposit.as_yoctonear(), caller
                ));
                Promise::new(caller).transfer(attached_deposit);
            }
        }
    }

    /// @notice Deletes a team wiki page pointer and refunds its storage stake.
    /// @dev Requires team write permission.
    /// @param team_id The team that owns the wiki page.
    /// @param slug Unique identifier for the wiki page.
    pub fn remove_team_wiki_pointer(&mut self, team_id: String, slug: String) {
        let caller = env::predecessor_account_id();
        
        vault::validate_team_id(&team_id);
        vault::validate_identifier(&slug);
        
        // Validate team write permission
        self.validate_team_write_permission(&team_id, &caller);

        let composite_key = format!("{}:{}", team_id, slug);

        if !self.team_wiki_pointers.contains_key(&composite_key) {
            env::panic_str("VAULT_ERROR_NOT_FOUND");
        }

        let pointer = self.team_wiki_pointers.get(&composite_key).unwrap();
        let mut bytes_freed = 0u64;

        // Removing key-value pair in team_wiki_pointers
        let key_size = 1 + 4 + composite_key.len() as u64;
        let val_size = pointer.serialized_size();
        bytes_freed += key_size + val_size + 40;

        // Remove slug from the enumeration list
        if let Some(mut list) = self.team_wiki_slug_lists.get(&team_id).cloned() {
            if let Some(pos) = list.iter().position(|x| x == &slug) {
                list.swap_remove(pos);
                if list.is_empty() {
                    self.team_wiki_slug_lists.remove(&team_id);
                    // Freeing entire list entry
                    let list_key_size = 1 + 4 + team_id.len() as u64;
                    let list_val_size = 4 + 4 + slug.len() as u64;
                    bytes_freed += list_key_size + list_val_size + 40;
                } else {
                    self.team_wiki_slug_lists.insert(team_id.clone(), list);
                    // Freeing single element from Vec
                    bytes_freed += 4 + slug.len() as u64;
                }
            }
        }

        self.team_wiki_pointers.remove(&composite_key);

        // Process storage refund
        self._refund_released_storage(caller, bytes_freed);
    }

    /// @notice Returns a paginated list of wiki slugs for a team.
    /// @dev Requires team membership.
    /// @param team_id The team to list wiki slugs for.
    /// @return Vec of wiki slug strings.
    pub fn list_team_wiki_slugs(&self, team_id: String) -> Vec<String> {
        // Validate team exists
        if !self.team_pointers.contains_key(&team_id) {
            env::panic_str("TEAM_NOT_FOUND");
        }
        
        // Validate caller is a team member
        let caller = env::predecessor_account_id();
        self.validate_team_membership(&team_id, &caller);
        
        self.team_wiki_slug_lists.get(&team_id).cloned().unwrap_or_default()
    }

    /// @notice Fetches a single team wiki page pointer.
    /// @dev Requires team membership.
    /// @param team_id The team that owns the wiki page.
    /// @param slug Unique identifier for the wiki page.
    /// @return Option<VaultPointer>.
    pub fn get_team_wiki_pointer(&self, team_id: String, slug: String) -> Option<VaultPointer> {
        // Validate inputs
        vault::validate_team_id(&team_id);
        vault::validate_identifier(&slug);
        
        // Validate caller is a team member
        let caller = env::predecessor_account_id();
        self.validate_team_membership(&team_id, &caller);

        let composite_key = format!("{}:{}", team_id, slug);
        self.team_wiki_pointers.get(&composite_key).cloned()
    }

    /// @notice Creates or updates a skill pointer for a team.
    /// @dev Validates inputs, enforces team write permission, and handles storage costs.
    /// @param team_id The team that owns the skill.
    /// @param skill_id Unique identifier for the skill.
    /// @param blob_id Walrus blob ID where the encrypted content is stored.
    /// @param content_sha256 SHA-256 hash of the original plaintext.
    #[payable]
    pub fn update_team_skill_pointer(&mut self, team_id: String, skill_id: String, blob_id: String, content_sha256: String) {
        let caller = env::predecessor_account_id();
        
        // Validate inputs
        vault::validate_team_id(&team_id);
        vault::validate_identifier(&skill_id);
        vault::validate_blob_id(&blob_id);
        vault::validate_content_sha256(&content_sha256);
        
        // Validate team write permission
        self.validate_team_write_permission(&team_id, &caller);
        
        let composite_key = format!("{}:{}", team_id, skill_id);

        let is_new = !self.team_skill_pointers.contains_key(&composite_key);

        // Enforce max-entries cap before inserting a new entry
        if is_new {
            let current_count = self.team_skill_id_lists
                .get(&team_id)
                .map_or(0, |v| v.len());
            if current_count >= vault::MAX_ENTRIES_PER_USER {
                env::panic_str("VAULT_ERROR_MAX_ENTRIES_REACHED");
            }
        }

        // Calculate storage byte changes manually
        let mut bytes_added = 0u64;
        let mut bytes_freed = 0u64;

        if is_new {
            // New key-value pair in team_skill_pointers
            let key_size = 1 + 4 + composite_key.len() as u64;
            // version(1) + blob_id(4 + len) + content_sha256(4 + 64) + updated_at_ms(8)
            let val_size = 1 + 4 + blob_id.len() as u64 + 4 + content_sha256.len() as u64 + 8;
            bytes_added += key_size + val_size + 40;

            // Adding skill_id to team_skill_id_lists
            let has_list = self.team_skill_id_lists.contains_key(&team_id);
            if !has_list {
                let list_key_size = 1 + 4 + team_id.len() as u64;
                let list_val_size = 4 + 4 + skill_id.len() as u64;
                bytes_added += list_key_size + list_val_size + 40;
            } else {
                bytes_added += 4 + skill_id.len() as u64;
            }
        } else {
            // Updating existing pointer in team_skill_pointers. Only blob_id length can change.
            let old_pointer = self.team_skill_pointers.get(&composite_key).unwrap();
            let new_len = blob_id.len() as u64;
            let old_len = old_pointer.blob_id.len() as u64;
            if new_len > old_len {
                bytes_added += new_len - old_len;
            } else if old_len > new_len {
                bytes_freed += old_len - new_len;
            }
        }

        let pointer = VaultPointer {
            version: 1,
            blob_id,
            content_sha256,
            updated_at_ms: env::block_timestamp_ms(),
        };
        self.team_skill_pointers.insert(composite_key, pointer);

        // Update enumeration list if a new key is added
        if is_new {
            let mut list = self.team_skill_id_lists.get(&team_id).cloned().unwrap_or_default();
            list.push(skill_id);
            self.team_skill_id_lists.insert(team_id.clone(), list);
        }

        // Process storage costs and refunds
        if bytes_added > bytes_freed {
            self._reconcile_storage_deposit(caller, bytes_added - bytes_freed);
        } else {
            let net_freed = bytes_freed - bytes_added;
            if net_freed > 0 {
                self._refund_released_storage(caller.clone(), net_freed);
            }
            let attached_deposit = env::attached_deposit();
            if attached_deposit.as_yoctonear() > 0 {
                env::log_str(&format!(
                    "VAULT_REFUND: returning {} yoctoNEAR full deposit to {} (no net storage added)",
                    attached_deposit.as_yoctonear(), caller
                ));
                Promise::new(caller).transfer(attached_deposit);
            }
        }
    }

    /// @notice Deletes a team skill pointer and refunds its storage stake.
    /// @dev Requires team write permission.
    /// @param team_id The team that owns the skill.
    /// @param skill_id Unique identifier for the skill.
    pub fn remove_team_skill_pointer(&mut self, team_id: String, skill_id: String) {
        let caller = env::predecessor_account_id();
        
        vault::validate_team_id(&team_id);
        vault::validate_identifier(&skill_id);
        
        // Validate team write permission
        self.validate_team_write_permission(&team_id, &caller);

        let composite_key = format!("{}:{}", team_id, skill_id);

        if !self.team_skill_pointers.contains_key(&composite_key) {
            env::panic_str("VAULT_ERROR_NOT_FOUND");
        }

        let pointer = self.team_skill_pointers.get(&composite_key).unwrap();
        let mut bytes_freed = 0u64;

        // Removing key-value pair in team_skill_pointers
        let key_size = 1 + 4 + composite_key.len() as u64;
        let val_size = pointer.serialized_size();
        bytes_freed += key_size + val_size + 40;

        // Remove from enumeration list
        if let Some(mut list) = self.team_skill_id_lists.get(&team_id).cloned() {
            if let Some(pos) = list.iter().position(|x| x == &skill_id) {
                list.swap_remove(pos);
                if list.is_empty() {
                    self.team_skill_id_lists.remove(&team_id);
                    // Freeing entire list entry
                    let list_key_size = 1 + 4 + team_id.len() as u64;
                    let list_val_size = 4 + 4 + skill_id.len() as u64;
                    bytes_freed += list_key_size + list_val_size + 40;
                } else {
                    self.team_skill_id_lists.insert(team_id.clone(), list);
                    // Freeing single element from Vec
                    bytes_freed += 4 + skill_id.len() as u64;
                }
            }
        }

        self.team_skill_pointers.remove(&composite_key);

        // Process storage refund
        self._refund_released_storage(caller, bytes_freed);
    }

    /// @notice Returns a paginated list of skill IDs for a team.
    /// @dev Requires team membership.
    /// @param team_id The team to list skill IDs for.
    /// @return Vec of skill ID strings.
    pub fn list_team_skill_ids(&self, team_id: String) -> Vec<String> {
        // Validate team exists
        if !self.team_pointers.contains_key(&team_id) {
            env::panic_str("TEAM_NOT_FOUND");
        }
        
        // Validate caller is a team member
        let caller = env::predecessor_account_id();
        self.validate_team_membership(&team_id, &caller);
        
        self.team_skill_id_lists.get(&team_id).cloned().unwrap_or_default()
    }

    /// @notice Fetches a single team skill pointer.
    /// @dev Requires team membership.
    /// @param team_id The team that owns the skill.
    /// @param skill_id Unique identifier for the skill.
    /// @return Option<VaultPointer>.
    pub fn get_team_skill_pointer(&self, team_id: String, skill_id: String) -> Option<VaultPointer> {
        // Validate inputs
        vault::validate_team_id(&team_id);
        vault::validate_identifier(&skill_id);
        
        // Validate caller is a team member
        let caller = env::predecessor_account_id();
        self.validate_team_membership(&team_id, &caller);

        let composite_key = format!("{}:{}", team_id, skill_id);
        self.team_skill_pointers.get(&composite_key).cloned()
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
        // F-06: Safe u64 → usize cast. On WASM32, usize is 32 bits — a from_index > u32::MAX
        // would silently truncate to 0 with `as usize`. Use checked cast to panic explicitly.
        let start = usize::try_from(from_index)
            .unwrap_or_else(|_| env::panic_str("VAULT_ERROR_INDEX_OUT_OF_RANGE"));
        
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
        // F-06: Safe u64 → usize cast.
        let start = usize::try_from(from_index)
            .unwrap_or_else(|_| env::panic_str("VAULT_ERROR_INDEX_OUT_OF_RANGE"));
        
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
    //                      TEAM MANAGEMENT METHODS
    // //////////////////////////////////////////////////////////////

    /// @notice Creates a new team with the calling account as the admin.
    /// @dev Validates team_id, ensures it doesn't exist, and initializes team storage.
    /// @param team_id Unique team identifier (alphanumeric + hyphen/underscore).
    /// @param name Human-readable team name.
    pub fn create_team(&mut self, team_id: String, name: String) {
        let caller = env::predecessor_account_id();
        
        // Validate team_id format
        vault::validate_team_id(&team_id);
        
        // Ensure team doesn't already exist
        if self.team_pointers.contains_key(&team_id) {
            env::panic_str("TEAM_ALREADY_EXISTS");
        }
        
        // Create team metadata
        let metadata = TeamMetadata {
            team_id: team_id.clone(),
            name,
            created_at: env::block_timestamp_ms(),
            created_by: caller.clone(),
        };
        
        // Store team metadata
        self.team_pointers.insert(team_id.clone(), metadata);
        
        // Initialize empty lists for team resources
        self.team_wiki_slug_lists.insert(team_id.clone(), Vec::new());
        self.team_skill_id_lists.insert(team_id.clone(), Vec::new());
        
        // Add creator as first member with Admin permission
        let mut members = Vec::new();
        members.push(TeamMember {
            account_id: caller.clone(),
            permission: Permission::Admin,
            joined_at: env::block_timestamp_ms(),
            added_by: caller,
        });
        self.team_members.insert(team_id, members);
    }

    /// @notice Adds a member to an existing team.
    /// @dev Requires caller to be a team admin and validates team member limits.
    /// @param team_id The team to add the member to.
    /// @param account_id NEAR account ID of the new member.
    /// @param permission Initial permission level (Read, Write, or Admin).
    #[payable]
    pub fn add_team_member(&mut self, team_id: String, account_id: AccountId, permission: Permission) {
        let caller = env::predecessor_account_id();
        
        // Validate team exists
        if !self.team_pointers.contains_key(&team_id) {
            env::panic_str("TEAM_NOT_FOUND");
        }
        
        // Validate caller is admin
        self.validate_team_admin_permission(&team_id, &caller);
        
        // Validate permission enum
        vault::validate_permission(&permission);
        
        // Check member limit
        if let Some(members) = self.team_members.get(&team_id) {
            if members.len() >= vault::MAX_TEAM_MEMBERS {
                env::panic_str("TEAM_MEMBER_LIMIT_REACHED");
            }
        }
        
        // Check if already a member
        if self.internal_is_team_member(&team_id, &account_id) {
            env::panic_str("TEAM_MEMBER_ALREADY_EXISTS");
        }
        
        // Add new member
        let mut members = self.team_members.get(&team_id).cloned().unwrap_or_default();
        members.push(TeamMember {
            account_id,
            permission,
            joined_at: env::block_timestamp_ms(),
            added_by: caller,
        });
        self.team_members.insert(team_id, members);
    }

    /// @notice Removes a member from a team.
    /// @dev Requires caller to be a team admin. Cannot remove self.
    /// @param team_id The team to remove the member from.
    /// @param account_id NEAR account ID of the member to remove.
    pub fn remove_team_member(&mut self, team_id: String, account_id: AccountId) {
        let caller = env::predecessor_account_id();
        
        // Validate team exists
        if !self.team_pointers.contains_key(&team_id) {
            env::panic_str("TEAM_NOT_FOUND");
        }
        
        // Validate caller is admin
        self.validate_team_admin_permission(&team_id, &caller);

        // Validate target member is in the team
        self.validate_team_membership(&team_id, &account_id);
        
        // Cannot remove self
        if account_id == caller {
            env::panic_str("TEAM_CANNOT_REMOVE_SELF");
        }
        
        // Remove member
        if let Some(mut members) = self.team_members.get(&team_id).cloned() {
            if let Some(pos) = members.iter().position(|m| m.account_id == account_id) {
                members.remove(pos);
                
                // If no members left, delete the team
                if members.is_empty() {
                    self.team_pointers.remove(&team_id);
                    self.team_wiki_slug_lists.remove(&team_id);
                    self.team_skill_id_lists.remove(&team_id);
                    self.team_members.remove(&team_id);
                } else {
                    self.team_members.insert(team_id, members);
                }
            }
        }
    }

    /// @notice Updates a team member's permission level.
    /// @dev Requires caller to be a team admin. Cannot reduce own permission.
    /// @param team_id The team containing the member.
    /// @param account_id NEAR account ID of the member to update.
    /// @param permission New permission level.
    pub fn update_team_member_permission(&mut self, team_id: String, account_id: AccountId, permission: Permission) {
        let caller = env::predecessor_account_id();
        
        // Validate team exists
        if !self.team_pointers.contains_key(&team_id) {
            env::panic_str("TEAM_NOT_FOUND");
        }
        
        // Validate caller is admin
        self.validate_team_admin_permission(&team_id, &caller);
        
        // Validate permission enum
        vault::validate_permission(&permission);
        
        // Cannot reduce own permission
        if account_id == caller {
            let current_permission = self.internal_get_team_member(&team_id, &caller)
                .map(|m| m.permission)
                .unwrap_or(Permission::Read);
            
            // Check if trying to reduce own permission
            if !matches!((current_permission, &permission),
                (Permission::Admin, &Permission::Admin) |
                (Permission::Write, &Permission::Write) |
                (Permission::Write, &Permission::Admin) |
                (Permission::Read, &Permission::Read) |
                (Permission::Read, &Permission::Write) |
                (Permission::Read, &Permission::Admin)) {
                env::panic_str("TEAM_CANNOT_REDUCE_OWN_PERMISSION");
            }
        }
        
        // Update permission
        if let Some(mut members) = self.team_members.get(&team_id).cloned() {
            if let Some(member) = members.iter_mut().find(|m| m.account_id == account_id) {
                member.permission = permission;
                self.team_members.insert(team_id, members);
            }
        }
    }

    /// @notice Lists all members of a team.
    /// @dev AUDIT-H4 FIX: Added caller membership check. Previously this was an open
    ///      view method — any NEAR account could enumerate the full membership list of
    ///      any private team, exposing account IDs and permission levels.
    ///      Now panics with TEAM_MEMBER_REQUIRED for non-members.
    /// @param team_id The team to list members from.
    /// @return Vec of TeamMember objects.
    pub fn list_team_members(&self, team_id: String) -> Vec<TeamMember> {
        let caller = env::predecessor_account_id();
        self.validate_team_membership(&team_id, &caller);
        self.team_members.get(&team_id).cloned().unwrap_or_default()
    }

    /// @notice Gets metadata for a specific team.
    /// @dev AUDIT-H4 FIX: Added caller membership check. Previously this was an open
    ///      view method — any NEAR account could read the team name and metadata of any
    ///      team without being a member. Now returns None gracefully for non-members
    ///      (does not panic — returning None leaks no information beyond "team not visible").
    /// @param team_id The team to retrieve metadata for.
    /// @return Option<TeamMetadata> — None if team doesn't exist OR caller is not a member.
    pub fn get_team_metadata(&self, team_id: String) -> Option<TeamMetadata> {
        let caller = env::predecessor_account_id();
        if !self.internal_is_team_member(&team_id, &caller) {
            return None; // Graceful non-disclosure — not a panic
        }
        self.team_pointers.get(&team_id).cloned()
    }

    /// @notice Public check for team membership (used by gateway).
    pub fn is_team_member(&self, team_id: String, account_id: AccountId) -> bool {
        self.internal_is_team_member(&team_id, &account_id)
    }

    /// @notice Public retrieval of a team member's record (used by gateway).
    pub fn get_team_member(&self, team_id: String, account_id: AccountId) -> Option<TeamMember> {
        self.internal_get_team_member(&team_id, &account_id)
    }

    // //////////////////////////////////////////////////////////////
    //                      TEAM ACCESS HELPERS
    // //////////////////////////////////////////////////////////////

    /// @notice Finds and returns a TeamMember by account_id in a team's member list.
    /// @dev Returns None if the team doesn't exist or the account is not a member.
    fn internal_get_team_member(&self, team_id: &str, account_id: &AccountId) -> Option<TeamMember> {
        self.team_members
            .get(team_id)
            .and_then(|members| {
                members.iter().find(|member| &member.account_id == account_id).cloned()
            })
    }

    /// @notice Checks if an account has Admin permission in a team.
    /// @dev Returns false if the team doesn't exist or account is not a member.
    fn is_team_admin(&self, team_id: &str, account_id: &AccountId) -> bool {
        self.internal_get_team_member(team_id, account_id)
            .map_or(false, |member| matches!(member.permission, Permission::Admin))
    }

    /// @notice Checks if an account is a member of a team (any permission level).
    /// @dev Returns false if the team doesn't exist or account is not a member.
    fn internal_is_team_member(&self, team_id: &str, account_id: &AccountId) -> bool {
        self.internal_get_team_member(team_id, account_id).is_some()
    }

    /// @notice Validates that the caller is a member of the specified team.
    /// @dev Panics with 'TEAM_MEMBER_REQUIRED' if validation fails.
    fn validate_team_membership(&self, team_id: &str, caller: &AccountId) {
        if !self.internal_is_team_member(team_id, caller) {
            env::panic_str("TEAM_MEMBER_REQUIRED");
        }
    }

    /// @notice Validates that the caller has Write or Admin permission in the team.
    /// @dev Panics with 'TEAM_PERMISSION_DENIED' if validation fails.
    fn validate_team_write_permission(&self, team_id: &str, caller: &AccountId) {
        let member = self.internal_get_team_member(team_id, caller);
        if !member.map_or(false, |m| matches!(m.permission, Permission::Write | Permission::Admin)) {
            env::panic_str("TEAM_PERMISSION_DENIED");
        }
    }

    /// @notice Validates that the caller has Admin permission in the team.
    /// @dev Panics with 'TEAM_PERMISSION_DENIED' if validation fails.
    fn validate_team_admin_permission(&self, team_id: &str, caller: &AccountId) {
        if !self.is_team_admin(team_id, caller) {
            env::panic_str("TEAM_PERMISSION_DENIED");
        }
    }

    // //////////////////////////////////////////////////////////////
    //                      INTERNAL UTILITIES
    // //////////////////////////////////////////////////////////////

    /// @notice Internal utility to reconcile storage costs.
    /// @dev Calculates bytes added, enforces deposit attached, and transfers excess back to user.
    fn _reconcile_storage_deposit(&self, caller: AccountId, bytes_added: u64) {
        if bytes_added > 0 {
            // MEDIUM-P2-5: checked_mul with explicit panic message instead of opaque unwrap().
            // Previous: checked_mul(...).unwrap() — panic message is "called Option::unwrap() on None"
            // Fix: named error code that operators can grep for in NEAR explorer.
            let required_deposit = env::storage_byte_cost()
                .as_yoctonear()
                .checked_mul(bytes_added as u128)
                .unwrap_or_else(|| env::panic_str("VAULT_ERROR_DEPOSIT_OVERFLOW"));
            let attached_deposit = env::attached_deposit().as_yoctonear();
            
            if attached_deposit < required_deposit {
                env::panic_str("VAULT_ERROR_INSUFFICIENT_DEPOSIT");
            }
            
            let excess = attached_deposit - required_deposit;
            if excess > 0 {
                // P3-8: Log the Promise before dispatching so it appears in the NEAR receipt log.
                // If the transfer Promise fails (insufficient balance on the contract account),
                // the log entry provides an audit trail that the refund was attempted.
                env::log_str(&format!(
                    "VAULT_REFUND: returning {} yoctoNEAR excess deposit to {}",
                    excess, caller
                ));
                Promise::new(caller).transfer(near_sdk::NearToken::from_yoctonear(excess));
            }
        } else {
            let attached_deposit = env::attached_deposit();
            if attached_deposit.as_yoctonear() > 0 {
                // P3-8: Log the full refund.
                env::log_str(&format!(
                    "VAULT_REFUND: returning {} yoctoNEAR full deposit to {} (no storage added)",
                    attached_deposit.as_yoctonear(), caller
                ));
                Promise::new(caller).transfer(attached_deposit);
            }
        }
    }

    /// @notice Internal utility to calculate released bytes and refund locked NEAR stake.
    fn _refund_released_storage(&self, caller: AccountId, bytes_freed: u64) {
        if bytes_freed > 0 {
            // MEDIUM-P2-5: checked_mul with explicit panic message.
            let released_stake = env::storage_byte_cost()
                .as_yoctonear()
                .checked_mul(bytes_freed as u128)
                .unwrap_or_else(|| env::panic_str("VAULT_ERROR_REFUND_OVERFLOW"));
            if released_stake > 0 {
                // P3-8: Log the storage release refund for auditability.
                env::log_str(&format!(
                    "VAULT_REFUND: releasing {} yoctoNEAR storage stake ({} bytes freed) to {}",
                    released_stake, bytes_freed, caller
                ));
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
        // P3-7: Use a valid base58 blob_id (no invalid chars like spaces or slashes, or l, I, 0, O)
        let blob_id = "CertfedBdBHashBase58Ab".to_string();
        let content_sha256 = "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string();

        contract.update_wiki_pointer(slug.clone(), blob_id.clone(), content_sha256.clone());

        let retrieved = contract.get_wiki_pointer(alice.clone(), slug).expect("Should find pointer");
        assert_eq!(retrieved.blob_id, blob_id);
        assert_eq!(retrieved.content_sha256, content_sha256);
        // P3-6: Verify version field is set correctly
        assert_eq!(retrieved.version, 1, "VaultPointer version must be 1");
    }

    #[test]
    fn test_multi_user_isolation() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 100_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();
        contract.update_wiki_pointer("shared-slug".to_string(), "BaceBase58VadXYZabcdef1234".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());

        // Bob tries to read Alice's data via Bob's identity context
        let bob: AccountId = "bob.near".parse().unwrap();
        testing_env!(get_context(bob.clone(), 100_000_000_000_000_000_000_000));
        
        let retrieved_as_bob = contract.get_wiki_pointer(bob.clone(), "shared-slug".to_string());
        assert!(retrieved_as_bob.is_none(), "Bob should not see a pointer under his own prefix");

        // Bob tries to read Alice's pointer by supplying Alice's account ID (allowed since view calls are public)
        let retrieved_as_public = contract.get_wiki_pointer(alice.clone(), "shared-slug".to_string()).unwrap();
        assert_eq!(retrieved_as_public.blob_id, "BaceBase58VadXYZabcdef1234");

        // Bob tries to delete Alice's pointer
        testing_env!(get_context(bob.clone(), 0));
    }

    #[test]
    #[should_panic(expected = "VAULT_ERROR_NOT_FOUND")]
    fn test_unauthorized_delete_reverts() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 100_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();
        contract.update_wiki_pointer("shared-slug".to_string(), "BaceBase58VadXYZabcdef1234".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());

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
        contract.update_wiki_pointer("slug".to_string(), "VadBase58B".to_string(), "short-hash".to_string());
    }

    #[test]
    fn test_pagination_and_lists() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 500_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();

        contract.update_wiki_pointer("slug-1".to_string(), "VadBase58B111111111111111".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());
        contract.update_wiki_pointer("slug-2".to_string(), "VadBase58B222222222222222".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());
        contract.update_wiki_pointer("slug-3".to_string(), "VadBase58B333333333333333".to_string(), "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string());

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

    /// F-02: Verify that MAX_ENTRIES_PER_USER cap is enforced.
    /// This test registers MAX_ENTRIES_PER_USER entries and verifies the (MAX+1)th panics.
    /// NOTE: This test is marked ignore because registering 1000 entries is expensive in a unit test.
    /// Run with: cargo test test_max_entries_cap -- --ignored
    #[test]
    #[ignore]
    #[should_panic(expected = "VAULT_ERROR_MAX_ENTRIES_REACHED")]
    fn test_max_entries_cap() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 999_999_999_999_999_999_999_999_999));
        let mut contract = AegisContract::new();

        for i in 0..vault::MAX_ENTRIES_PER_USER {
            let slug = format!("slug-{:04}", i);
            contract.update_wiki_pointer(
                slug,
                // TEST-FIX-4: Use URL-safe Base64 blob ID (Walrus format)
                "M4hsZGQ1oCktdzegB6HnI6Mi28S2nqOPHxK-W7-4BUk".to_string(),
                "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
            );
        }

        // This (MAX_ENTRIES_PER_USER + 1)th call must panic
        contract.update_wiki_pointer(
            "slug-overflow".to_string(),
            "M4hsZGQ1oCktdzegB6HnI6Mi28S2nqOPHxK-W7-4BUk".to_string(),
            "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        );
    }

    /// P3-7 CORRECTION: Validate that invalid blob_id characters are rejected.
    /// Walrus uses URL-safe Base64 [A-Za-z0-9_-]. Space and '/' are invalid in that alphabet.
    #[test]
    #[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
    fn test_blob_id_invalid_chars_rejected() {
        let alice: AccountId = "alice.near".parse().unwrap();
        testing_env!(get_context(alice.clone(), 100_000_000_000_000_000_000_000));
        let mut contract = AegisContract::new();
        // Blob ID with chars invalid in URL-safe Base64: space and slash
        // Note: '0', 'O', 'I', 'l' are NOW VALID (URL-safe Base64 is not Base58)
        contract.update_wiki_pointer(
            "slug".to_string(),
            "blob/id with spaces".to_string(), // space and '/' are invalid
            "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        );
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


