use borsh::BorshDeserialize;
use serde::Serialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::hash::hash;
use solana_sdk::pubkey::Pubkey;
use thiserror::Error;

const ANCHOR_DISCRIMINATOR_LEN: usize = 8;

/// Compute the Anchor discriminator for the Multisig account.
/// Anchor uses sha256("account:<Name>")[..8].
pub fn multisig_discriminator() -> [u8; 8] {
    let h = hash(b"account:Multisig");
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&h.to_bytes()[..8]);
    disc
}

/// Permissions bitmask for a multisig member.
/// Initiate=1, Vote=2, Execute=4.
#[derive(BorshDeserialize, Debug, Clone, Serialize)]
pub struct Permissions {
    pub mask: u8,
}

impl Permissions {
    pub fn can_vote(&self) -> bool {
        self.mask & 0b010 != 0
    }

    pub fn can_execute(&self) -> bool {
        self.mask & 0b100 != 0
    }
}

#[derive(BorshDeserialize, Debug, Clone, Serialize)]
pub struct Member {
    pub key: Pubkey,
    pub permissions: Permissions,
}

/// Squads v4 Multisig account, deserialized from on-chain data.
/// Field order matches the Anchor-serialized layout exactly.
#[derive(BorshDeserialize, Debug, Clone)]
pub struct MultisigAccount {
    pub create_key: Pubkey,
    pub config_authority: Pubkey,
    pub threshold: u16,
    pub time_lock: u32,
    pub transaction_index: u64,
    pub stale_transaction_index: u64,
    pub rent_collector: Option<Pubkey>,
    pub bump: u8,
    pub members: Vec<Member>,
}

/// The subset of multisig config that scoring needs.
/// Extracted from the full MultisigAccount to keep the scoring interface clean.
#[derive(Debug, Clone, Serialize)]
pub struct MultisigConfig {
    pub threshold: u16,
    pub member_count: usize,
    pub voter_count: usize,
    pub time_lock: u32,
}

impl From<&MultisigAccount> for MultisigConfig {
    fn from(account: &MultisigAccount) -> Self {
        Self {
            threshold: account.threshold,
            member_count: account.members.len(),
            voter_count: account
                .members
                .iter()
                .filter(|m| m.permissions.can_vote())
                .count(),
            time_lock: account.time_lock,
        }
    }
}

#[derive(Debug, Error)]
pub enum MultisigError {
    #[error("rpc error: {0}")]
    Rpc(#[from] solana_client::client_error::ClientError),
    #[error("account data too short (got {0} bytes, need at least 9)")]
    DataTooShort(usize),
    #[error("borsh deserialization failed: {0}")]
    Deserialize(String),
}

/// Fetch and deserialize a Squads v4 Multisig account from on-chain data.
/// Skips the 8-byte Anchor discriminator, then Borsh-deserializes the rest.
pub async fn fetch_multisig_config(
    rpc: &RpcClient,
    multisig_pubkey: &Pubkey,
) -> Result<MultisigAccount, MultisigError> {
    let account = rpc.get_account(multisig_pubkey).await?;
    let data = &account.data;

    if data.len() < ANCHOR_DISCRIMINATOR_LEN + 1 {
        return Err(MultisigError::DataTooShort(data.len()));
    }

    let mut slice = &data[ANCHOR_DISCRIMINATOR_LEN..];
    MultisigAccount::deserialize(&mut slice)
        .map_err(|e| MultisigError::Deserialize(e.to_string()))
}
