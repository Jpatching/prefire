use serde::Serialize;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status_client_types::UiTransactionTokenBalance;

/// What type of governance action was detected.
/// The multisig address lives on MonitoredEvent, not here --
/// classify_instruction doesn't have access to account keys.
#[derive(Debug, Clone, Serialize)]
pub enum GovernanceEvent {
    ProposalCreated { description: String },
    ProposalApproved { description: String },
    ProposalActivated { description: String },
    ConfigChange { description: String },
    VaultTransfer { description: String },
}

/// A governance event with full transaction context.
/// Live mode leaves signers/account_keys empty (backfilled in enrichment).
/// Replay mode populates everything from getTransaction.
#[derive(Serialize, Clone, Debug)]
pub struct MonitoredEvent {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub event: GovernanceEvent,
    pub multisig: Pubkey,
    pub signers: Vec<Pubkey>,
    pub account_keys: Vec<Pubkey>,
    #[serde(skip)]
    pub log_messages: Vec<String>,
    /// SOL balances before/after transaction (from getTransaction metadata).
    /// Empty in live WebSocket mode (balance data not available until replay).
    #[serde(skip)]
    pub pre_balances: Vec<u64>,
    #[serde(skip)]
    pub post_balances: Vec<u64>,
    /// Token balances before/after transaction.
    #[serde(skip)]
    pub pre_token_balances: Vec<UiTransactionTokenBalance>,
    #[serde(skip)]
    pub post_token_balances: Vec<UiTransactionTokenBalance>,
}

pub fn classify_instruction(instruction_name: &str) -> Option<GovernanceEvent> {
    match instruction_name {
        "ProposalCreate" => Some(GovernanceEvent::ProposalCreated {
            description: instruction_name.to_string(),
        }),
        "ProposalApprove" => Some(GovernanceEvent::ProposalApproved {
            description: instruction_name.to_string(),
        }),
        "ProposalActivate" => Some(GovernanceEvent::ProposalActivated {
            description: instruction_name.to_string(),
        }),
        "ConfigTransactionCreate" | "MultisigAddMember" => Some(GovernanceEvent::ConfigChange {
            description: instruction_name.to_string(),
        }),
        "VaultTransactionCreate" | "VaultTransactionExecute" | "SpendingLimitUse" => {
            Some(GovernanceEvent::VaultTransfer {
                description: instruction_name.to_string(),
            })
        }
        _ => None,
    }
}
