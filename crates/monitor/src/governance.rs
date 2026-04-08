use serde::Serialize;
use solana_sdk::pubkey::Pubkey;

#[derive(Debug, Clone, Serialize)]
pub enum GovernanceEvent {
    ConfigChange {
        multisig: Pubkey,
        description: String,
    },
    VaultTransfer {
        multisig: Pubkey,
        description: String,
    },
    ProposalApproved {
        multisig: Pubkey,
        description: String,
    },
    ProposalActivated {
        multisig: Pubkey,
        description: String,
    },
    ProposalCreated {
        multisig: Pubkey,
        description: String,
    },
}
