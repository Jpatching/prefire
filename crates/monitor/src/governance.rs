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
pub fn classify_instruction(instruction_name: &str, _signature: &str) -> Option<GovernanceEvent> {
    match instruction_name {
        "ProposalCreate" => Some(GovernanceEvent::ProposalCreated {
            multisig: Pubkey::default(),
            description: instruction_name.to_string(),
        }),
        "ProposalApprove" => Some(GovernanceEvent::ProposalApproved {
            multisig: Pubkey::default(),
            description: instruction_name.to_string(),
        }),
        "ProposalActivate" => Some(GovernanceEvent::ProposalActivated {
            multisig: Pubkey::default(),
            description: instruction_name.to_string(),
        }),
        "ConfigTransactionCreate" => Some(GovernanceEvent::ConfigChange {
            multisig: Pubkey::default(),
            description: instruction_name.to_string(),
        }),
        "MultisigAddMember" => Some(GovernanceEvent::ConfigChange {
            multisig: Pubkey::default(),
            description: instruction_name.to_string(),
        }),
        "VaultTransactionCreate" => Some(GovernanceEvent::VaultTransfer {
            multisig: Pubkey::default(),
            description: instruction_name.to_string(),
        }),
        "VaultTransactionExecute" => Some(GovernanceEvent::VaultTransfer {
            multisig: Pubkey::default(),
            description: instruction_name.to_string(),
        }),
        "SpendingLimitUse" => Some(GovernanceEvent::VaultTransfer {
            multisig: Pubkey::default(),
            description: instruction_name.to_string(),
        }),

        _ => None,
    }
}
