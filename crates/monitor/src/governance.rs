use solana_sdk::pubkey::Pubkey;

#[derive(Debug, Clone)]
pub enum GovernanceEvent {
    ConfigChange { multisig: Pubkey, description: String },
    VaultTransfer { multisig: Pubkey, description: String },
    ProprosalApproved { multisig: Pubkey, description: String},
    ProprosalActivated { multisig: Pubkey, description: String},
}
