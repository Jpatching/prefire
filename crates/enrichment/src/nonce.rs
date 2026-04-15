use std::str::FromStr;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::RpcProgramAccountsConfig;
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_sdk::pubkey::Pubkey;

/// The RecentBlockhashes sysvar address. This sysvar is required by the
/// AdvanceNonceAccount System Program instruction and essentially never
/// appears in normal transactions. Its presence is the most reliable
/// indicator of durable nonce usage.
const RECENT_BLOCKHASHES_SYSVAR: &str = "SysvarRecentB1ockHashes11111111111111111111";

/// Check if a transaction used a durable nonce.
///
/// Primary check: the RecentBlockhashes sysvar in account keys.
/// Fallback: "AdvanceNonceAccount" in log messages (in case some
/// future program version logs it explicitly).
///
/// Durable nonces are a strong attack signal -- they let someone pre-sign
/// a transaction days in advance, then submit it instantly when ready.
pub fn uses_durable_nonce(log_messages: &[String], account_keys: &[Pubkey]) -> bool {
    // Primary: check for RecentBlockhashes sysvar in account keys
    if let Ok(sysvar) = Pubkey::from_str(RECENT_BLOCKHASHES_SYSVAR) {
        if account_keys.iter().any(|k| *k == sysvar) {
            return true;
        }
    }

    // Fallback: check log messages
    log_messages
        .iter()
        .any(|line| line.contains("AdvanceNonceAccount"))
}

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const NONCE_ACCOUNT_SIZE: u64 = 80;
/// In a nonce account: 4 bytes version + 4 bytes state + 32 bytes authority
const NONCE_AUTHORITY_OFFSET: usize = 8;

/// Fetch the pubkeys of all durable nonce accounts where `authority` is the authority.
/// Returns the account addresses (not the account data).
pub async fn fetch_nonce_accounts(
    rpc: &RpcClient,
    authority: &Pubkey,
) -> Result<Vec<Pubkey>, Box<dyn std::error::Error + Send + Sync>> {
    let system_program = Pubkey::from_str(SYSTEM_PROGRAM)?;

    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::DataSize(NONCE_ACCOUNT_SIZE),
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                NONCE_AUTHORITY_OFFSET,
                authority.to_bytes().to_vec(),
            )),
        ]),
        ..Default::default()
    };

    let accounts = rpc
        .get_program_accounts_with_config(&system_program, config)
        .await?;

    Ok(accounts.into_iter().map(|(pubkey, _)| pubkey).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nonce_from_sysvar_in_account_keys() {
        // The RecentBlockhashes sysvar is ONLY present when AdvanceNonceAccount
        // is called. If it's in account_keys, a durable nonce is being used.
        let sysvar = Pubkey::from_str(RECENT_BLOCKHASHES_SYSVAR).unwrap();
        let keys = vec![Pubkey::new_unique(), sysvar, Pubkey::new_unique()];
        assert!(uses_durable_nonce(&[], &keys));
    }

    #[test]
    fn no_false_positive_without_sysvar() {
        // Normal transaction: no RecentBlockhashes sysvar, no nonce log.
        let keys = vec![Pubkey::new_unique(), Pubkey::new_unique()];
        assert!(!uses_durable_nonce(&[], &keys));
    }

    #[test]
    fn detects_nonce_from_log_fallback() {
        // Even if sysvar isn't in keys, the log message fallback works.
        let logs = vec!["Program log: AdvanceNonceAccount".to_string()];
        assert!(uses_durable_nonce(&logs, &[]));
    }

    #[test]
    fn empty_inputs_return_false() {
        assert!(!uses_durable_nonce(&[], &[]));
    }
}
