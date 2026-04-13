use std::str::FromStr;
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
