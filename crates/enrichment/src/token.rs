use serde::Serialize;
use solana_transaction_status_client_types::UiTransactionTokenBalance;

/// A detected token transfer in a governance transaction.
/// Negative amount_delta = outflow from vault (suspicious for drain attacks).
#[derive(Debug, Clone, Serialize)]
pub struct TokenTransferInfo {
    pub mint: String,
    pub amount_delta: i128,
    pub decimals: u8,
}

/// Compute SOL transfer amount from pre/post lamport balances.
/// Returns the largest single-account outflow in SOL (negative = outflow).
/// We look at the vault account's balance change, not the fee payer's.
pub fn sol_outflow_lamports(pre_balances: &[u64], post_balances: &[u64]) -> i128 {
    pre_balances
        .iter()
        .zip(post_balances.iter())
        .map(|(pre, post)| *post as i128 - *pre as i128)
        // Most negative delta = largest outflow
        .min()
        .unwrap_or(0)
}

/// Extract token balance changes from pre/post token balance snapshots.
/// Matches accounts by (account_index, mint) and computes deltas.
pub fn extract_token_transfers(
    pre: &[UiTransactionTokenBalance],
    post: &[UiTransactionTokenBalance],
) -> Vec<TokenTransferInfo> {
    let mut transfers = Vec::new();

    for post_bal in post {
        // Find matching pre-balance by account index and mint
        let pre_amount = pre
            .iter()
            .find(|p| p.account_index == post_bal.account_index && p.mint == post_bal.mint)
            .and_then(|p| p.ui_token_amount.amount.parse::<i128>().ok())
            .unwrap_or(0);

        let post_amount = post_bal
            .ui_token_amount
            .amount
            .parse::<i128>()
            .unwrap_or(0);

        let delta = post_amount.checked_sub(pre_amount).unwrap_or(0);
        if delta != 0 {
            transfers.push(TokenTransferInfo {
                mint: post_bal.mint.clone(),
                amount_delta: delta,
                decimals: post_bal.ui_token_amount.decimals,
            });
        }
    }

    transfers
}
