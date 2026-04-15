//! Config snapshot persistence.
//!
//! Stores MultisigConfig as JSON files in a snapshots directory.
//! Used by the enrichment pipeline to detect config changes over time
//! (threshold lowered, timelock removed, members added/removed).

use std::path::{Path, PathBuf};

use solana_sdk::pubkey::Pubkey;

use crate::multisig::MultisigConfig;

/// Directory where config snapshots are stored.
const DEFAULT_SNAPSHOT_DIR: &str = "data/snapshots";

fn snapshot_path(dir: &Path, multisig: &Pubkey) -> PathBuf {
    dir.join(format!("{}.json", multisig))
}

/// Load a previously saved config snapshot for a multisig.
/// Returns None if no snapshot exists (first time seeing this multisig).
pub fn load_snapshot(multisig: &Pubkey) -> Option<MultisigConfig> {
    load_snapshot_from(Path::new(DEFAULT_SNAPSHOT_DIR), multisig)
}

/// Load from a specific directory (for testing).
pub fn load_snapshot_from(dir: &Path, multisig: &Pubkey) -> Option<MultisigConfig> {
    let path = snapshot_path(dir, multisig);
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Save the current config as a snapshot for future comparison.
pub fn save_snapshot(multisig: &Pubkey, config: &MultisigConfig) -> std::io::Result<()> {
    save_snapshot_to(Path::new(DEFAULT_SNAPSHOT_DIR), multisig, config)
}

/// Save to a specific directory (for testing).
pub fn save_snapshot_to(
    dir: &Path,
    multisig: &Pubkey,
    config: &MultisigConfig,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = snapshot_path(dir, multisig);
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&path, json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn roundtrip_snapshot() {
        let dir = TempDir::new().unwrap();
        let multisig = Pubkey::new_unique();
        let config = MultisigConfig {
            threshold: 3,
            member_count: 7,
            voter_count: 5,
            time_lock: 86400,
        };

        // No snapshot yet
        assert!(load_snapshot_from(dir.path(), &multisig).is_none());

        // Save and reload
        save_snapshot_to(dir.path(), &multisig, &config).unwrap();
        let loaded = load_snapshot_from(dir.path(), &multisig).unwrap();
        assert_eq!(loaded.threshold, 3);
        assert_eq!(loaded.time_lock, 86400);
    }
}
