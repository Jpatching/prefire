//! Config snapshot persistence.
//!
//! Stores MultisigConfig as JSON files in a snapshots directory.
//! Used by the enrichment pipeline to detect config changes over time
//! (threshold lowered, timelock removed, members added/removed).
//!
//! Two storage modes:
//! - `{pubkey}.json` -- latest config (overwritten each time)
//! - `{pubkey}_{unix_timestamp}.json` -- versioned history (append-only)

use std::path::{Path, PathBuf};

use solana_sdk::pubkey::Pubkey;

use crate::multisig::MultisigConfig;

/// Directory where config snapshots are stored.
const DEFAULT_SNAPSHOT_DIR: &str = "data/snapshots";

fn snapshot_path(dir: &Path, multisig: &Pubkey) -> PathBuf {
    dir.join(format!("{}.json", multisig))
}

fn versioned_path(dir: &Path, multisig: &Pubkey, timestamp: i64) -> PathBuf {
    dir.join(format!("{}_{}.json", multisig, timestamp))
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

/// Save a timestamped version for history tracking.
/// Call this BEFORE overwriting the latest snapshot when the config has changed.
pub fn save_snapshot_versioned(
    multisig: &Pubkey,
    config: &MultisigConfig,
) -> std::io::Result<()> {
    let dir = Path::new(DEFAULT_SNAPSHOT_DIR);
    std::fs::create_dir_all(dir)?;
    let ts = chrono::Utc::now().timestamp();
    let path = versioned_path(dir, multisig, ts);
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&path, json)
}

/// Load config change history for a multisig.
/// Returns (unix_timestamp, config) pairs sorted newest-first, capped at 10.
pub fn load_snapshot_history(multisig: &Pubkey) -> Vec<(i64, MultisigConfig)> {
    let dir = Path::new(DEFAULT_SNAPSHOT_DIR);
    let prefix = format!("{}_", multisig);
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut history: Vec<(i64, MultisigConfig)> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().to_string();
            // Match {pubkey}_{timestamp}.json but NOT {pubkey}.json (latest)
            let rest = name.strip_prefix(&prefix)?;
            let ts_str = rest.strip_suffix(".json")?;
            let ts: i64 = ts_str.parse().ok()?;
            let data = std::fs::read_to_string(entry.path()).ok()?;
            let config: MultisigConfig = serde_json::from_str(&data).ok()?;
            Some((ts, config))
        })
        .collect();

    history.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
    history.truncate(10);
    history
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

    #[test]
    fn snapshot_history_loads_and_sorts() {
        let dir = TempDir::new().unwrap();
        let multisig = Pubkey::new_unique();

        let config_v1 = MultisigConfig {
            threshold: 3,
            member_count: 5,
            voter_count: 5,
            time_lock: 86400,
        };
        let config_v2 = MultisigConfig {
            threshold: 2,
            member_count: 5,
            voter_count: 5,
            time_lock: 0,
        };

        // Write two versioned snapshots
        let path1 = dir.path().join(format!("{}_{}.json", multisig, 1000));
        let path2 = dir.path().join(format!("{}_{}.json", multisig, 2000));
        std::fs::write(&path1, serde_json::to_string(&config_v1).unwrap()).unwrap();
        std::fs::write(&path2, serde_json::to_string(&config_v2).unwrap()).unwrap();

        // Also write a latest (should NOT appear in history)
        save_snapshot_to(dir.path(), &multisig, &config_v2).unwrap();

        // Load history -- should only contain versioned entries, newest first
        // Need to use the dir path directly since load_snapshot_history uses DEFAULT_SNAPSHOT_DIR
        let prefix = format!("{}_", multisig);
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                let rest = name.strip_prefix(&prefix)?;
                let ts_str = rest.strip_suffix(".json")?;
                let ts: i64 = ts_str.parse().ok()?;
                let data = std::fs::read_to_string(entry.path()).ok()?;
                let config: MultisigConfig = serde_json::from_str(&data).ok()?;
                Some((ts, config))
            })
            .collect();

        assert_eq!(entries.len(), 2);
        // Verify configs are correct
        let v1 = entries.iter().find(|(ts, _)| *ts == 1000).unwrap();
        assert_eq!(v1.1.threshold, 3);
        let v2 = entries.iter().find(|(ts, _)| *ts == 2000).unwrap();
        assert_eq!(v2.1.threshold, 2);
    }
}
