const SQUADS_PROGRAM_ID: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

pub fn extract_squads_instructions(logs: &[String]) -> Vec<String> {
    let mut depth = 0;
    let mut instructions = Vec::new();

    for line in logs {
        if line.contains(&format!("{} invoke", SQUADS_PROGRAM_ID)) {
            depth += 1;
        }
        if line.contains(&format!("{} success", SQUADS_PROGRAM_ID)) {
            depth -= 1;
        }
        if depth > 0 {
            if let Some(name) = line.strip_prefix("Program log: Instruction: ") {
                instructions.push(name.to_string());
            }
        }
    }
    instructions
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These logs match real Squads v4 transaction output format.
    /// The parser tracks invoke depth to only extract Squads instructions,
    /// ignoring nested program calls (like System Program transfers).
    #[test]
    fn extracts_squads_instruction_names() {
        let logs = vec![
            format!("Program {} invoke [1]", SQUADS_PROGRAM_ID),
            "Program log: Instruction: ProposalCreate".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            format!("Program {} success", SQUADS_PROGRAM_ID),
        ];
        let result = extract_squads_instructions(&logs);
        assert_eq!(result, vec!["ProposalCreate"]);
    }

    #[test]
    fn extracts_multiple_instructions() {
        // A single transaction can contain multiple Squads instructions
        // (e.g., the Drift exploit TX1 had VaultTransactionCreate + ProposalCreate + ProposalApprove)
        let logs = vec![
            format!("Program {} invoke [1]", SQUADS_PROGRAM_ID),
            "Program log: Instruction: VaultTransactionCreate".to_string(),
            format!("Program {} success", SQUADS_PROGRAM_ID),
            format!("Program {} invoke [1]", SQUADS_PROGRAM_ID),
            "Program log: Instruction: ProposalCreate".to_string(),
            format!("Program {} success", SQUADS_PROGRAM_ID),
            format!("Program {} invoke [1]", SQUADS_PROGRAM_ID),
            "Program log: Instruction: ProposalApprove".to_string(),
            format!("Program {} success", SQUADS_PROGRAM_ID),
        ];
        let result = extract_squads_instructions(&logs);
        assert_eq!(
            result,
            vec!["VaultTransactionCreate", "ProposalCreate", "ProposalApprove"]
        );
    }

    #[test]
    fn ignores_non_squads_logs() {
        let logs = vec![
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program log: Instruction: Transfer".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
        ];
        let result = extract_squads_instructions(&logs);
        assert!(result.is_empty());
    }

    #[test]
    fn empty_logs_return_empty() {
        let result = extract_squads_instructions(&[]);
        assert!(result.is_empty());
    }
}
