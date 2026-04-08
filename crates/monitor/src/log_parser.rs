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
