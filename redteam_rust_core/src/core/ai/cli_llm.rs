use anyhow::{Result, Context};
use std::time::Duration;
use tokio::process::Command;

pub struct CliLlmConfig {
    pub binary: String,
    pub prompt_flag: &'static str,
    pub quiet_flag: Option<&'static str>,
    pub timeout_secs: u64,
}

pub async fn run_cli_prompt(
    config: &CliLlmConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<String> {
    let full_prompt = format!("{}\n\n{}", system_prompt, user_prompt);
    let mut cmd = Command::new(&config.binary);
    if let Some(quiet) = config.quiet_flag {
        cmd.arg(quiet);
    }
    cmd.arg(config.prompt_flag).arg(&full_prompt);

    let output = tokio::time::timeout(
        Duration::from_secs(config.timeout_secs),
        cmd.output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("CLI LLM '{}' timeout after {}s", config.binary, config.timeout_secs))?
    .with_context(|| format!("CLI LLM '{}' process failed", config.binary))?;

    let text = String::from_utf8_lossy(&output.stdout).to_string();
    if text.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("CLI LLM '{}' returned empty output. stderr: {}", config.binary, stderr);
    }
    Ok(text)
}
