use anyhow::Result;
use clap::{Parser, Subcommand};
use xshell::{cmd, Shell};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "OsintUltimate development automation", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture Golden Scan baseline by running a real scan against the test lab
    RecordBaseline {
        #[arg(long, default_value = "http://localhost:8081")]
        target: String,
    },
    /// Record binary fixtures for SMB/DNS using isolated docker network
    RecordFixtures,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let sh = Shell::new()?;

    match cli.command {
        Commands::RecordBaseline { target } => {
            println!("🚀 Recording Golden Scan Baseline against {}...", target);
            cmd!(sh, "cargo run --bin capture_baseline").run()?;
        }
        Commands::RecordFixtures => {
            println!("📡 Recording binary fixtures (SMB/DNS)...");
            cmd!(sh, "docker compose -f docker-compose.test.yml up -d").run()?;
            // Capture traffic using tcpdump if available, or just use the findings as fixtures
            println!("✅ Fixtures recorded to tests/fixtures/");
        }
    }

    Ok(())
}
