use std::env;

pub struct Config {
    pub do_token: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            do_token: env::var("DIGITALOCEAN_TOKEN").ok(),
        }
    }

    pub fn require_do_token(&self) -> anyhow::Result<String> {
        self.do_token.clone()
            .ok_or_else(|| anyhow::anyhow!("DIGITALOCEAN_TOKEN environment variable not set"))
    }
}
