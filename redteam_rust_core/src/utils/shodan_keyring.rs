use crate::utils::config::Config;
use std::sync::OnceLock;
use tracing::warn;

pub struct ShodanKeyring {
    student_key: Option<String>,
    paid_key: Option<String>,
}

static KEYRING: OnceLock<ShodanKeyring> = OnceLock::new();

impl ShodanKeyring {
    pub fn init(config: &Config) {
        let student_key = std::env::var("SHODAN_STUDENT_API_KEY").ok();
        let paid_key = config.shodan_api_key.clone();

        let keyring = Self { student_key, paid_key };
        let _ = KEYRING.set(keyring);
    }

    pub fn get() -> &'static Self {
        KEYRING.get().expect("ShodanKeyring must be initialized")
    }

    pub fn get_key_with_slot_for_dns(&self) -> Option<(&str, &'static str)> {
        if let Some(ref sk) = self.student_key {
            Some((sk.as_str(), "shodan_student"))
        } else if let Some(ref pk) = self.paid_key {
            warn!("⚠️ SENTINEL: SHODAN_STUDENT_API_KEY missing. Falling back to paid key for DNS enum (NOT RECOMMENDED).");
            Some((pk.as_str(), "shodan_paid"))
        } else {
            None
        }
    }

    pub fn get_key_for_search(&self) -> Option<&str> {
        self.paid_key.as_deref()
    }
}
