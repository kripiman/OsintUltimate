use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkerProfile {
    #[default]
    Scan,
    Enrich,
    CveCorrelation,
}

impl std::fmt::Display for WorkerProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerProfile::Scan => write!(f, "scan"),
            WorkerProfile::Enrich => write!(f, "enrich"),
            WorkerProfile::CveCorrelation => write!(f, "cve_correlation"),
        }
    }
}

impl FromStr for WorkerProfile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "scan" => Ok(WorkerProfile::Scan),
            "enrich" => Ok(WorkerProfile::Enrich),
            "cve_correlation" | "cve-correlation" => Ok(WorkerProfile::CveCorrelation),
            _ => Err(format!("Unknown worker profile: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_from_str() {
        assert_eq!(WorkerProfile::from_str("scan").unwrap(), WorkerProfile::Scan);
        assert_eq!(WorkerProfile::from_str("enrich").unwrap(), WorkerProfile::Enrich);
        assert_eq!(WorkerProfile::from_str("cve_correlation").unwrap(), WorkerProfile::CveCorrelation);
        assert_eq!(WorkerProfile::from_str("cve-correlation").unwrap(), WorkerProfile::CveCorrelation);
        assert!(WorkerProfile::from_str("unknown").is_err());
    }

    #[test]
    fn test_profile_display() {
        assert_eq!(WorkerProfile::Scan.to_string(), "scan");
        assert_eq!(WorkerProfile::Enrich.to_string(), "enrich");
        assert_eq!(WorkerProfile::CveCorrelation.to_string(), "cve_correlation");
    }

    #[test]
    fn test_profile_default() {
        assert_eq!(WorkerProfile::default(), WorkerProfile::Scan);
    }
}
