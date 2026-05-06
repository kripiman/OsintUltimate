use crate::models::Severity;
use cvss::v3::base::Base;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub struct Cvss31 {
    pub score: f32,
    pub vector: String,
}

impl Cvss31 {
    /// Calculates score from a CVSS 3.1 vector string.
    pub fn from_vector(vector: &str) -> Option<Self> {
        if let Ok(base) = Base::from_str(vector) {
            let score = base.score().value() as f32;
            Some(Self {
                score,
                vector: vector.to_string(),
            })
        } else {
            None
        }
    }

    /// Generates a realistic CVSS 3.1 vector and score from internal Severity.
    pub fn from_severity(severity: &Severity) -> Self {
        let vector = match severity {
            Severity::Critical => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8
            Severity::High => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",     // 9.1
            Severity::Medium => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",   // 5.3
            Severity::Low => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",      // 4.3
            Severity::Info => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",     // 0.0
        };

        let base = Base::from_str(vector).expect("Static vector should be valid");
        Self {
            score: base.score().value() as f32,
            vector: vector.to_string(),
        }
    }
}

// V14.2 Legacy shim for compatibility
pub struct Cvss40;
impl Cvss40 {
    pub fn calculate(severity: &Severity, _impact: f32) -> f32 {
        let cvss = Cvss31::from_severity(severity);
        cvss.score // Ignore impact as adding it to CVSS 3.1 score is non-standard
    }

    pub fn to_vector_string(score: f32) -> String {
        format!("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/Score:{}", score)
    }
}
