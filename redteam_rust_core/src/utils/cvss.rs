use crate::models::Severity;

#[derive(Debug, Clone, PartialEq)]
pub struct Cvss40 {
    pub average_score: f32,
}

impl Cvss40 {
    /// Parsea un vector de métricas o un string de vector CVSS 4.0 y calcula el score.
    /// Para este stub, simplificamos el cálculo basado en la severidad y impacto.
    pub fn calculate(severity: &Severity, impact: f32) -> f32 {
        let base = match severity {
            Severity::Critical => 9.0,
            Severity::High => 7.0,
            Severity::Medium => 4.0,
            Severity::Low => 1.0,
            Severity::Info => 0.0,
        };

        (base + (impact * 1.0)).clamp(0.0, 10.0)
    }

    /// Genera un vector CVSS 4.0 resumido
    pub fn to_vector_string(score: f32) -> String {
        format!("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/Score:{}", score)
    }
}
