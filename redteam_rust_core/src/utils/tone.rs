use serde_json::Value;

/// Sanitiza un campo para el formato TONE, eliminando el delimitador '|' y saltos de línea.
fn sanitize_tone_field(input: &str) -> String {
    input.replace('|', " ")
         .replace('\n', " ")
         .replace('\r', "")
         .trim()
         .to_string()
}

/// TONE (Tactical Object Notation for Egress)
/// Un formato denso diseñado para maximizar el ahorro de tokens en salidas de herramientas con muchos hallazgos.
pub fn tone_encode(findings: &[Value]) -> String {
    if findings.is_empty() {
        return "No se encontraron hallazgos relevantes.".to_string();
    }

    let mut output = String::new();
    
    // Header V1 estandarizado
    output.push_str("#type:tone-v1;keys:$0:id,$1:sev,$2:cat,$3:conf,$4:summary\n");
    output.push_str(&format!("[{}]{{$0,$1,$2,$3,$4}}:\n", findings.len()));

    for f in findings {
        let id = f.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let sev = f.get("sev").and_then(|v| v.as_str()).unwrap_or("?");
        let cat = f.get("cat").and_then(|v| v.as_str()).unwrap_or("?");
        
        // Campo de Confianza (Phase 4 Integration)
        let conf = f.get("conf").and_then(|v| v.as_str()).unwrap_or("POTENTIAL");
        
        let summary_raw = f.get("desc").and_then(|v| v.as_str())
            .or_else(|| f.get("title").and_then(|v| v.as_str()))
            .unwrap_or("");

        // Sanitización y truncamiento Hardened
        let s_id = sanitize_tone_field(id);
        let s_sev = sanitize_tone_field(sev);
        let s_cat = sanitize_tone_field(cat);
        let s_conf = sanitize_tone_field(conf);
        let s_summary = sanitize_tone_field(summary_raw)
            .chars()
            .take(120)
            .collect::<String>();

        // Usamos '|' como separador denso protegido
        output.push_str(&format!("  {}|{}|{}|{}|{}\n", s_id, s_sev, s_cat, s_conf, s_summary.trim()));
    }

    output.push_str("\n[TIP: Si necesitas el detalle técnico de un ID específico, pídemelo.]");
    
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_tone_encode_basic() {
        let findings = vec![
            json!({
                "id": "sqli-01",
                "sev": "high",
                "cat": "vulnerability",
                "desc": "SQL Injection found in /api/v1/login"
            }),
            json!({
                "id": "xss-02",
                "sev": "medium",
                "cat": "vulnerability",
                "desc": "Cross-Site Scripting in search parameter"
            }),
        ];

        let encoded = tone_encode(&findings);
        
        assert!(encoded.contains("#type:tone-v1"));
        assert!(encoded.contains("[2]{$0,$1,$2,$3}:"));
        assert!(encoded.contains("sqli-01|high|vulnerability|SQL Injection found in /api/v1/login"));
        assert!(encoded.contains("xss-02|medium|vulnerability|Cross-Site Scripting in search parameter"));
    }

    #[test]
    fn test_tone_encode_empty() {
        let encoded = tone_encode(&[]);
        assert_eq!(encoded, "No se encontraron hallazgos relevantes.");
    }
}
