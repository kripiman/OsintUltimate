use crate::plugins::triage::similarity_engine::{compute_tlsh, calculate_distance};

/// D4 FIX: Strings con entropía realista (contenido de security finding).
/// ASCII puro para evitar problemas de UTF-8 en mutate() (E2 preventivo).
fn make_finding_text(variant: u8) -> String {
    let ev_hash_str = format!("{:08x}", (variant as u32).wrapping_mul(0xDEADBEEFu32));
    format!(
        "SQL Injection detected at endpoint /api/v{v}/users?id={id} \
         with parameter 'id'. Payload: ' OR '1'='{v2}' UNION SELECT \
         table_name FROM information_schema.tables -- . \
         Response: HTTP 500, mysql_error() exposed schema version {sv}. \
         Stack trace depth {sd}. Host: target-{v}.example.com Port: {port}. \
         Evidence hash: {ev_hash}. Scanner: nuclei-v3 template sqli-generic.",
        v = variant,
        id = variant as u32 * 137 + 1000,
        v2 = variant,
        sv = variant as u32 * 7 + 5,
        sd = variant as u32 * 3 + 2,
        port = 8000u32 + variant as u32,
        ev_hash = ev_hash_str,
    )
}

/// E2 FIX: Mutación ASCII-safe — mantiene printable ASCII [32,126].
fn mutate(input: &str, percent: f64) -> String {
    let mut bytes = input.as_bytes().to_vec();
    let n = ((bytes.len() as f64) * percent).max(1.0) as usize;
    let step = (bytes.len() / n).max(1);
    for i in (0..bytes.len()).step_by(step) {
        // Mantener en rango printable ASCII [32, 126]
        bytes[i] = ((bytes[i] as u32 - 32 + 1) % 95 + 32) as u8;
    }
    // Safe: solo ASCII printable, nunca invalida UTF-8
    String::from_utf8(bytes).expect("ASCII mutation produced invalid UTF-8")
}

/// Test de propiedad métrica de TLSH: desigualdad triangular.
///
/// BK-Tree requiere: d(a,c) <= d(a,b) + d(b,c) para todos los puntos.
/// Metodología (C4 fix):
///   - Usar contenido realista de finding (alta entropía)
///   - Mutar 2%/4%/6% para generar near-duplicates
///   - Reportar tasa de violación (no solo pass/fail)
///   - Umbral: < 1% violaciones para considerar TLSH métrico-safe
#[test]
fn tlsh_triangle_inequality_near_duplicates() {
    let mut violations = 0u32;
    let mut total = 0u32;
    let mut skipped_none = 0u32;

    for variant in 0u8..=200 {
        let base = make_finding_text(variant);
        let a = mutate(&base, 0.02);
        let b = mutate(&base, 0.04);
        let c = mutate(&base, 0.06);

        match (compute_tlsh(&a), compute_tlsh(&b), compute_tlsh(&c)) {
            (Some(ha), Some(hb), Some(hc)) => {
                let d_ab = calculate_distance(&ha, &hb).unwrap_or(u32::MAX);
                let d_bc = calculate_distance(&hb, &hc).unwrap_or(u32::MAX);
                let d_ac = calculate_distance(&ha, &hc).unwrap_or(u32::MAX);

                // Solo contar si las distancias son válidas (no overflow)
                if d_ab < 900 && d_bc < 900 && d_ac < 900 {
                    total += 1;
                    if d_ac > d_ab + d_bc {
                        violations += 1;
                        eprintln!(
                            "Triangle violation: d(a,c)={} > d(a,b)={} + d(b,c)={}",
                            d_ac, d_ab, d_bc
                        );
                    }
                }
            }
            _ => skipped_none += 1,
        }
    }

    let rate = violations as f64 / total.max(1) as f64;
    println!(
        "TLSH Triangle Inequality: {}/{} violations ({:.2}%), {} skipped (TLSH returned None)",
        violations, total, rate * 100.0, skipped_none
    );

    // Necesitamos muestras suficientes para ser estadísticamente válidos (D4)
    assert!(
        total >= 50,
        "Insufficient TLSH samples ({}/50). Inputs may lack entropy. \
         Check make_finding_text() or TLSH minimum byte requirements.",
        total
    );

    // Umbral: < 1% violaciones = BK-Tree seguro con TLSH
    assert!(
        rate < 0.01,
        "TLSH viola la desigualdad triangular en {:.1}% de tripletas ({}/{}) — \
         BK-Tree NO es seguro. Considera usar LSH en su lugar.",
        rate * 100.0, violations, total
    );
}
