use serde_json::{Value, Map, json};
use std::collections::HashMap;
use anyhow::{Result, anyhow};

/// Sanitizes a string for safe transport over JSON/SSE streams.
/// Converts non-ASCII and control characters to \uXXXX escape sequences,
/// preventing stream corruption from CJK characters, emojis, or Wenyan output.
pub fn to_ascii_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() && !c.is_ascii_control() || matches!(c, '\n' | '\t' | '\r') {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{:04x}", unit));
            }
        }
    }
    out
}

/// Sanitiza un campo para el formato TONE, eliminando el delimitador '|' y saltos de línea.
fn sanitize_tone_field(input: &str) -> String {
    input.replace(['|', '\n'], " ")
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

// ─── TONL V1.1 ───────────────────────────────────────────────────────────────
// Ported from MCP-OSINTULT.
// Adds: Global Key Dictionary ($N aliases), bidirectional encode/decode,
// and tabular array format — all with pre-compiled-safe logic.

/// Encodes a JSON Value into TONL V1.1 dense format with global key dictionary.
pub fn tonl_encode(data: Value) -> String {
    let mut key_freq: HashMap<String, usize> = HashMap::new();
    collect_key_freq(&data, &mut key_freq);

    let mut sorted: Vec<_> = key_freq.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let dict: Vec<String> = sorted.into_iter()
        .filter(|(k, freq)| {
            *freq > 1 && k.len() > 3 && k.chars().all(|c| c.is_alphanumeric() || c == '_')
        })
        .take(64)
        .map(|(k, _)| k)
        .collect();

    let dict_map: HashMap<String, String> = dict.iter().enumerate()
        .map(|(i, k)| (k.clone(), format!("${}", i)))
        .collect();

    let mut output = String::from("#version 1.1\n");
    if !dict.is_empty() {
        output.push_str("#keys ");
        for (i, key) in dict.iter().enumerate() {
            if i > 0 { output.push(','); }
            output.push_str(&format!("${}:{}", i, key));
        }
        output.push('\n');
    }
    output.push_str(&tonl_encode_value(data, 0, &dict_map));
    output.trim().to_string()
}

/// Decodes TONL V1.1 back into a JSON Value.
pub fn tonl_decode(input: &str) -> Result<Value> {
    let mut lines = input.lines().peekable();
    let mut dict: HashMap<String, String> = HashMap::new();

    while let Some(&line) = lines.peek() {
        let t = line.trim();
        if t.starts_with("#version") {
            lines.next();
        } else if t.starts_with("#keys") {
            if dict.len() > 128 { return Err(anyhow!("TONL: dictionary overflow")); }
            let keys_part = t.strip_prefix("#keys").unwrap().trim();
            for part in keys_part.split(',') {
                let kv: Vec<&str> = part.splitn(2, ':').collect();
                if kv.len() == 2 && kv[0].trim().starts_with('$') {
                    dict.insert(kv[0].trim().to_string(), kv[1].trim().to_string());
                }
            }
            lines.next();
        } else {
            break;
        }
    }
    tonl_decode_value(&mut lines, 0, &dict)
}

fn collect_key_freq(data: &Value, freq: &mut HashMap<String, usize>) {
    match data {
        Value::Object(obj) => {
            for (k, v) in obj {
                *freq.entry(k.clone()).or_insert(0) += 1;
                collect_key_freq(v, freq);
            }
        }
        Value::Array(arr) => arr.iter().for_each(|v| collect_key_freq(v, freq)),
        _ => {}
    }
}

fn tonl_encode_value(data: Value, depth: usize, dict: &HashMap<String, String>) -> String {
    let indent = "  ".repeat(depth);
    match data {
        Value::Array(arr) => {
            if arr.is_empty() { return "[]".to_string(); }
            if let Some(first) = arr[0].as_object() {
                let mut keys: Vec<&str> = first.keys().map(|k| k.as_str()).collect();
                keys.sort();
                let header_keys: Vec<String> = keys.iter()
                    .map(|&k| dict.get(k).cloned().unwrap_or_else(|| k.to_string()))
                    .collect();
                let mut out = format!("[{}]{{{}}}:\n", arr.len(), header_keys.join(","));
                for item in &arr {
                    if let Some(obj) = item.as_object() {
                        let row: Vec<String> = keys.iter().map(|&k| {
                            match obj.get(k).unwrap_or(&Value::Null) {
                                Value::String(s) => {
                                    if s.contains(',') { format!("\"{}\"", s) } else { s.clone() }
                                }
                                v => v.to_string(),
                            }
                        }).collect();
                        out.push_str(&format!("{}  {}\n", indent, row.join(",")));
                    }
                }
                return out.trim_end().to_string();
            }
            let items: Vec<String> = arr.iter().map(|v| v.to_string()).collect();
            format!("[{}]: {}", items.len(), items.join(","))
        }
        Value::Object(obj) => {
            let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
            keys.sort();
            keys.iter().map(|&k| {
                let v = obj.get(k).unwrap();
                let k_enc = dict.get(k).cloned().unwrap_or_else(|| k.to_string());
                let v_enc = tonl_encode_value(v.clone(), depth + 1, dict);
                if v_enc.contains('\n') {
                    format!("{}:\n{}  {}", k_enc, indent, v_enc)
                } else {
                    format!("{}: {}", k_enc, v_enc)
                }
            }).collect::<Vec<_>>().join(&format!("\n{}", indent))
        }
        Value::String(s) => s,
        _ => data.to_string(),
    }
}

fn tonl_decode_value(
    lines: &mut std::iter::Peekable<std::str::Lines>,
    depth: usize,
    dict: &HashMap<String, String>,
) -> Result<Value> {
    let line_raw = match lines.peek() {
        Some(l) => l.to_string(),
        None => return Err(anyhow!("TONL: unexpected EOF")),
    };
    let current_indent = line_raw.len() - line_raw.trim_start().len();
    let line = line_raw.trim();
    if line.is_empty() {
        lines.next();
        return tonl_decode_value(lines, depth, dict);
    }
    if current_indent < depth && depth > 0 { return Ok(Value::Null); }
    lines.next();

    // Tabular array: [N]{field,...}:
    if line.starts_with('[') && line.contains(']') && line.contains('{') {
        let count_end = line.find(']').ok_or_else(|| anyhow!("TONL: malformed array header"))?;
        let count: usize = line[1..count_end].parse().map_err(|e| anyhow!("TONL: {}", e))?;
        let fs = line.find('{').unwrap() + 1;
        let fe = line.find('}').unwrap();
        let fields: Vec<String> = line[fs..fe].split(',').map(|f| {
            let name = f.split(':').next().unwrap_or(f);
            if name.starts_with('$') {
                dict.get(name).cloned().unwrap_or_else(|| name.to_string())
            } else {
                name.to_string()
            }
        }).collect();
        let mut arr = Vec::new();
        for _ in 0..count {
            let row = lines.next()
                .ok_or_else(|| anyhow!("TONL: expected {} rows", count))?
                .trim()
                .to_string();
            let values = tonl_parse_csv_row(&row);
            let mut obj = Map::new();
            for (i, name) in fields.iter().enumerate() {
                let val = values.get(i).cloned().unwrap_or_else(|| "null".to_string());
                obj.insert(name.clone(), json!(val.trim_matches('"')));
            }
            arr.push(Value::Object(obj));
        }
        return Ok(Value::Array(arr));
    }

    // Key-value object
    if line.contains(':') {
        let mut obj = Map::new();
        let mut current = Some(line.to_string());
        while let Some(l) = current {
            let parts: Vec<&str> = l.splitn(2, ':').collect();
            if parts.len() < 2 { break; }
            let mut key = parts[0].trim().to_string();
            if key.starts_with('$') {
                key = dict.get(&key).cloned().unwrap_or(key);
            }
            let val_str = parts[1].trim();
            let is_nested = val_str.is_empty() || val_str == "obj" || val_str == "arr";
            if is_nested {
                if let Some(next) = lines.peek() {
                    let ni = next.len() - next.trim_start().len();
                    if ni > current_indent {
                        obj.insert(key, tonl_decode_value(lines, ni, dict)?);
                    } else {
                        obj.insert(key, Value::Null);
                    }
                }
            } else {
                let v = if val_str.eq_ignore_ascii_case("true") { json!(true) }
                        else if val_str.eq_ignore_ascii_case("false") { json!(false) }
                        else if let Ok(n) = val_str.parse::<f64>() { json!(n) }
                        else { json!(val_str.trim_matches('"')) };
                obj.insert(key, v);
            }
            current = match lines.peek() {
                Some(next) => {
                    let ni = next.len() - next.trim_start().len();
                    if ni == current_indent && next.contains(':') && !next.trim().starts_with('[') {
                        Some(lines.next().unwrap().to_string())
                    } else {
                        None
                    }
                }
                None => None,
            };
        }
        return Ok(Value::Object(obj));
    }

    Ok(json!(line.trim_matches('"')))
}

fn tonl_parse_csv_row(line: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for c in line.chars() {
        if escaped { current.push(c); escaped = false; continue; }
        if c == '\\' { escaped = true; continue; }
        if c == '"' { in_quotes = !in_quotes; }
        else if c == ',' && !in_quotes {
            result.push(current.trim().to_string());
            current = String::new();
        } else {
            current.push(c);
        }
    }
    result.push(current.trim().to_string());
    result
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
        assert!(encoded.contains("[2]{$0,$1,$2,$3,$4}:"));
        assert!(encoded.contains("sqli-01|high|vulnerability|POTENTIAL|SQL Injection found in /api/v1/login"));
        assert!(encoded.contains("xss-02|medium|vulnerability|POTENTIAL|Cross-Site Scripting in search parameter"));
    }

    #[test]
    fn test_tone_encode_empty() {
        let encoded = tone_encode(&[]);
        assert_eq!(encoded, "No se encontraron hallazgos relevantes.");
    }

    #[test]
    fn test_tonl_roundtrip() {
        let data = json!([
            {"id": "sqli-01", "severity": "high",   "category": "injection"},
            {"id": "xss-02",  "severity": "medium", "category": "xss"},
        ]);
        let encoded = tonl_encode(data);
        assert!(encoded.contains("#version 1.1"));
        let decoded = tonl_decode(&encoded).unwrap();
        assert_eq!(decoded[0]["id"], "sqli-01");
        assert_eq!(decoded[1]["severity"], "medium");
    }

    #[test]
    fn test_tonl_smaller_than_json() {
        let data = json!([
            {"severity": "critical", "category": "sqli", "description": "SQL injection"},
            {"severity": "high",     "category": "xss",  "description": "XSS stored"},
            {"severity": "medium",   "category": "lfi",  "description": "LFI traversal"},
        ]);
        let tonl = tonl_encode(data.clone());
        let plain = serde_json::to_string(&data).unwrap();
        assert!(tonl.len() < plain.len(),
            "TONL ({} chars) must be smaller than JSON ({} chars)", tonl.len(), plain.len());
    }

    #[test]
    fn test_tonl_dict_compresses_repeated_keys() {
        let data = json!([
            {"severity": "high",   "category": "sqli"},
            {"severity": "medium", "category": "xss"},
            {"severity": "low",    "category": "info"},
        ]);
        let encoded = tonl_encode(data);
        // Dictionary should alias repeated keys (severity, category appear 3x each)
        assert!(encoded.contains('$'));
    }
}
