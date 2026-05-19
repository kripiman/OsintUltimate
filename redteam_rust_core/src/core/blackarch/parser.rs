use super::schema::{BlackArchTool, ToolSchema, FlagSchema, ResourceCost};
use regex::Regex;

pub(crate) fn parse_help_output(
    tool_name: &str,
    help_text: &str,
    tool_info: Option<&BlackArchTool>,
) -> ToolSchema {
    let lines: Vec<&str> = help_text.lines().collect();
    ToolSchema {
        tool_name: tool_name.to_string(),
        version: extract_version(&lines),
        synopsis: extract_synopsis(&lines, tool_info),
        flags: parse_flags(&lines),
        output_formats: detect_output_formats(help_text),
        resource_cost: classify_resource_cost(tool_info),
    }
}

fn extract_synopsis(lines: &[&str], tool_info: Option<&BlackArchTool>) -> String {
    lines.iter()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| tool_info.map(|t| t.description.clone()).unwrap_or_default())
}

fn extract_version(lines: &[&str]) -> Option<String> {
    let version_re = Regex::new(r"(?i)(?:v(?:ersion)?\s*)?(\d+\.\d+(?:\.\d+)?)").ok()?;
    lines.iter()
        .take(5)
        .find_map(|l| version_re.find(l).map(|m| m.as_str().to_string()))
}

fn detect_output_formats(help_text: &str) -> Vec<String> {
    let help_lower = help_text.to_lowercase();
    let mut output_formats = Vec::new();
    for fmt in &["json", "xml", "csv", "html", "yaml", "greppable"] {
        if help_lower.contains(fmt) {
            output_formats.push(fmt.to_string());
        }
    }
    output_formats
}

fn classify_resource_cost(tool_info: Option<&BlackArchTool>) -> ResourceCost {
    tool_info
        .map(|t| match t.category.as_str() {
            "scanner" | "cracker" | "exploitation" => ResourceCost::Heavy,
            "webapp" | "fuzzer" => ResourceCost::Medium,
            _ => ResourceCost::Light,
        })
        .unwrap_or(ResourceCost::Medium)
}

fn parse_flags(lines: &[&str]) -> Vec<FlagSchema> {
    let mut flags = Vec::new();
    let re_comb = Regex::new(r"^\s+(-\w),?\s*(--[\w-]+)\s+(.+)").ok();
    let re_l = Regex::new(r"^\s+(--[\w-]+)\s+(.+)").ok();
    let re_s = Regex::new(r"^\s+(-\w)\s{2,}(.+)").ok();
    let re_sv = Regex::new(r"^\s+(-\w)\s+(<[^>]+>)\s{2,}(.+)").ok();

    for line in lines {
        if let Some(flag) = parse_line(line, &re_comb, &re_l, &re_s, &re_sv) {
            flags.push(flag);
        }
    }
    flags
}

fn parse_line(
    line: &str,
    re_c: &Option<Regex>,
    re_l: &Option<Regex>,
    re_s: &Option<Regex>,
    re_sv: &Option<Regex>,
) -> Option<FlagSchema> {
    if let Some(f) = try_comb(line, re_c) { return Some(f); }
    if let Some(f) = try_long(line, re_l) { return Some(f); }
    if let Some(f) = try_short(line, re_s) { return Some(f); }
    try_sv(line, re_sv)
}

fn try_comb(line: &str, re: &Option<Regex>) -> Option<FlagSchema> {
    let caps = re.as_ref()?.captures(line)?;
    let d = caps.get(3)?.as_str().trim().to_string();
    Some(FlagSchema {
        short: caps.get(1).map(|m| m.as_str().to_string()),
        long: caps.get(2).map(|m| m.as_str().to_string()),
        takes_value: flag_takes_value(&d, line),
        default_value: extract_default(&d),
        description: d,
    })
}

fn try_long(line: &str, re: &Option<Regex>) -> Option<FlagSchema> {
    let caps = re.as_ref()?.captures(line)?;
    let d = caps.get(2)?.as_str().trim().to_string();
    Some(FlagSchema {
        short: None,
        long: caps.get(1).map(|m| m.as_str().to_string()),
        takes_value: flag_takes_value(&d, line),
        default_value: extract_default(&d),
        description: d,
    })
}

fn try_short(line: &str, re: &Option<Regex>) -> Option<FlagSchema> {
    let caps = re.as_ref()?.captures(line)?;
    let d = caps.get(2)?.as_str().trim().to_string();
    Some(FlagSchema {
        short: caps.get(1).map(|m| m.as_str().to_string()),
        long: None,
        takes_value: flag_takes_value(&d, line),
        default_value: extract_default(&d),
        description: d,
    })
}

fn try_sv(line: &str, re: &Option<Regex>) -> Option<FlagSchema> {
    let caps = re.as_ref()?.captures(line)?;
    let d = caps.get(3)?.as_str().trim().to_string();
    Some(FlagSchema {
        short: caps.get(1).map(|m| m.as_str().to_string()),
        long: None,
        takes_value: true,
        default_value: extract_default(&d),
        description: d,
    })
}

fn flag_takes_value(desc: &str, line: &str) -> bool {
    let indicators = ["<", ">", "FILE", "PATH", "NUM", "PORT", "URL", "HOST", "="];
    indicators.iter().any(|i| desc.to_uppercase().contains(i) || line.contains(i))
}

fn extract_default(desc: &str) -> Option<String> {
    let re = Regex::new(r"(?i)(?:\(|\[)default[:\s]+([^\)\]]+)(?:\)|\])").ok()?;
    re.captures(desc).and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::Capability;

    #[test]
    fn test_parse_help_output_extracts_flags() {
        let mock_help = "Nmap 7.93\nUsage: nmap\n  -p <port>  (default: 1-1024)\n  -oN <file> xml greppable\n";
        let tool_info = BlackArchTool {
            name: "nmap".to_string(),
            category: "scanner".to_string(),
            description: "Network exploration tool".to_string(),
            capabilities: vec![Capability::PortScanning],
        };
        let schema = parse_help_output("nmap", mock_help, Some(&tool_info));
        assert_eq!(schema.tool_name, "nmap");
        assert!(schema.version.is_some());
        assert!(!schema.flags.is_empty());
        assert!(schema.output_formats.contains(&"xml".to_string()));
        assert!(schema.output_formats.contains(&"greppable".to_string()));
        assert_eq!(schema.resource_cost, ResourceCost::Heavy);
        let port_flag = schema.flags.iter().find(|f| f.short.as_deref() == Some("-p"));
        assert!(port_flag.is_some());
        assert!(port_flag.unwrap().takes_value);
    }

    #[test]
    fn test_extract_default_value() {
        assert_eq!(extract_default("Specify ports (default: 1-1024)"), Some("1-1024".to_string()));
        assert_eq!(extract_default("Set timeout [Default: 30]"), Some("30".to_string()));
        assert_eq!(extract_default("Enable verbose mode"), None);
    }

    #[test]
    fn test_flag_takes_value_heuristic() {
        assert!(flag_takes_value("Specify <PORT> to scan", "  -p <PORT>"));
        assert!(flag_takes_value("Output FILE path", "  -o FILE"));
        assert!(!flag_takes_value("Enable verbose mode", "  -v  Enable verbose mode"));
    }

    #[test]
    fn test_resource_cost_classification() {
        let scanner = BlackArchTool { name: "nmap".to_string(), category: "scanner".to_string(), description: "".to_string(), capabilities: vec![] };
        assert_eq!(parse_help_output("nmap", "help", Some(&scanner)).resource_cost, ResourceCost::Heavy);
        let webapp = BlackArchTool { name: "sqlmap".to_string(), category: "webapp".to_string(), description: "".to_string(), capabilities: vec![] };
        assert_eq!(parse_help_output("sqlmap", "help", Some(&webapp)).resource_cost, ResourceCost::Medium);
    }
}
