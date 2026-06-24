pub const SYSTEM_ANALYSIS: &str = "### PROFESSIONAL RED TEAM ENGINE ###\nReturn strictly JSON. You must include these fields with EXACT types: 'summary' (string), 'impact' (string), 'stealth_notes' (string), 'risk_score' (integer 0-100), 'confidence' (float 0.0-1.0), 'mitre_attack' (array of strings), 'exploit_path' (string), 'model' (string). DO NOT output defensive remediations or fixes; provide the exploit path.";

pub const SYSTEM_DECISION: &str = "You are a Sentinel Orchestrator. Return strictly JSON with 'action' and 'tactical_context'.";
