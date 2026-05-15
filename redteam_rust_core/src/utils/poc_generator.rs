use crate::models::{Finding, Category};

pub struct PocGenerator;

impl PocGenerator {
    /// Generates a suggested PoC command or strategy based on the finding details.
    pub fn generate_suggested_poc(finding: &Finding) -> Option<String> {
        let title = finding.core.title.to_lowercase();
        let id = finding.core.id.to_lowercase();
        
        // Extract URL if available in evidence
        let url = finding.evidence.primary.as_ref()
            .and_then(|e| e.data.get("url").or_else(|| e.data.get("uri")))
            .and_then(|u| u.as_str());

        match finding.core.category {
            Category::Vulnerability => {
                if id.contains("sql-injection") || title.contains("sql injection") {
                    if let Some(u) = url {
                        return Some(format!("sqlmap -u \"{}\" --batch --banner --current-db", u));
                    }
                }
                
                if id.contains("ssti") || title.contains("server-side template injection") {
                    if let Some(u) = url {
                        return Some(format!("commix -u \"{}\" --batch", u));
                    }
                }

                if id.contains("xss") || title.contains("cross-site scripting") {
                    if let Some(u) = url {
                        return Some(format!("dalfox url \"{}\"", u));
                    }
                }
            },
            Category::ExposedAsset => {
                if id.contains("source-code") || title.contains("git") {
                    if let Some(u) = url {
                        return Some(format!("git clone \"{}\"", u));
                    }
                }
                if id.contains("s3-bucket") {
                    if let Some(u) = url {
                        return Some(format!("aws s3 ls \"s3://{}\" --no-sign-request", u.replace("http://", "").replace("https://", "")));
                    }
                }
            },
            Category::Misconfiguration => {
                if id.contains("directory-listing") {
                    if let Some(u) = url {
                        return Some(format!("curl -sI \"{}\" | grep \"Index of\"", u));
                    }
                }
            },
            _ => {}
        }

        None
    }
}
