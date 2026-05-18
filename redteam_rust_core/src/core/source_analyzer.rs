use crate::models::{Finding, Category, Severity};
use anyhow::{Result, Context};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
use regex::Regex;
use std::fs;
use tracing::info;

pub struct SourceAnalyzer {
    pub root_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SourceFinding {
    pub file: String,
    pub line: usize,
    pub snippet: String,
    pub description: String,
    pub severity: Severity,
    pub is_endpoint: bool,
}

impl SourceAnalyzer {
    pub fn new(root: PathBuf) -> Self {
        Self { root_dir: root }
    }

    /// Clona un repositorio remoto en un directorio temporal y retorna el analyzer.
    pub async fn from_git(url: &str) -> Result<Self> {
        let id = Uuid::new_v4().to_string();
        let tmp_dir = std::env::temp_dir().join(format!("osint_src_{}", id));
        fs::create_dir_all(&tmp_dir)?;

        info!("📂 SAST: Clonando repositorio {} en {:?}", url, tmp_dir);
        
        let output = Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg(url)
            .arg(".")
            .current_dir(&tmp_dir)
            .output()
            .context("Fallo al ejecutar git clone. ¿Está git instalado?")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Error al clonar repositorio: {}", err));
        }

        Ok(Self::new(tmp_dir))
    }

    /// Ejecuta el análisis completo en el directorio raíz.
    pub async fn analyze(&self) -> Result<Vec<SourceFinding>> {
        let mut results = Vec::new();
        self.walk_dir(&self.root_dir, &mut results)?;
        Ok(results)
    }

    fn walk_dir(&self, dir: &Path, results: &mut Vec<SourceFinding>) -> Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    // Ignorar node_modules, .git, etc.
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name == "node_modules" || name == ".git" || name == "venv" || name == "target" {
                        continue;
                    }
                    self.walk_dir(&path, results)?;
                } else {
                    self.analyze_file(&path, results)?;
                }
            }
        }
        Ok(())
    }

    fn analyze_file(&self, path: &Path, results: &mut Vec<SourceFinding>) -> Result<()> {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        match ext {
            "js" | "ts" | "jsx" | "tsx" => self.analyze_javascript(path, results),
            "py" => self.analyze_python(path, results),
            _ => Ok(()),
        }
    }

    fn analyze_javascript(&self, path: &Path, results: &mut Vec<SourceFinding>) -> Result<()> {
        let content = fs::read_to_string(path)?;
        
        // 1. ENDPOINTS (Express/Fastify patterns)
        let re_routes = Regex::new(r#"\.(get|post|put|delete|patch|all)\s*\(\s*['"]([^'"]+)['"]"#).unwrap();
        for (i, line) in content.lines().enumerate() {
            if let Some(cap) = re_routes.captures(line) {
                results.push(SourceFinding {
                    file: path.to_string_lossy().to_string(),
                    line: i + 1,
                    snippet: line.trim().to_string(),
                    description: format!("Endpoint Detectado: {} {}", cap[1].to_uppercase(), &cap[2]),
                    severity: Severity::Info,
                    is_endpoint: true,
                });
            }
        }

        // 2. SINKS (Dangerous functions)
        let sinks = [
            (r#"eval\s*\("#, "Uso de eval() detectado (Riesgo de Inyección)"),
            (r#"child_process\.exec\s*\("#, "Ejecución de comandos del sistema"),
            (r#"dangerouslySetInnerHTML"#, "Renderizado de HTML crudo (Riesgo XSS)"),
            (r#"req\.params|req\.query|req\.body"#, "Uso de entrada de usuario sin sanitizar visible")
        ];

        for (pattern, desc) in sinks {
            let re = Regex::new(pattern).unwrap();
            for (i, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    results.push(SourceFinding {
                        file: path.to_string_lossy().to_string(),
                        line: i + 1,
                        snippet: line.trim().to_string(),
                        description: desc.to_string(),
                        severity: Severity::Medium,
                        is_endpoint: false,
                    });
                }
            }
        }

        Ok(())
    }

    fn analyze_python(&self, path: &Path, results: &mut Vec<SourceFinding>) -> Result<()> {
        let content = fs::read_to_string(path)?;

        // 1. ENDPOINTS (Flask/Django/FastAPI)
        let re_routes = Regex::new(r#"@(app|router|blueprint)\.(get|post|route)\s*\(['"]([^'"]+)['"]"#).unwrap();
        for (i, line) in content.lines().enumerate() {
            if let Some(cap) = re_routes.captures(line) {
                results.push(SourceFinding {
                    file: path.to_string_lossy().to_string(),
                    line: i + 1,
                    snippet: line.trim().to_string(),
                    description: format!("Endpoint Python: {} {}", cap[2].to_uppercase(), &cap[3]),
                    severity: Severity::Info,
                    is_endpoint: true,
                });
            }
        }

        // 2. SINKS
        let sinks = [
            (r#"os\.system\s*\(|subprocess\.call\s*\("#, "Ejecución de comandos del sistema"),
            (r#"pickle\.load\s*\("#, "Uso de Pickle (Riesgo de Deserialización)"),
            (r#"execute\s*\(\s*f['"]"#, "Posible Inyección SQL via F-Strings"),
            (r#"yaml\.load\s*\("#, "Carga de YAML insegura")
        ];

        for (pattern, desc) in sinks {
            let re = Regex::new(pattern).unwrap();
            for (i, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    results.push(SourceFinding {
                        file: path.to_string_lossy().to_string(),
                        line: i + 1,
                        snippet: line.trim().to_string(),
                        description: desc.to_string(),
                        severity: Severity::High,
                        is_endpoint: false,
                    });
                }
            }
        }

        Ok(())
    }

    /// Convierte hallazgos de código en Hallazgos del motor para correlación.
    pub fn to_core_findings(&self, findings: &[SourceFinding]) -> Vec<Finding> {
        findings.iter().map(|f| {
            let mut h = Finding::new(
                &format!("sast-{}", Uuid::new_v4()),
                if f.is_endpoint { Category::Recon } else { Category::Vulnerability },
                f.severity.clone(),
                &f.description,
                serde_json::json!({
                    "file": f.file,
                    "line": f.line,
                    "snippet": f.snippet,
                    "type": "source_aware",
                    "endpoint": if f.is_endpoint { Some(f.description.replace("Endpoint Detectado: ", "").replace("Endpoint Python: ", "")) } else { None }
                })
            );
            h.core.title = format!("SAST: {}", f.description);
            h
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_js_analysis() -> Result<()> {
        let dir = tempdir()?;
        let file_path = dir.path().join("test.js");
        fs::write(&file_path, "app.get('/api/v1/test', (req, res) => { eval(req.query.id); });")?;

        let analyzer = SourceAnalyzer::new(dir.path().to_path_buf());
        let results = analyzer.analyze().await?;

        assert!(results.iter().any(|r| r.is_endpoint && r.description.contains("/api/v1/test")));
        assert!(results.iter().any(|r| !r.is_endpoint && r.description.contains("eval()")));
        
        Ok(())
    }

    #[tokio::test]
    async fn test_python_analysis() -> Result<()> {
        let dir = tempdir()?;
        let file_path = dir.path().join("app.py");
        fs::write(&file_path, "@app.route('/login')\ndef login(): os.system(cmd)")?;

        let analyzer = SourceAnalyzer::new(dir.path().to_path_buf());
        let results = analyzer.analyze().await?;

        assert!(results.iter().any(|r| r.is_endpoint && r.description.contains("/login")));
        assert!(results.iter().any(|r| !r.is_endpoint && r.description.contains("comandos")));
        
        Ok(())
    }
}
