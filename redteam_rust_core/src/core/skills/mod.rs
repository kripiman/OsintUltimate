use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use crate::models::Finding;
use crate::core::ai::types::{Posture, RouteLevel, CavemanLevel};
use tracing::{info, warn};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SkillMitre {
    pub tactic: String,
    pub tactic_name: String,
    pub technique: Option<String>,
    pub sub_technique: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SkillPreconditions {
    pub min_cvss: Option<f32>,
    pub requires_verified: Option<bool>,
    pub requires_tag: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Skill {
    pub id: String,
    pub name: String,
    pub version: String,
    pub mitre: SkillMitre,
    pub category_match: Vec<String>,
    pub posture_match: Vec<String>,
    pub tags: Vec<String>,
    pub route_level_min: String,
    pub token_cost: u32,
    pub preconditions: Option<SkillPreconditions>,
    pub prompt_fragment: String,
}

pub struct SkillManager {
    skills: Vec<Skill>,
    by_category: HashMap<String, Vec<usize>>,
    by_tag: HashMap<String, Vec<usize>>,
    // V15: Token redundancy prevention (per-session/mission usage tracker)
    used_skills: Arc<tokio::sync::Mutex<HashSet<String>>>,
}

impl SkillManager {
    pub fn load_from_dir<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let mut skills = Vec::new();
        let dir_path = dir.as_ref();
        
        if !dir_path.exists() {
            warn!("⚠️ [Skills] Directory {} does not exist. Starting with empty skill set.", dir_path.display());
            return Ok(Self { 
                skills: Vec::new(), 
                by_category: HashMap::new(), 
                by_tag: HashMap::new(),
                used_skills: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            });
        }

        for entry in std::fs::read_dir(dir_path)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let raw = std::fs::read_to_string(&path)?;
                let skill: Skill = serde_json::from_str(&raw)
                    .with_context(|| format!("Failed to parse skill: {}", path.display()))?;
                skills.push(skill);
            }
        }

        let mut by_category: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_tag: HashMap<String, Vec<usize>> = HashMap::new();

        for (i, s) in skills.iter().enumerate() {
            for cat in &s.category_match {
                by_category.entry(cat.clone()).or_default().push(i);
            }
            for tag in &s.tags {
                by_tag.entry(tag.to_lowercase()).or_default().push(i);
            }
        }

        info!("🧠 [Skills] Loaded {} professional tactical skills from {}", skills.len(), dir_path.display());

        Ok(Self { 
            skills, 
            by_category, 
            by_tag,
            used_skills: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        })
    }

    /// Matches skills for a finding, considering posture and route level.
    pub async fn match_for_context(
        &self,
        finding: &Finding,
        posture: Posture,
        _route_level: RouteLevel,
        budget: u32,
    ) -> Vec<&Skill> {
        let category_str = format!("{:?}", finding.core.category);
        let posture_str = format!("{:?}", posture);
        
        let mut candidates: Vec<(usize, u32)> = Vec::new();
        let used_lock = self.used_skills.lock().await;

        // 1. Match by Category
        if let Some(indices) = self.by_category.get(&category_str) {
            for &i in indices {
                let s = &self.skills[i];
                
                // V15: Token redundancy prevention: Skip if already used in this mission
                if used_lock.contains(&s.id) { continue; }
                
                // Match posture
                if !s.posture_match.is_empty() && !s.posture_match.contains(&posture_str) { continue; }
                
                // Check preconditions
                if let Some(pre) = &s.preconditions {
                    if let Some(min_cvss) = pre.min_cvss {
                        let actual_cvss = finding.enrichment.cvss_score.unwrap_or(0.0);
                        if actual_cvss < min_cvss { continue; }
                    }
                    if let Some(req_ver) = pre.requires_verified {
                        let verified = finding.evidence.primary.as_ref().map(|e| e.verified).unwrap_or(false);
                        if req_ver && !verified { continue; }
                    }
                    if let Some(req_tag) = &pre.requires_tag {
                        if !finding.enrichment.mitre_tags.contains(req_tag) { continue; }
                    }
                }

                candidates.push((i, 10)); // Base score
            }
        }

        // 2. Score by Tags (Boost)
        for tag in &finding.enrichment.mitre_tags {
            if let Some(indices) = self.by_tag.get(&tag.to_lowercase()) {
                for &i in indices {
                    // Update score if already a candidate, or add as candidate
                    if let Some(entry) = candidates.iter_mut().find(|c| c.0 == i) {
                        entry.1 += 20; // Big boost for tag match
                    } else {
                        // Check preconditions even for tag match
                        let s = &self.skills[i];
                        if used_lock.contains(&s.id) { continue; }
                        if !s.posture_match.is_empty() && !s.posture_match.contains(&posture_str) { continue; }
                        
                        let mut pre_passed = true;
                        if let Some(pre) = &s.preconditions {
                            if let Some(min_cvss) = pre.min_cvss {
                                if finding.enrichment.cvss_score.unwrap_or(0.0) < min_cvss { pre_passed = false; }
                            }
                        }
                        
                        if pre_passed {
                            candidates.push((i, 15)); // Tag match starting score
                        }
                    }
                }
            }
        }

        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        // 3. Select within token budget
        let mut total_tokens = 0;
        let mut selected = Vec::new();
        for (i, _) in candidates {
            let s = &self.skills[i];
            if total_tokens + s.token_cost <= budget {
                total_tokens += s.token_cost;
                selected.push(s);
            }
        }

        selected
    }

    /// Builds a compressed injection string and marks skills as used.
    pub async fn build_injection(&self, matched: &[&Skill], caveman: CavemanLevel) -> Option<String> {
        if matched.is_empty() { return None; }

        let mut used_lock = self.used_skills.lock().await;
        let mut fragments = Vec::new();

        for s in matched {
            fragments.push(format!("[MITRE {}] {}", s.mitre.technique.as_deref().unwrap_or(&s.mitre.tactic), s.prompt_fragment));
            // Mark as used to avoid redundancy in future calls of the same mission
            used_lock.insert(s.id.clone());
        }

        let composite = fragments.join(" | ");
        Some(crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&composite, caveman))
    }

    /// Resets the usage history (e.g. for a new mission)
    pub async fn reset_history(&self) {
        let mut used_lock = self.used_skills.lock().await;
        used_lock.clear();
    }
}
