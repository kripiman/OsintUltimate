use serde::{Deserialize, Serialize};
use std::fmt;
use std::collections::{HashMap, HashSet};
use anyhow::{Result, anyhow};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveStatus {
    Pending,
    InProgress,
    Completed,
    Blocked,
    Cancelled,
}

impl fmt::Display for ObjectiveStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjectivePhase {
    Recon,
    InitialAccess,
    LateralMovement,
    PostExploitation,
    Exfiltration,
    Persistence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpsecLevel {
    Minimum,
    Default,
    High,
    Paranoid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Objective {
    pub id: String,              // OBJ-xxx
    pub title: String,
    pub description: String,
    pub status: ObjectiveStatus,
    pub phase: ObjectivePhase,
    pub opsec: OpsecLevel,
    pub depends_on: Vec<String>, // Soporte para Grafo de Dependencias
    pub acceptance_criteria: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub findings_produced: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub priority: u8,            // 1-5 (Alta a Baja)
    pub agent_assigned: Option<String>,
}

impl Objective {
    pub fn new(id: &str, title: &str, description: &str, phase: ObjectivePhase) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: id.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            status: ObjectiveStatus::Pending,
            phase,
            opsec: OpsecLevel::Default,
            depends_on: Vec::new(),
            acceptance_criteria: Vec::new(),
            mitre_tactics: Vec::new(),
            findings_produced: Vec::new(),
            created_at: now,
            updated_at: now,
            priority: 3,
            agent_assigned: None,
        }
    }

    pub fn with_status(mut self, status: ObjectiveStatus) -> Self {
        self.status = status;
        self.updated_at = chrono::Utc::now();
        self
    }

    pub fn with_opsec(mut self, level: OpsecLevel) -> Self {
        self.opsec = level;
        self
    }

    pub fn add_dependency(mut self, dependency_id: &str) -> Self {
        self.depends_on.push(dependency_id.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OPPLAN {
    pub objectives: HashMap<String, Objective>,
}

impl OPPLAN {
    pub fn new() -> Self {
        Self {
            objectives: HashMap::new(),
        }
    }

    pub fn add_objective(&mut self, objective: Objective) -> Result<()> {
        if self.objectives.contains_key(&objective.id) {
            return Err(anyhow!("Objective ID '{}' already exists in OPPLAN", objective.id));
        }
        
        // Verificar que las dependencias existan si el plan ya está poblado
        for dep in &objective.depends_on {
            if !self.objectives.contains_key(dep) {
                tracing::warn!("⚠️ OPPLAN: Objective '{}' depends on non-existent ID '{}'", objective.id, dep);
            }
        }

        self.objectives.insert(objective.id.clone(), objective);
        self.validate_cycles()?;
        Ok(())
    }

    /// Implementación de Detección de Ciclos (DFS) para Grafos de Dependencia.
    pub fn validate_cycles(&self) -> Result<()> {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for id in self.objectives.keys() {
            if self.has_cycle_util(id, &mut visited, &mut rec_stack) {
                return Err(anyhow!("OPPLAN Error: Cyclic dependency detected involving objective '{}'", id));
            }
        }
        Ok(())
    }

    fn has_cycle_util(&self, id: &str, visited: &mut HashSet<String>, rec_stack: &mut HashSet<String>) -> bool {
        if rec_stack.contains(id) {
            return true;
        }
        if visited.contains(id) {
            return false;
        }

        visited.insert(id.to_string());
        rec_stack.insert(id.to_string());

        if let Some(obj) = self.objectives.get(id) {
            for dep in &obj.depends_on {
                if self.has_cycle_util(dep, visited, rec_stack) {
                    return true;
                }
            }
        }

        rec_stack.remove(id);
        false
    }

    /// Retorna los siguientes objetivos que pueden ser ejecutados (pendientes y con dependencias completadas).
    pub fn next_pending(&self) -> Vec<&Objective> {
        self.objectives.values()
            .filter(|obj| obj.status == ObjectiveStatus::Pending)
            .filter(|obj| {
                // Todas las dependencias deben estar en estado 'Completed'
                obj.depends_on.iter().all(|dep_id| {
                    match self.objectives.get(dep_id) {
                        Some(dep) => dep.status == ObjectiveStatus::Completed,
                        None => false, // Dependencia no encontrada = no puede avanzar
                    }
                })
            })
            .collect()
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let plan = serde_json::from_str(&content)?;
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_resolution_multiple_deps() -> Result<()> {
        let mut plan = OPPLAN::new();

        let obj1 = Objective::new("OBJ-001", "Scope Recon", "Identify assets", ObjectivePhase::Recon)
            .with_status(ObjectiveStatus::Completed);
        let obj2 = Objective::new("OBJ-002", "Service Enum", "Scan ports", ObjectivePhase::Recon)
            .with_status(ObjectiveStatus::Completed);
        
        // OBJ-003 depende de obj1 Y obj2
        let obj3 = Objective::new("OBJ-003", "Vuln Scan", "Deep scan", ObjectivePhase::Recon)
            .add_dependency("OBJ-001")
            .add_dependency("OBJ-002");

        plan.add_objective(obj1)?;
        plan.add_objective(obj2)?;
        plan.add_objective(obj3)?;

        let next = plan.next_pending();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].id, "OBJ-003");

        Ok(())
    }

    #[test]
    fn test_graph_blocked_deps() -> Result<()> {
        let mut plan = OPPLAN::new();

        let obj1 = Objective::new("OBJ-001", "Exploit A", "Try A", ObjectivePhase::InitialAccess)
            .with_status(ObjectiveStatus::Completed);
        let obj2 = Objective::new("OBJ-002", "Exploit B", "Try B", ObjectivePhase::InitialAccess)
            .with_status(ObjectiveStatus::Pending); // Todavía pendiente
        
        let obj3 = Objective::new("OBJ-003", "Pivot", "Lateral movement", ObjectivePhase::LateralMovement)
            .add_dependency("OBJ-001")
            .add_dependency("OBJ-002");

        plan.add_objective(obj1)?;
        plan.add_objective(obj2)?;
        plan.add_objective(obj3)?;

        let next = plan.next_pending();
        // Solo OBJ-002 debería estar pendiente (OBJ-003 está bloqueado por OBJ-002)
        assert!(next.iter().any(|o| o.id == "OBJ-002"));
        assert!(!next.iter().any(|o| o.id == "OBJ-003"));

        Ok(())
    }

    #[test]
    fn test_cycle_detection() {
        let mut plan = OPPLAN::new();

        let obj1 = Objective::new("OBJ-001", "A", "", ObjectivePhase::Recon)
            .add_dependency("OBJ-002");
        let obj2 = Objective::new("OBJ-002", "B", "", ObjectivePhase::Recon)
            .add_dependency("OBJ-001");

        let _ = plan.add_objective(obj1);
        let result = plan.add_objective(obj2);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cyclic dependency"));
    }
}
