#[cfg(test)]
mod tests {
    use crate::models::objectives::{Objective, ObjectiveStatus, ObjectivePhase, OPPLAN};

    #[test]
    fn test_graph_resolution_multiple_deps() -> anyhow::Result<()> {
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
    fn test_graph_blocked_deps() -> anyhow::Result<()> {
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
