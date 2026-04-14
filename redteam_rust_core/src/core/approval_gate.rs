// src/core/approval_gate.rs (NUEVO)
// 🚪 Risk Approval Gate - Control de acciones de alto riesgo
// 🔐 Garantiza conformidad y rastro de auditoría

use dashmap::DashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn, error};
use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub role: UserRole,
    pub authorized_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    Analyst,           // Can only view reports
    RedTeamBasic,      // Scanning + Discovery layers
    RedTeamFull,       // All layers including Exploitation
    Administrator,     // Full access + can approve actions
    CISO,             // Compliance + executive oversight
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub action: String,
    pub risk_level: u8,  // 0-100
    pub required_by: DateTime<Utc>,
    pub requested_by: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved { by: String, at: DateTime<Utc>, reason: String, handover_payload: Option<String> },
    Rejected { by: String, at: DateTime<Utc>, reason: String },
    Expired,
}

/// Gate que controla acciones de alto riesgo
pub struct ApprovalGate {
    risk_threshold: u8,
    pub pending_approvals: Arc<DashMap<String, ApprovalRequest>>,
    approval_cache: Arc<DashMap<String, ApprovalStatus>>,
    audit_log: Arc<DashMap<DateTime<Utc>, AuditLogEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: DateTime<Utc>,
    pub user: String,
    pub action: String,
    pub result: String,
    pub details: serde_json::Value,
}

impl ApprovalGate {
    pub fn new(risk_threshold: u8) -> Self {
        Self {
            risk_threshold,
            pending_approvals: Arc::new(DashMap::new()),
            approval_cache: Arc::new(DashMap::new()),
            audit_log: Arc::new(DashMap::new()),
        }
    }
    
    pub fn for_red_team() -> Self {
        Self::new(80) // Aprobación requerida para acciones > 80 risk
    }
    
    pub fn for_authorized_testing() -> Self {
        Self::new(100) // Sin aprobaciones, todo permitido
    }
    
    pub fn for_compliance() -> Self {
        Self::new(50) // Aprobación para casi todo
    }
    
    /// Solicita aprobación para una acción de alto riesgo. Responde con `None` si se aprueba automáticamente, o `Some(request_id)` si aguarda aprobación.
    pub async fn request_approval(
        &self,
        action: &str,
        risk_level: u8,
        user: &User,
        reason: &str,
    ) -> Result<Option<String>> {
        // Si el riesgo está por debajo del threshold, aprobada automáticamente
        if risk_level <= self.risk_threshold {
            self.log_action(
                user.name.clone(),
                action.to_string(),
                "APPROVED (Auto - Low Risk)".to_string(),
                serde_json::json!({"risk_level": risk_level, "threshold": self.risk_threshold}),
            ).await;
            return Ok(None);
        }
        
        // Riesgo alto: crear solicitud de aprobación
        let request = ApprovalRequest {
            id: uuid::Uuid::new_v4().to_string(),
            action: action.to_string(),
            risk_level,
            required_by: Utc::now() + chrono::Duration::hours(1),
            requested_by: user.name.clone(),
            reason: reason.to_string(),
        };
        
        warn!(
            "High-risk action request: {} (Risk: {}/100) by {}",
            action, risk_level, user.name
        );
        
        let request_id = request.id.clone();
        self.pending_approvals.insert(request.id.clone(), request);
        
        self.log_action(
            user.name.clone(),
            action.to_string(),
            "PENDING_APPROVAL".to_string(),
            serde_json::json!({"request_id": request_id}),
        ).await;
        
        // En una implementación real, notificación a CISO/Admin
        Ok(Some(request_id))
    }
    
    /// Aprueba una solicitud pendiente
    pub async fn approve(
        &self,
        request_id: &str,
        approver: &User,
        reason: &str,
        handover_payload: Option<String>,
    ) -> Result<()> {
        if approver.role != UserRole::Administrator && approver.role != UserRole::CISO {
            return Err(anyhow!("User {} not authorized to approve requests", approver.name));
        }
        
        let status = ApprovalStatus::Approved {
            by: approver.name.clone(),
            at: Utc::now(),
            reason: reason.to_string(),
            handover_payload: handover_payload.clone(),
        };
        
        self.approval_cache.insert(request_id.to_string(), status);
        self.pending_approvals.remove(request_id);
        
        info!("Request {} approved by {}", request_id, approver.name);
        
        self.log_action(
            approver.name.clone(),
            format!("APPROVE_REQUEST:{}", request_id),
            "APPROVED".to_string(),
            serde_json::json!({"request_id": request_id, "reason": reason}),
        ).await;
        
        Ok(())
    }
    
    /// Rechaza una solicitud
    pub async fn reject(
        &self,
        request_id: &str,
        rejector: &User,
        reason: &str,
    ) -> Result<()> {
        if rejector.role != UserRole::Administrator && rejector.role != UserRole::CISO {
            return Err(anyhow!("User {} not authorized to reject requests", rejector.name));
        }
        
        let status = ApprovalStatus::Rejected {
            by: rejector.name.clone(),
            at: Utc::now(),
            reason: reason.to_string(),
        };
        
        self.approval_cache.insert(request_id.to_string(), status);
        self.pending_approvals.remove(request_id);
        
        error!("Request {} rejected by {}", request_id, rejector.name);
        
        self.log_action(
            rejector.name.clone(),
            format!("REJECT_REQUEST:{}", request_id),
            "REJECTED".to_string(),
            serde_json::json!({"request_id": request_id, "reason": reason}),
        ).await;
        
        Ok(())
    }
    
    /// Verifica si una acción ya fue aprobada
    pub async fn is_approved(&self, action_id: &str) -> bool {
        if let Some(status) = self.approval_cache.get(action_id) {
            return matches!(*status, ApprovalStatus::Approved { .. });
        }
        false
    }
    
    pub fn approval_cache(&self) -> Arc<DashMap<String, ApprovalStatus>> {
        self.approval_cache.clone()
    }
    
    /// Bloquea temporalmente hasta que se apruebe o rechace una solicitud
    pub async fn wait_for_approval(&self, request_id: &str, timeout_secs: u64) -> bool {
        use tokio::time::{sleep, Duration};
        let start = std::time::Instant::now();
        
        while start.elapsed().as_secs() < timeout_secs {
            if let Some(status) = self.approval_cache.get(request_id) {
                return matches!(*status, ApprovalStatus::Approved { .. });
            }
            sleep(Duration::from_millis(1000)).await;
        }
        
        // V14.1 AGT-001: Explicitly expire the request on timeout to prevent late approval race
        self.approval_cache.insert(request_id.to_string(), ApprovalStatus::Expired);
        self.pending_approvals.remove(request_id);
        
        false
    }
    
    async fn log_action(
        &self,
        user: String,
        action: String,
        result: String,
        details: serde_json::Value,
    ) {
        let timestamp = Utc::now();
        let entry = AuditLogEntry {
            timestamp,
            user,
            action,
            result,
            details,
        };
        
        self.audit_log.insert(timestamp, entry);
    }
    
    /// Exporta el audit log
    pub async fn get_audit_log(&self) -> Vec<AuditLogEntry> {
        let mut logs: Vec<_> = self.audit_log.iter().map(|kv| kv.value().clone()).collect();
        logs.sort_by_key(|l| l.timestamp);
        logs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_auto_approval_low_risk() {
        let gate = ApprovalGate::for_red_team();
        let user = User {
            id: "user1".to_string(),
            name: "Tester".to_string(),
            role: UserRole::RedTeamBasic,
            authorized_at: Utc::now(),
        };
        
        let result = gate.request_approval(
            "Low risk action",
            30,  // < 80 threshold
            &user,
            "Testing",
        ).await;
        
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
    
    #[tokio::test]
    async fn test_high_risk_requires_approval() {
        let gate = ApprovalGate::for_red_team();
        let user = User {
            id: "user1".to_string(),
            name: "Tester".to_string(),
            role: UserRole::RedTeamBasic,
            authorized_at: Utc::now(),
        };
        
        let result = gate.request_approval(
            "High risk action",
            95,  // > 80 threshold
            &user,
            "Testing",
        ).await;
        
        assert!(result.is_ok());
        assert!(result.unwrap().is_some()); // Require validation
    }
}
