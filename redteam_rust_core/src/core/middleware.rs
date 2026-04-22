use crate::core::blackarch::BlackArchTool;
use crate::core::policy::PolicyProvider;
use anyhow::{Result, anyhow};
use std::sync::Arc;

pub trait CommandMiddleware: Send + Sync {
    fn name(&self) -> &str;
    fn validate(&self, tool: &BlackArchTool, args: &[String], policy: &dyn PolicyProvider) -> Result<()>;
}

pub struct TargetScopeMiddleware;

impl CommandMiddleware for TargetScopeMiddleware {
    fn name(&self) -> &str {
        "TargetScopeMiddleware"
    }

    fn validate(&self, _tool: &BlackArchTool, args: &[String], policy: &dyn PolicyProvider) -> Result<()> {
        let roe = policy.get_roe();
        if roe.is_none() {
            // Si no hay RoE formal cargado aún, permitimos asumiendo Dev Mode o rely-on-StaticPolicy.
            return Ok(());
        }

        for arg in args {
            if self.is_target_like(arg)
                && !policy.is_target_allowed(arg) {
                    return Err(anyhow!("TargetScopeViolation: Argument '{}' is outside the authorized Rules of Engagement (RoE).", arg));
                }
        }
        Ok(())
    }
}

impl TargetScopeMiddleware {
    fn is_target_like(&self, arg: &str) -> bool {
        // Un heurístico simple para detectar dominios/IPs que no son flags
        (arg.contains('.') || arg.contains(':')) && !arg.starts_with('-')
    }
}

pub struct FlagSafetyMiddleware;

impl CommandMiddleware for FlagSafetyMiddleware {
    fn name(&self) -> &str {
        "FlagSafetyMiddleware"
    }

    fn validate(&self, tool: &BlackArchTool, args: &[String], _policy: &dyn PolicyProvider) -> Result<()> {
        let tool_name = tool.name.to_lowercase();
        
        // Example: Nmap specific safety
        if tool_name == "nmap" {
            for arg in args {
                if arg == "--script" {
                    // We allow scripts only if they are vetted (future enhancement)
                    // For now, let's just warn or block if it's too broad
                }
                if arg == "-oN" || arg == "-oX" || arg == "-oG" || arg == "-oA" {
                    return Err(anyhow!("FlagSafetyViolation: Manual output redirection '-o' is forbidden. Sinks handle persistence."));
                }
            }
        }

        // Example: Hydra specific safety
        if tool_name == "hydra" {
            for arg in args {
                if arg == "-t" {
                    // Check for excessive threads
                }
            }
        }

        Ok(())
    }
}

pub struct SafeCommandMiddleware;

impl CommandMiddleware for SafeCommandMiddleware {
    fn name(&self) -> &str {
        "SafeCommandMiddleware"
    }

    fn validate(&self, tool: &BlackArchTool, args: &[String], _policy: &dyn PolicyProvider) -> Result<()> {
        let forbidden_binaries = ["pkill", "killall", "nsenter", "eval", "iptables", "rm", "mkfs", "dd"];
        
        // Check the tool itself
        let tool_name = tool.name.to_lowercase();
        if forbidden_binaries.contains(&tool_name.as_str()) {
            return Err(anyhow!("SafeCommandViolation: The tool '{}' is restricted for safety reasons.", tool_name));
        }

        // Check for binary execution in arguments
        for arg in args {
            let arg_lower = arg.to_lowercase();
            for bin in forbidden_binaries {
                if arg_lower == *bin || arg_lower.starts_with(&format!("{} ", bin)) {
                    return Err(anyhow!("SafeCommandViolation: Potentially dangerous command '{}' detected in arguments.", bin));
                }
            }
        }

        Ok(())
    }
}

pub struct MiddlewareRegistry {
    middlewares: Vec<Arc<dyn CommandMiddleware>>,
}

impl MiddlewareRegistry {
    pub fn new() -> Self {
        Self { middlewares: Vec::new() }
    }

    pub fn add(&mut self, middleware: Arc<dyn CommandMiddleware>) {
        self.middlewares.push(middleware);
    }

    pub fn validate_all(&self, tool: &BlackArchTool, args: &[String], policy: &dyn PolicyProvider) -> Result<()> {
        for middleware in &self.middlewares {
            middleware.validate(tool, args, policy)?;
        }
        Ok(())
    }
}

impl Default for MiddlewareRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.add(Arc::new(TargetScopeMiddleware));
        registry.add(Arc::new(FlagSafetyMiddleware));
        registry.add(Arc::new(SafeCommandMiddleware));
        registry
    }
}
