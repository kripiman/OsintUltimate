use crate::plugins::Capability;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackArchTool {
    pub name: String,
    pub category: String,
    pub description: String,
    pub capabilities: Vec<Capability>,
}

pub struct BlackArchBridge {
    pub tools: HashMap<String, BlackArchTool>,
    pub available_tools: HashSet<String>, // CACHE: avoids repeated `which` calls
}

impl BlackArchBridge {
    pub fn new() -> Self {
        let mut tools = HashMap::new();

        // Mapeo inicial de herramientas populares de BlackArch
        // En una versión más avanzada, esto se cargaría de un JSON dinámico
        
        let popular_tools = vec![
            BlackArchTool {
                name: "sqlmap".to_string(),
                category: "webapp".to_string(),
                description: "Automatic SQL injection and database takeover tool".to_string(),
                capabilities: vec![Capability::SqlInjection, Capability::VulnerabilityScanning, Capability::ApiSecurity],
            },
            BlackArchTool {
                name: "nmap".to_string(),
                category: "scanner".to_string(),
                description: "Network exploration tool and security / port scanner".to_string(),
                capabilities: vec![Capability::PortScanning, Capability::ServiceDiscovery],
            },
            BlackArchTool {
                name: "nuclei".to_string(),
                category: "scanner".to_string(),
                description: "Fast and customizable vulnerability scanner based on simple YAML based templates".to_string(),
                capabilities: vec![Capability::VulnerabilityScanning, Capability::WebFuzzing],
            },
            BlackArchTool {
                name: "hydra".to_string(),
                category: "cracker".to_string(),
                description: "Network logon cracker which supports many different services".to_string(),
                capabilities: vec![Capability::BruteForce], 
            },
            BlackArchTool {
                name: "dalfox".to_string(),
                category: "webapp".to_string(),
                description: "Parameter Analysis and XSS Scanning tool based on golang".to_string(),
                capabilities: vec![Capability::XssScanning, Capability::VulnerabilityScanning],
            },
            BlackArchTool {
                name: "commix".to_string(),
                category: "exploitation".to_string(),
                description: "Automated All-in-One OS Command Injection and Exploitation Tool".to_string(),
                capabilities: vec![Capability::CommandInjection, Capability::VulnerabilityScanning], 
            },
            BlackArchTool {
                name: "graphql-cop".to_string(),
                category: "webapp".to_string(),
                description: "GraphQL security auditor".to_string(),
                capabilities: vec![Capability::VulnerabilityScanning, Capability::GraphQL],
            },
        ];

        let mut available_tools = HashSet::new();
        for tool in popular_tools {
            if which::which(&tool.name).is_ok() {
                available_tools.insert(tool.name.clone());
            }
            tools.insert(tool.name.clone(), tool);
        }

        Self { tools, available_tools }
    }

    pub fn is_tool_installed(&self, tool_name: &str) -> bool {
        self.available_tools.contains(tool_name)
    }

    pub fn get_available_tools(&self) -> Vec<&BlackArchTool> {
        self.tools.values()
            .filter(|t| self.is_tool_installed(&t.name))
            .collect()
    }

    pub fn suggest_tools_for_capability(&self, capability: Capability) -> Vec<&BlackArchTool> {
        self.tools.values()
            .filter(|t| t.capabilities.contains(&capability) && self.is_tool_installed(&t.name))
            .collect()
    }
}
