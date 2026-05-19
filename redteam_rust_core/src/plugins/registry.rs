use crate::plugins::{ScannerPlugin, DiscoveryPlugin, TargetType, RiskLevel};
use crate::utils::executor::ExecutorMode;
use crate::plugins::config::GlobalConfig;

pub struct PluginRegistry {
    pub scanners: Vec<Box<dyn ScannerPlugin>>,
    pub discovery: Vec<Box<dyn DiscoveryPlugin>>,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
            discovery: Vec::new(),
        }
    }

    pub fn add_scanner(&mut self, scanner: Box<dyn ScannerPlugin>) {
        self.scanners.push(scanner);
    }

    pub fn add_discovery(&mut self, discovery: Box<dyn DiscoveryPlugin>) {
        self.discovery.push(discovery);
    }

    pub fn get_scanners_for_target(&self, target_type: TargetType) -> Vec<&dyn ScannerPlugin> {
        self.scanners.iter()
            .filter(|p| p.metadata().target_type == target_type)
            .map(|p| p.as_ref())
            .collect()
    }

    pub fn get_safe_scanners(&self) -> Vec<&dyn ScannerPlugin> {
        self.scanners.iter()
            .filter(|p| p.metadata().risk_level == RiskLevel::Safe)
            .map(|p| p.as_ref())
            .collect()
    }
}

pub fn get_registry<M: ExecutorMode>(config: GlobalConfig<M>) -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    
    for scanner in super::scanner_factory::get_all_scanners(config.clone()) {
        registry.add_scanner(scanner);
    }
    
    for discovery in super::discovery_factory::get_all_discovery(config) {
        registry.add_discovery(discovery);
    }
    
    registry
}
