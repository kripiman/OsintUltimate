use sysinfo::System;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfrastructureType {
    UltraLowMemory,
    LocalPC,
    Server,
    Hybrid,
}

pub struct HardwareInfo {
    pub infra_type: InfrastructureType,
    pub cores: usize,
    pub ram_mb: u64,
}

pub fn detect_infrastructure() -> HardwareInfo {
    let mut sys = System::new_all();
    sys.refresh_all();

    let cores = sys.cpus().len();
    let ram_mb = sys.total_memory() / (1024 * 1024);

    let infra_type = if ram_mb <= 1536 {
        InfrastructureType::UltraLowMemory
    } else if cores <= 4 && ram_mb <= 16384 {
        InfrastructureType::LocalPC
    } else if cores > 8 && ram_mb > 32768 {
        InfrastructureType::Server
    } else {
        InfrastructureType::Hybrid
    };

    HardwareInfo {
        infra_type,
        cores,
        ram_mb,
    }
}
