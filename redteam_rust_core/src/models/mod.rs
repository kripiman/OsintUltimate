pub mod findings;
pub mod scan_result;

pub use findings::{Finding, Severity, Category, Evidence};
pub use scan_result::{ScanResult, TargetHost, ScanMetadata};
