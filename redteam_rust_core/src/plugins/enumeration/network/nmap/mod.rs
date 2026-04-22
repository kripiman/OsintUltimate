pub mod parser;
pub mod classifier;

pub use parser::parse_nmap_xml;
pub use classifier::{classify_script_severity, suggest_exploit_vector};
