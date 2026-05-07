// Detection and evasion plugins
pub mod jitter;
pub mod stealth_policy;
#[cfg(feature = "sovereign")]
pub mod scarecrow;
#[cfg(feature = "sovereign")]
pub mod donut;
