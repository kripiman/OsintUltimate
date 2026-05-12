use tlsh_fixed::{TlshBuilder, BucketKind, ChecksumKind, Version};

/// Computes the TLSH hash of a given input string.
/// TLSH requires a minimum of 50 bytes of input with sufficient complexity to generate a hash.
pub fn compute_tlsh(input: &str) -> Option<String> {
    // [守門機制] TLSH input must be at least 50 bytes.
    if input.len() < 50 {
        return None;
    }
    
    // Standard configuration for TLSH
    let mut builder = TlshBuilder::new(BucketKind::Bucket128, ChecksumKind::OneByte, Version::Version4);
    builder.update(input.as_bytes());
    
    match builder.build() {
        Ok(tlsh) => Some(tlsh.hash()),
        Err(_) => None,
    }
}

/// Calculates the TLSH distance between two hashes.
/// A distance < 30 generally indicates a high degree of similarity (e.g. > 85%).
pub fn calculate_distance(hash1: &str, hash2: &str) -> Option<u32> {
    use std::str::FromStr;
    let t1 = tlsh_fixed::Tlsh::from_str(hash1).ok()?;
    let t2 = tlsh_fixed::Tlsh::from_str(hash2).ok()?;
    
    // diff compares the hashes. true usually means "include length difference".
    Some(t1.diff(&t2, true) as u32)
}
