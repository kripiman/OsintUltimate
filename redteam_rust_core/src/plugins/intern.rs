//! Plugin name interner.
//!
//! Bounds memory leakage for dynamic plugin names (FFI/WASM) by deduplicating
//! leaked strings by value. The first time a distinct name is loaded it is
//! leaked once; subsequent loads of the same name return the existing reference.
//!
//! This is defensive hardening for future hot-reload loops. Today plugins are
//! loaded once at boot, so the leak is already bounded by the number of
//! distinct plugins. With the interner, that bound holds even if the same
//! plugin is reloaded many times.

use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::sync::Mutex;

static NAME_INTERNER: Lazy<Mutex<HashSet<&'static str>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

/// Returns a `'static` reference to `name`, interning it if not seen before.
///
/// Bounded by the number of distinct plugin names ever interned.
pub(crate) fn intern_name(name: &str) -> &'static str {
    let mut set = NAME_INTERNER.lock().unwrap();
    if let Some(existing) = set.get(name) {
        return existing;
    }
    let leaked = Box::leak(name.to_owned().into_boxed_str());
    set.insert(leaked);
    leaked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_deduplicates_identical_names() {
        let a = intern_name("duplicate");
        let b = intern_name("duplicate");
        assert_eq!(a, b);
        // Same pointer — only one leak occurred for this distinct name.
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn intern_distinct_names_different() {
        let a = intern_name("alpha");
        let b = intern_name("beta");
        assert_ne!(a, b);
        assert!(!std::ptr::eq(a, b));
    }
}
