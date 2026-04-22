/// V14.8 Sync: Sanitizes a string to ensure it only contains printable ASCII characters.
/// Prevents technical terminology from being mangled while stripping potentially harmful binary or control chars.
pub fn to_ascii_safe(input: &str) -> String {
    input.chars()
        .filter(|c| c.is_ascii() && (!c.is_control() || *c == '\n' || *c == '\r' || *c == '\t'))
        .collect()
}

/// V14.8 Sync: More aggressive sanitization for shell contexts.
pub fn to_shell_safe(input: &str) -> String {
    input.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-' | '.' | '/' | ':' | ' '))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_ascii_safe() {
        let input = "Hello \x00 world! \n \r \t 卒業";
        let expected = "Hello  world! \n \r \t ";
        assert_eq!(to_ascii_safe(input), expected);
    }
}
