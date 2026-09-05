use regex::Regex;
use std::sync::LazyLock;

static COMBINED_PII_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Principal Standard: Combined regex with named capture groups for Single-Pass traversal.
    // This reduces algorithmic complexity from O(N * M) to O(N).
    Regex::new(concat!(
        r"(?P<ip>\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)|",
        r"(?P<ipv6>\b[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F:]+\b)|",
        r"(?P<email>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)|",
        r"(?P<key>[A-Za-z0-9+/]{43}=)|",
        r"(?P<code>\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b|\b[A-Z0-9]{25}\b)|",
        r"(?P<jwt>eyJ[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,2})|",
        r"(?P<bearer>(?i)bearer\s+[a-zA-Z0-9_\-\.=]+)"
    )).expect("Valid combined PII regex")
});

/// Scrubs Personally Identifiable Information (PII) from logs.
/// Big-Tech Grade: Single-pass replacement for O(N) performance.
pub fn scrub_pii(input: &str) -> String {
    COMBINED_PII_RE
        .replace_all(input, |caps: &regex::Captures| {
            if caps.name("ip").is_some() || caps.name("ipv6").is_some() {
                "[REDACTED_IP]"
            } else if caps.name("email").is_some() {
                "[REDACTED_EMAIL]"
            } else if caps.name("key").is_some() {
                "[REDACTED_KEY]"
            } else if caps.name("code").is_some() {
                "[REDACTED_CODE]"
            } else if caps.name("jwt").is_some() {
                "[MASKED_TOKEN]"
            } else if caps.name("bearer").is_some() {
                "Bearer [REDACTED_TOKEN]"
            } else {
                "[REDACTED]"
            }
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_pii() {
        let raw = "User with email test@example.com and IP 192.168.1.50 accessed with key ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs= and code ABCDEFGHIJKLMNOPQRSTUVWXY";
        let scrubbed = scrub_pii(raw);
        assert!(scrubbed.contains("[REDACTED_EMAIL]"));
        assert!(scrubbed.contains("[REDACTED_IP]"));
        assert!(scrubbed.contains("[REDACTED_KEY]"));
        assert!(scrubbed.contains("[REDACTED_CODE]"));
    }
}
