use regex::Regex;
use std::sync::LazyLock;

static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b").expect("Valid IP regex")
});
static IPV6_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}):[0-9a-fA-F:]+\b").expect("Valid IPv6 regex")
});
static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").expect("Valid email regex")
});
static KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{43}=").expect("Valid key regex"));
static CODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z0-9]{25}\b").expect("Valid code regex"));
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,2}").expect("Valid JWT regex")
});
static BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]+").expect("Valid Bearer token regex")
});

/// Scrubs Personally Identifiable Information (PII) from logs.
pub fn scrub_pii(input: &str) -> String {
    let s = IPV4_RE.replace_all(input, "[REDACTED_IP]");
    let s = IPV6_RE.replace_all(&s, "[REDACTED_IP]");
    let s = EMAIL_RE.replace_all(&s, "[REDACTED_EMAIL]");
    let s = KEY_RE.replace_all(&s, "[REDACTED_KEY]");
    let s = CODE_RE.replace_all(&s, "[REDACTED_CODE]");
    let s = JWT_RE.replace_all(&s, "[MASKED_TOKEN]");
    let s = BEARER_RE.replace_all(&s, "Bearer [REDACTED_TOKEN]");
    s.into_owned()
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
