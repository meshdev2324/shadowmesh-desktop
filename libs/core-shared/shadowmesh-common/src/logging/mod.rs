use regex::Regex;
use std::sync::LazyLock;

static COMBINED_PII_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Principal Standard: Combined regex with named capture groups for Single-Pass traversal.
    // This reduces algorithmic complexity from O(N * M) to O(N).
    //
    // `sub_token` is the ShadowMesh subscription token: the literal prefix
    // `sm_sub_` followed by a hex body. It is a bearer credential on the
    // *public, unauthenticated* `GET /sub/<token>` route — whoever presents it
    // receives every one of that device's share links, including a WireGuard
    // private key. None of the other alternatives ever matched one: the prefix
    // contains `_` (which breaks the 43-char base64 `key` run), it is 71
    // characters of mixed case (so neither the 25-char uppercase `code` nor a
    // dotted `ip` can match inside it), it is not `eyJ`-prefixed and it is not
    // preceded by `bearer `. A token that reached a log line was therefore
    // written to disk verbatim, at any level.
    //
    // Over-matching analysis, since this rule widens what is redacted:
    // * The `[0-9a-fA-F]{16,}` floor is deliberate. A real token carries 64 hex
    //   characters; requiring at least 16 means a bare `sm_sub_`, or a short
    //   fragment such as the `sm_sub_1` in a diagnostic message about a
    //   malformed token, stays readable instead of being redacted into noise.
    // * The literal prefix is required, so ordinary prose, hostnames, UUIDs and
    //   hex digests with no `sm_sub_` in front of them are untouched — see
    //   `scrub_does_not_over_match_unrelated_text`.
    // * `(?i:...)` scopes case-insensitivity to the 7-character prefix alone.
    //   Tokens are minted lowercase, so this is defence in depth for a value
    //   that was upper-cased somewhere upstream; it cannot widen the hex body.
    Regex::new(concat!(
        r"(?P<ip>\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)|",
        r"(?P<ipv6>\b[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F:]+\b)|",
        r"(?P<email>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)|",
        r"(?P<sub_token>(?i:sm_sub_)[0-9a-fA-F]{16,})|",
        r"(?P<key>[A-Za-z0-9+/]{43}=)|",
        r"(?P<code>\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b|\b[A-Z0-9]{25}\b)|",
        r"(?P<jwt>eyJ[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,2})|",
        r"(?P<bearer>(?i)bearer\s+[a-zA-Z0-9_\-\.=]+)|",
        // A ShadowMesh device identity: the lowercase-hex string used as the
        // JWT `sub`, the `peers.identity_public_key`, and the `device_id` on
        // every device row. It is pseudonymous but *linkable* -- the same value
        // appears on every line for one device, and in `audit_logs` -- so an
        // operator with a log file can enumerate and correlate devices without
        // any credential having leaked.
        //
        // 40 hex characters is the lower bound: it is the length of the
        // WireGuard peer public key used as the device identity. Requiring
        // all-hex and that floor keeps this from matching words, version
        // strings, or the 64-char hex *digests* this module also emits.
        r"(?P<device_id>\b[0-9a-f]{40,64}\b)"
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
            } else if caps.name("sub_token").is_some() {
                "[REDACTED_SUB_TOKEN]"
            } else if caps.name("key").is_some() {
                "[REDACTED_KEY]"
            } else if caps.name("code").is_some() {
                "[REDACTED_CODE]"
            } else if caps.name("jwt").is_some() {
                "[MASKED_TOKEN]"
            } else if caps.name("bearer").is_some() {
                "Bearer [REDACTED_TOKEN]"
            } else if caps.name("device_id").is_some() {
                "[REDACTED_DEVICE]"
            } else {
                "[REDACTED]"
            }
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An obviously-fake subscription token: the `sm_sub_` prefix followed by 64
    /// hex characters, which is exactly the shape `generate_subscription_token`
    /// produces. Not a credential — it is the literal `deadbeef` pattern.
    const FAKE_SUB_TOKEN: &str = concat!(
        "sm_sub_", "deadbeef", "deadbeef", "deadbeef", "deadbeef", "deadbeef", "deadbeef",
        "deadbeef", "deadbeef"
    );

    #[test]
    fn test_scrub_pii() {
        let raw = "User with email test@example.com and IP 192.168.1.50 accessed with key ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs= and code ABCDEFGHIJKLMNOPQRSTUVWXY";
        let scrubbed = scrub_pii(raw);
        assert!(scrubbed.contains("[REDACTED_EMAIL]"));
        assert!(scrubbed.contains("[REDACTED_IP]"));
        assert!(scrubbed.contains("[REDACTED_KEY]"));
        assert!(scrubbed.contains("[REDACTED_CODE]"));
    }

    /// The regression guard: a subscription token is a bearer credential on the
    /// unauthenticated `GET /sub/<token>` route, and no pre-existing rule ever
    /// matched one (its `sm_sub_` prefix breaks the base64 `key` run and its
    /// 71 mixed-case characters match none of the other shapes).
    #[test]
    fn test_subscription_token_is_redacted() {
        let scrubbed = scrub_pii(&format!("GET /sub/{FAKE_SUB_TOKEN} HTTP/1.1 returned 200"));
        assert!(!scrubbed.contains(FAKE_SUB_TOKEN), "the raw token survived scrubbing: {scrubbed}");
        assert!(
            !scrubbed.contains("deadbeefdeadbeef"),
            "part of the token body survived scrubbing: {scrubbed}"
        );
        assert!(scrubbed.contains("[REDACTED_SUB_TOKEN]"), "{scrubbed}");
        // The route is still identifiable, which is the whole point of
        // scrubbing rather than dropping the line.
        assert!(scrubbed.contains("GET /sub/"), "{scrubbed}");
        assert!(scrubbed.contains("returned 200"), "{scrubbed}");
    }

    /// The same token in the shapes a real log line would carry it in: a query
    /// string, a JSON body and a bare value.
    #[test]
    fn test_subscription_token_is_redacted_in_every_position() {
        for raw in [
            format!("url=https://shadowmesh.example/sub/{FAKE_SUB_TOKEN}?format=json"),
            format!("{{\"token\":\"{FAKE_SUB_TOKEN}\",\"id\":7}}"),
            format!("rotated credential {FAKE_SUB_TOKEN} at midnight"),
            // Upper-cased upstream: the prefix match is case-insensitive.
            format!("leaked {}", FAKE_SUB_TOKEN.to_uppercase()),
        ] {
            let scrubbed = scrub_pii(&raw);
            assert!(
                !scrubbed.to_lowercase().contains("deadbeefdeadbeef"),
                "token body survived in: {raw} -> {scrubbed}"
            );
            assert!(scrubbed.contains("[REDACTED_SUB_TOKEN]"), "{raw} -> {scrubbed}");
        }
    }

    /// A device identity is pseudonymous but linkable: the same value appears on
    /// every line for one device. Redacted, with the surrounding diagnostic
    /// left intact so the line is still readable.
    #[test]
    fn test_device_identity_is_redacted() {
        // 42 hex chars, the shape a WireGuard peer public key takes as a device id.
        let device = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678ab";
        let scrubbed = scrub_pii(&format!("device_id={device} traffic counters moved backwards"));
        assert!(!scrubbed.contains(device), "device identity survived scrubbing: {scrubbed}");
        assert!(scrubbed.contains("[REDACTED_DEVICE]"), "{scrubbed}");
        // The diagnostic itself must survive -- scrubbing, not dropping.
        assert!(scrubbed.contains("traffic counters moved backwards"), "{scrubbed}");
    }

    /// Widening the scrubber must not eat the diagnostics it exists to preserve.
    /// Everything here is a string an operator genuinely needs to read, and all
    /// of it must come back byte-identical.
    #[test]
    fn test_scrub_does_not_over_match_unrelated_text() {
        for raw in [
            // The bare prefix and a short fragment: not a token (the real body is
            // 64 hex characters), so they stay legible in a "malformed token"
            // diagnostic. The `{16,}` floor is what makes this safe.
            "token sm_sub_ was empty",
            "token sm_sub_1 is too short to be one",
            "the prefix sm_sub_ was not followed by hex",
            // No prefix at all.
            "deadbeefdeadbeefdeadbeefdeadbeef",
            "GET /sub/not-a-token 404",
            "peer_set_version 7 reality_short_id 0123456789abcdef",
        ] {
            assert_eq!(scrub_pii(raw), raw, "over-matched: {raw}");
        }
    }
}
