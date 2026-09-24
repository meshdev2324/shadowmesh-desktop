# ShadowMesh Core Threat Model

## Assets
- User Data (Payloads)
- User Privacy (Source/Destination Metadata)
- Cryptographic Keys
- System Resources (CPU/Memory)

## Threats
- **Metadata Leakage**: DNS leaks or unencrypted headers revealing user activity.
- **Traffic Fingerprinting**: Pattern analysis of packet sizes and timing.
- **Unauthorized Access**: Exploiting flaws in inbound authentication.
- **Denial of Service (DoS)**: Resource exhaustion via malformed packets or many connections.
- **Remote Code Execution (RCE)**: Buffer overflows or logic errors in protocol parsers.

## Mitigations
- **DnsLeakProtection**: Enforced DNS routing via `ShadowRouter`.
- **DPI Evasion**: Fragmentation and padding in `fragment` module.
- **Secure Parsing**: Using `nom` for structured, bounds-checked parsing.
- **Resource Limits**: Bounded queues and connection timeouts.
- **Audited Crypto**: Use `ring` or `aws-lc-rs` for all cryptographic operations.
