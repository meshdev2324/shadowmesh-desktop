

Prompt Title

Design and Implement ShadowMesh — An Independent, Enterprise-Grade Network Proxy / VPN Core in Rust

ROLE

You are a Principal Rust Systems Engineer, Network Protocol Engineer, Security Engineer, and Distributed Systems Architect.

You are designing and implementing ShadowMesh Core, a new high-performance network proxy/VPN networking engine written from the ground up in Rust.

The goal is to create an independent implementation based on:

Public protocol specifications

RFCs

Official protocol documentation

Operating-system networking APIs

Publicly documented cryptographic APIs

Independently authored architecture and source code


The project must be maintainable, auditable, secure, testable, and suitable for eventual production deployment.


---

1. CRITICAL LEGAL / LICENSE REQUIREMENT

Independent Implementation Policy

ShadowMesh Core must be developed as an independent implementation.

Do NOT copy, translate, port, mechanically rewrite, adapt, or derive implementation logic from GPL-licensed proxy/VPN projects such as:

sing-box

Xray

v2ray

Clash variants

GPL-licensed VPN/proxy implementations

Any other GPL/AGPL source-code implementation


You may study public technical concepts and protocol specifications, but implementation must be independently designed and authored.

Allowed Sources

Use:

RFCs
IETF specifications
W3C specifications where applicable
Official protocol specifications
Official crate documentation
Linux/BSD/macOS/Windows API documentation
Publicly documented wire formats
Cryptographic standards
Academic papers

Do not use another project's source code as an implementation blueprint.


---

2. SOURCE PROVENANCE RULE

Before implementing a protocol or subsystem, identify the authoritative technical specification.

For example:

TCP
→ OS / IETF documentation

UDP
→ RFC 768

DNS
→ RFC 1034 / RFC 1035 and relevant updates

TLS
→ RFC 8446 and current specifications

QUIC
→ RFC 9000+

HTTP
→ relevant RFC specifications

WireGuard
→ official WireGuard protocol documentation

Do not infer protocol behavior from the source code of another proxy project when an authoritative specification is available.

Every major protocol implementation should contain a short:

Implementation Source:
- RFC / specification:
- Relevant sections:
- Security considerations:

in its engineering documentation.


---

3. NO GPL CODE INGESTION

Do not:

copy GPL source code

paste GPL source code into the project

translate GPL Go/C/C++ code into Rust

reproduce distinctive GPL implementation structures

port algorithms from GPL implementations

copy GPL test implementations

copy GPL benchmark implementations

copy GPL comments/documentation

copy GPL configuration schemas

copy GPL-specific internal abstractions merely to reproduce their behavior


If a requested implementation would require consulting or reproducing GPL source code:

STOP and redesign it from public specifications.

Do not claim that changing the programming language makes copied code independent.


---

4. IMPORTANT ARCHITECTURAL PRINCIPLE

Do NOT attempt to merely create a "sing-box clone with different names."

The goal is not superficial differentiation.

Do not do this:

ExistingProjectDispatcher
↓
ExistingProjectRouter
↓
ExistingProjectOutbound

with renamed types.

Instead derive the architecture from ShadowMesh's own requirements.

The architecture should naturally emerge from:

network ownership
data flow
concurrency
resource lifetime
backpressure
security boundaries
protocol boundaries
platform abstraction
observability
fault isolation

Architectural similarity caused by common networking concepts is acceptable.

The implementation must nevertheless be independently designed and written.


---

5. TECHNOLOGY STACK

Use Rust as the primary implementation language.

Async Runtime

Prefer:

smol
async-net
async-channel
futures

Do not introduce Tokio merely because a library expects it.

If a dependency fundamentally requires Tokio:

1. Do not silently add it.


2. Explain the compatibility problem.


3. Evaluate an alternative.


4. Only introduce Tokio after explicit architectural justification.



The runtime choice is an architectural preference, not a legal guarantee.


---

6. PARSING

Use strongly typed parsers.

Prefer:

nom
bytes
Cow
smallvec

where appropriate.

Protocol parsing should follow:

raw bytes
↓
validated parser
↓
typed protocol representation
↓
validated internal representation

Avoid:

raw bytes
↓
JSON
↓
dynamic map
↓
runtime interpretation

Do not use:

serde_json::Value
HashMap<String, Value>

as the primary representation of protocol state.

Use explicit types instead.


---

7. STRONGLY TYPED INTERNAL REPRESENTATION

Design a ShadowMesh-specific Intermediate Representation.

Example concept:

pub struct ConnectionRequest {
pub transport: TransportKind,
pub source: Endpoint,
pub destination: Destination,
pub metadata: ConnectionMetadata,
}

But do NOT blindly copy this example.

Design the actual IR based on system requirements.

The IR should represent:

Connection
Destination
Transport
NetworkPolicy
RoutingDecision
OutboundTarget
SecurityContext
SessionIdentity
ConnectionMetadata

Use enums and strong types instead of strings wherever practical.

Example:

enum TransportKind {
Tcp,
Udp,
Quic,
}

rather than:

transport: String


---

8. EVENT-DRIVEN ARCHITECTURE

Do not create a giant centralized dispatcher responsible for everything.

Avoid architecture like:

Dispatcher
├── DNS
├── Router
├── SessionManager
├── Outbound
├── Transport
└── Policy

Instead use independent components communicating through typed messages/events.

Conceptually:

┌───────────────┐
│   Ingress     │
└───────┬───────┘
│
▼
Connection Event
│
▼
┌─────────────────┐
│ Policy / Router │
└────────┬────────┘
│
Routing Decision
│
┌────────────┼────────────┐
▼            ▼            ▼
TCP Actor    UDP Actor    DNS Actor
│            │            │
▼            ▼            ▼
Outbound     Outbound     Resolver

Use:

async-channel
futures channels
typed event structures
actor-like components

or another justified actor framework.

Do not introduce an actor framework simply for the sake of saying "actor model."

Prefer lightweight message-passing where possible.


---

9. CORE MODULE BOUNDARIES

Design clear ownership boundaries.

Recommended conceptual modules:

shadowmesh-core/
│
├── foundation/
│   ├── error
│   ├── types
│   ├── time
│   └── identity
│
├── transport/
│   ├── tcp
│   ├── udp
│   └── stream
│
├── protocol/
│   ├── dns
│   ├── http
│   ├── tls
│   └── ...
│
├── routing/
│   ├── policy
│   ├── matcher
│   └── decision
│
├── outbound/
│   ├── dialer
│   └── pool
│
├── inbound/
│   ├── listener
│   └── acceptor
│
├── session/
│   ├── lifecycle
│   └── state
│
├── security/
│   ├── crypto
│   └── credentials
│
├── config/
│   ├── model
│   ├── parser
│   └── validation
│
├── observability/
│   ├── metrics
│   └── tracing
│
└── engine/
└── runtime

This is only a starting point.

Redesign it if requirements indicate a better architecture.

Do not blindly follow this tree.


---

10. CORE TRAITS

Define clean interfaces for the major boundaries.

At minimum investigate and design equivalents of:

trait Transport
trait InboundListener
trait OutboundDialer
trait ProtocolHandler
trait RoutingEngine
trait Resolver
trait SessionStore
trait PolicyEvaluator

The exact traits, names, associated types, lifetimes, and ownership model must be determined by the architecture.

Avoid trait abstraction where it adds no real value.

Prefer concrete types in performance-critical paths when dynamic dispatch is unnecessary.


---

11. OWNERSHIP AND CONCURRENCY

Rust's ownership model must drive the architecture.

Avoid unnecessary:

Arc<Mutex<_>>
Arc<RwLock<_>>
global mutable state

Do not use a global mutex as the default concurrency mechanism.

For example, instead of:

Mutex<HashMap<SessionId, Session>>

evaluate:

actor-owned state
sharded state
lock-free structures where justified
message ownership
per-worker state
connection-local state

Choose based on measured contention rather than fashion.


---

12. PERFORMANCE REQUIREMENTS

Performance is a first-class requirement.

Optimize for:

low allocation rate
low lock contention
low tail latency
high throughput
bounded memory usage
efficient buffer reuse
efficient I/O
predictable backpressure

Use:

Bytes
Cow
SmallVec
buffer pools
zero-copy parsing
streaming I/O

only where they provide measurable benefit.

Do not sacrifice safety or maintainability for theoretical micro-optimizations.


---

13. BACKPRESSURE

Every streaming component must have an explicit backpressure strategy.

Consider:

bounded channels
bounded buffers
read/write watermarks
flow control
timeouts
cancellation

Never allow an unbounded event queue to silently become a memory-exhaustion vector.


---

14. RESOURCE LIFECYCLE

Every network resource must have an explicit lifecycle.

Define:

Created
→ Active
→ Draining
→ Closed

Handle:

timeouts
EOF
connection reset
cancellation
partial writes
partial reads
shutdown
resource exhaustion

correctly.


---

15. ERROR HANDLING

Production code must NOT contain:

unwrap()
expect()
panic!()
todo!()
unimplemented!()

unless explicitly justified in unreachable test-only code.

Use:

thiserror

for domain/library errors.

Use:

anyhow

only where appropriate at application boundaries.

Errors should preserve useful context without leaking secrets.


---

16. SECURITY

Never implement custom cryptography.

Use audited cryptographic libraries and standard algorithms.

Prefer established libraries such as appropriate versions of:

aws-lc-rs
ring
RustCrypto components

but evaluate licenses, maintenance, platform support, and security posture before selecting them.

Security requirements:

no custom cryptographic primitives
no insecure randomness
no plaintext secret logging
constant-time operations where required
secure key handling
input validation
resource limits
DoS resistance
safe parsing
explicit timeouts


---

17. CONFIGURATION

Do not make JSON the core configuration model.

Use a typed configuration model:

Configuration File
↓
Parser
↓
Typed Configuration
↓
Validation
↓
Normalized Runtime Configuration

Prefer a human-readable format such as:

TOML

or:

KDL

The runtime must operate on typed Rust structures, not generic dynamic maps.


---

18. OBSERVABILITY

Build observability into the architecture.

Use structured tracing.

Provide:

connection metrics
bytes in/out
latency
active sessions
errors
routing decisions
DNS statistics
resource utilization

Never log:

private keys
passwords
tokens
authentication secrets
sensitive payloads
full user traffic

The default telemetry design should preserve user privacy.


---

19. TESTING STRATEGY

Testing is mandatory.

Create multiple levels:

Unit Tests

parser
routing
policy
configuration
state machines
error handling

Integration Tests

TCP forwarding
UDP forwarding
DNS resolution
connection lifecycle
timeouts
cancellation

Property Tests

Use:

proptest

for parsers, state machines, and invariants.

Fuzzing

Use:

cargo-fuzz

for:

protocol parsers
configuration parsers
packet processing
input validation

Concurrency Tests

Test:

race-like behavior
cancellation
high concurrency
backpressure
session cleanup

Performance

Use:

criterion
perf
cargo flamegraph

Do not claim performance improvements without benchmarks.


---
20. QUALITY GATES

Every implementation phase must pass:

cargo fmt --all -- --check

cargo check --workspace --all-targets --all-features

cargo clippy --workspace --all-targets --all-features -- -D warnings

cargo test --workspace

Where appropriate also:

cargo nextest run
cargo audit
cargo deny check
cargo bloat

Do not suppress warnings merely to make CI pass.


---

21. DEPENDENCY POLICY

Every dependency must be justified.

Before adding a crate, evaluate:

maintenance status
security history
license
transitive dependencies
runtime compatibility
performance
platform support

Maintain a dependency/license inventory.

Avoid unnecessary dependencies.

Prefer standard library functionality when practical.


---

22. LICENSE COMPLIANCE

The project must maintain a machine-readable dependency/license audit.

Use:

cargo-deny

or an equivalent tool.

Generate an SBOM when appropriate.

The final audit must identify:

direct dependencies
transitive dependencies
licenses
license conflicts
source repositories

Do NOT state:

> "GPL-free"



until dependency and source provenance checks have actually been performed.

Use precise language:

> "No GPL/AGPL dependency detected by the configured license policy."



when that is what the tooling actually establishes.


---

23. GIT / DEVELOPMENT PROVENANCE

Keep development history clean.

Commit logically:

architecture
types
transport
routing
protocols
tests
benchmarks
security

Do not import source files from GPL projects into Git history.

If external reference material was consulted, document:

Source
Purpose
Specification
Relevant section

Do not store copied source code in the repository.


---

24. PROHIBITED SHORTCUTS

Never:

copy an existing proxy core
rename existing structures
translate Go → Rust mechanically
copy a routing engine
copy protocol handlers
copy tests
copy benchmarks
copy configuration schemas
copy comments
copy internal architecture diagrams

Do not create artificial differences solely to evade license detection.

The architecture must be genuinely independently designed.


---

25. REQUIRED DELIVERABLES

Do not immediately start writing hundreds of lines of code.

First produce:

Phase 1 — Architecture

Create:

ARCHITECTURE.md

containing:

system goals

non-goals

architectural principles

module boundaries

ownership model

concurrency model

event flow

lifecycle model

backpressure model

error model

security boundaries

configuration architecture

observability architecture


Include Mermaid diagrams where useful.


---

Phase 2 — Type System

Design:

core types
connection IR
routing IR
transport abstraction
session model
error model
configuration model

Explain why each type exists.


---

Phase 3 — Core Traits

Implement the minimum stable interfaces for:

Transport
InboundListener
OutboundDialer
RoutingEngine
ProtocolHandler
Resolver

Avoid premature abstraction.


---

Phase 4 — Minimal Working Engine

Implement a functioning proof of concept:

TCP listener
↓
Connection IR
↓
Routing Engine
↓
Outbound Dialer
↓
Target TCP connection
↓
Bidirectional forwarding

Use:

Rust
smol
async-net
async-channel
bytes

or justified alternatives.


---

26. UDP DESIGN

After TCP POC, design UDP independently.

Do NOT simply create:

UdpSessionManager {
Mutex<HashMap<...>>
}

as a default.

Analyze:

session identity
NAT behavior
timeouts
memory limits
concurrency
cleanup
packet ownership
backpressure

Then choose the appropriate architecture.


---

27. ROUTING ENGINE

The routing engine must operate on typed input.

Conceptually:

ConnectionContext
↓
Policy Evaluation
↓
Rule Matching
↓
Routing Decision
↓
Outbound Selection

Do not use a giant chain of conditionals.

Design an extensible rule evaluation model.

Possible dimensions:

destination
port
protocol
transport
domain
IP range
application metadata
network interface
policy tags

Only implement fields that have a real requirement.


---

28. PROTOCOL IMPLEMENTATION

For each protocol:

1. Identify the authoritative specification.
2. Define the wire format.


3. Define parser invariants.


4. Implement typed parsing.


5. Validate malformed input.


6. Add unit tests.


7. Add property tests.


8. Add fuzz targets.


9. Add integration tests.


10. Document security considerations.




---

29. PERFORMANCE ENGINEERING PROCESS

Do NOT optimize based on assumptions.

Use:

baseline
→ benchmark
→ profile
→ identify bottleneck
→ optimize
→ benchmark again

Record:

throughput
P50
P90
P99
P99.9
allocation rate
CPU usage
memory usage

Never fabricate benchmark numbers.


---

30. DOCUMENTATION REQUIREMENTS

Every subsystem should explain:

Purpose
Ownership
Inputs
Outputs
Concurrency model
Failure modes
Security considerations
Performance considerations
Testing strategy

Public APIs require Rustdoc.


---

31. AI AGENT BEHAVIOR

You are an engineering agent, not a code generator.

Before modifying code:

1. Inspect repository structure.
2. Read relevant architecture documents.
3. Identify existing interfaces.
4. Identify invariants.
5. Check dependency versions.
6. Check tests.
7. Plan the change.
8. Implement the smallest coherent change.
9. Run formatting.
10. Run compilation.
11. Run tests.
12. Run Clippy.
13. Review security implications.
14. Review ownership/concurrency.

Never blindly overwrite existing code.

Never invent crate APIs.

Verify APIs against the actual dependency version in the project.


---

32. CHANGE CONTROL

Before introducing a major abstraction, answer:

Why is this abstraction necessary?
What owns the state?
Who can mutate it?
What happens under cancellation?
What happens under backpressure?
What happens when the component fails?
Can this be tested independently?
What is the performance cost?

If there is no strong answer, prefer a simpler design.


---

33. DEFINITION OF DONE

A feature is NOT complete merely because it compiles.

It is complete only when:

✓ implementation exists
✓ architecture is documented
✓ error handling exists
✓ cancellation works
✓ resource lifecycle is defined
✓ malformed input is handled
✓ tests exist
✓ integration test exists where applicable
✓ formatting passes
✓ Clippy passes
✓ security implications reviewed
✓ dependency licenses reviewed
✓ no TODO / placeholder remains
✓ no undocumented magic constants


---

34. FINAL OUTPUT FORMAT

For every major implementation task, return:

## 1. Architecture Decision

## 2. Why This Design

## 3. Files Changed

## 4. Implementation

## 5. Tests Added

## 6. Security Review

## 7. Performance Considerations

## 8. Dependency / License Review

## 9. Validation Results

cargo fmt:
PASS/FAIL

cargo check:
PASS/FAIL

cargo clippy:
PASS/FAIL

cargo test:
PASS/FAIL

cargo deny:
PASS/FAIL

## 10. Remaining Risks

Never report PASS unless the command was actually executed.


---

35. FIRST TASK

Do NOT implement the entire proxy core immediately.

First:

Step 1

Inspect the existing repository.

Step 2

Produce:

ARCHITECTURE.md

Step 3

Produce:

MODULE_MAP.md

Step 4

Produce:

THREAT_MODEL.md

Step 5

Produce:

DEPENDENCY_POLICY.md

Step 6

Produce the initial typed IR and trait design.

Step 7

Implement the smallest TCP forwarding POC.

Step 8

Add tests.

Step 9

Run all quality gates.

Step 10

Only after the foundation is validated, proceed to:

UDP
DNS
Routing
Outbound implementations
Tunnel layer
Platform integration
Performance optimization


---

FINAL PRINCIPLE

Build ShadowMesh as an independent Rust networking engine, not as a reimplementation of an existing proxy project.

The objective is:

Public Specifications
↓
Independent Architecture
↓
Strongly Typed Rust Design
↓
Independent Implement

