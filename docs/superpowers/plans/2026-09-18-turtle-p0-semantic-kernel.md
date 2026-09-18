# Turtle P0 Semantic Kernel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Turtle P0: a deterministic, fail-closed policy evaluator, conservative attenuation checker, simulated shared-domain budgets, canonical digests, enforcement-plan representation, CLI, independent reference evaluator, fixtures, ADRs, and reproducible evidence — with no containment, broker, daemon, or production-authorization claim.

**Architecture:** A Cargo workspace with a small trusted semantic core (`crates/turtle-policy`) and a thin owner CLI (`crates/turtle-cli`). YAML is converted by a strict event walker into JSON, validated against an embedded JSON Schema with no network retrieval, then compiled into correlated grant clauses. Evaluation intersects administrator, owner, and ancestor layers with default deny and deny precedence. An independent crate under `tests/reference` reimplements the decision predicate without importing the production `evaluate` function. Shared budgets use an in-memory mutex-serialized ledger suitable for concurrency tests; occupancy fields are parsed and labeled, never reserved as cumulative effect units.

**Tech Stack:** Rust stable 1.98.1, Cargo workspace, `saphyr-parser` 0.0.12, `serde`/`serde_json`, `jsonschema` 0.56.0 (offline retriever), `sha2` 0.10.9, `clap` 4.6.7, `thiserror` 2.0.20, `proptest` 1.11.0, `hex` 0.4.3.

## Inspection findings (authoritative starting state)

- Workspace `D:\syberlabs\turtle` contained only `SyberLabs-Turtle-System-Design-Spec-v0.1.md`. No `AGENTS.md`, no existing crates, no tests, no git repository.
- Parent `D:\syberlabs\.git` exists as an empty directory (no `HEAD`). It is not a usable Turtle repository. P0 is initialized as a new git repository at `D:\syberlabs\turtle`.
- Design spec v0.1 dated 18 September 2026 is treated as authoritative. Conflicts with the implementation brief are documented below rather than silently changed.
- Host is Windows. P0 is a pure semantic library and does not require Linux sandbox features.

## Global Constraints

- Language: Rust stable (`rust-toolchain.toml` pins `1.98.1`). Edition 2021.
- Workspace crates: `crates/turtle-policy`, `crates/turtle-cli`. Reference crate: `tests/reference/turtle-policy-ref`.
- Schema: `schemas/turtle-policy-v0alpha1.schema.json`.
- Serialization: strict YAML frontend → validated JSON → RFC 8785-compatible canonical bytes for digest inputs.
- Hash: SHA-256 with domain-separated prefixes. Policy digest prefix is `turtle-policy-v0alpha1\n`.
- Errors: typed internal `PolicyError`; stable public `ReasonCode`.
- No `unsafe`. No network during parse/evaluate/canonicalize. No regex predicates. No embedded scripting. No custom cryptography. No database.
- In-memory transactional budget ledger is the P0 accounting model. Limitation must be explicit in docs and the enforcement plan.
- Deny unknown fields, unsupported constraints, malformed values, missing trusted context, and ambiguous identities.
- Adapter validity and approval validity are trusted evaluator inputs and default to unsatisfied (`false`).
- `EffectRequest` contains no caller-authoritative subject, role, or credential secret.
- P0 claim ceiling, copied verbatim: “Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.”
- P0 must never emit enforcement status `enforced`.
- Pin crate versions with `=` in workspace `Cargo.toml`.
- Commits are required after each verified task. Do not weaken a security invariant to pass a test.

## Spec conflicts and documented adaptations

| Spec / brief point | P0 handling |
|---|---|
| Manifest example uses singular `action` / `resource` | Accept exactly one of singular or plural; canonicalize to sets. Reject if both are present. |
| Required public model uses `ActionSet` / `ResourceSet` | Internal and public types are sets. YAML sugar is the only adaptation. |
| Spec §6.2 includes `AdapterValid` and `ApprovalValid` | Implemented as trusted inputs defaulting to unsatisfied. The brief’s `obligations_are_satisfied` is the same gate when the obligation is approval. |
| Spec compilation steps 8–9 create a sandbox | Out of P0. The compiler stops at a machine-readable enforcement plan. |
| Occupancy limits (`memoryMiB`, `pids`, `cpuMillisPerSecond`) | Parsed and explained. Not reserved by the P0 cumulative budget ledger. |
| `turtle run`, daemon APIs, MCP, adapters | Out of P0. CLI implements only `policy check`, `policy explain`, `policy diff`. |
| Absolute expiry plus monotonic timer | P0 lifetime is integer `maxSeconds` plus optional RFC 3339 `expiresAt`. Evaluation uses trusted `now` from context. |

## Chosen repository / file structure

```
D:\syberlabs\turtle\
  Cargo.toml
  Cargo.lock
  rust-toolchain.toml
  rustfmt.toml
  clippy.toml
  .gitignore
  LICENSE
  README.md
  AGENTS.md
  schemas/turtle-policy-v0alpha1.schema.json
  crates/turtle-policy/Cargo.toml
  crates/turtle-policy/src/lib.rs
  crates/turtle-policy/src/reason.rs
  crates/turtle-policy/src/error.rs
  crates/turtle-policy/src/ids.rs
  crates/turtle-policy/src/limits.rs
  crates/turtle-policy/src/digest.rs
  crates/turtle-policy/src/jcs.rs
  crates/turtle-policy/src/yaml.rs
  crates/turtle-policy/src/schema.rs
  crates/turtle-policy/src/path.rs
  crates/turtle-policy/src/constraints.rs
  crates/turtle-policy/src/manifest.rs
  crates/turtle-policy/src/grant.rs
  crates/turtle-policy/src/evaluate.rs
  crates/turtle-policy/src/attenuate.rs
  crates/turtle-policy/src/budget.rs
  crates/turtle-policy/src/plan.rs
  crates/turtle-policy/src/diff.rs
  crates/turtle-policy/src/actions.rs
  crates/turtle-policy/tests/eval_invariants.rs
  crates/turtle-policy/tests/attenuation.rs
  crates/turtle-policy/tests/budgets.rs
  crates/turtle-policy/tests/canonical.rs
  crates/turtle-policy/tests/malformed.rs
  crates/turtle-cli/Cargo.toml
  crates/turtle-cli/src/main.rs
  crates/turtle-cli/tests/cli.rs
  tests/reference/turtle-policy-ref/Cargo.toml
  tests/reference/turtle-policy-ref/src/lib.rs
  tests/reference/independence.rs
  tests/reference/differential.rs
  tests/adversarial/cross_product.rs
  tests/adversarial/identity.rs
  tests/adversarial/paths.rs
  tests/fixtures/valid/read-only-repo-worker.yaml
  tests/fixtures/valid/attenuated-child.yaml
  tests/fixtures/valid/all-supported-constraints.yaml
  tests/fixtures/invalid/cross-product-request.json
  tests/fixtures/invalid/child-widens-recipients.yaml
  tests/fixtures/malformed/duplicate-keys.yaml
  tests/fixtures/malformed/alias.yaml
  tests/fixtures/malformed/merge-key.yaml
  tests/fixtures/malformed/custom-tag.yaml
  tests/fixtures/malformed/unknown-field.yaml
  tests/fixtures/malformed/unknown-action.yaml
  tests/fixtures/malformed/path-traversal.yaml
  tests/fixtures/malformed/absolute-path.yaml
  tests/fixtures/malformed/nonfinite.yaml
  tests/fixtures/diff/narrow.yaml
  tests/fixtures/diff/widen.yaml
  tests/fixtures/diff/old.yaml
  docs/authority-semantics.md
  docs/manifest-schema.md
  docs/evidence/p0-semantic-kernel.md
  docs/decisions/0001-correlated-clauses.md
  docs/decisions/0002-one-parent-clause-subsumption.md
  docs/decisions/0003-stateful-grants.md
  docs/decisions/0004-fail-closed-unsupported.md
  docs/decisions/0005-independent-reference-evaluator.md
  docs/superpowers/plans/2026-09-18-turtle-p0-semantic-kernel.md
  SyberLabs-Turtle-System-Design-Spec-v0.1.md
```

## Public interfaces (locked names)

Names match the implementation brief. Additional types are required to make evaluation well-defined; they do not replace the required types.

```rust
pub const API_VERSION: &str = "turtle.syberlabs.space/v0alpha1";
pub const CLAIM_CEILING: &str =
    "Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.";

pub struct TurtlePolicy { /* validated owner request; fields private except via accessors */ }

pub struct EffectiveGrant {
    pub identity: TurtleIdentity,
    pub clauses: Vec<GrantClause>,
    pub limits: LimitSet,
    pub delegation: DelegationPolicy,
    pub lifetime: Lifetime,
    pub revisions: RevisionVector,
    pub disclosure: DisclosureEnvelope,
}

pub struct GrantClause {
    pub id: ClauseId,
    pub effect: ClauseEffect, // Permit | Deny
    pub actions: ActionSet,
    pub resources: ResourceSet,
    pub credential: Option<CredentialBindingId>,
    pub recipients: RecipientSet,
    pub constraints: ConstraintSet,
    pub obligations: ObligationSet,
}

pub struct EffectRequest {
    pub operation_key: OperationKey,
    pub action: ActionId,
    pub resource: ResourceId,
    pub arguments_digest: Digest,
    pub recipient: RecipientId,
    pub preconditions: Preconditions,
}

pub struct TrustedContext {
    pub subject: TurtleIdentity,
    pub turtle_active: bool,
    pub ancestors_active: bool,
    pub adapter_valid: bool,          // default false
    pub approval_valid: bool,         // default false
    pub now: Timestamp,
    pub layers: Vec<EffectiveGrant>,  // admin, owner, ancestors; intersection
}

pub enum Decision {
    Allow(DecisionEvidence),
    Deny(Denial),
}

pub struct Denial {
    pub code: ReasonCode,
    pub constraint_id: Option<String>,
    pub explanation: String,
    pub retryable: bool,
}

pub fn parse_manifest(bytes: &[u8]) -> Result<TurtlePolicy, PolicyError>;
pub fn compile(policy: &TurtlePolicy, identity: TurtleIdentity) -> Result<EffectiveGrant, PolicyError>;
pub fn evaluate(grant: &EffectiveGrant, request: &EffectRequest, ctx: &TrustedContext) -> Decision;
pub fn evaluate_layers(ctx: &TrustedContext, request: &EffectRequest, budget: Option<&BudgetLedger>) -> Decision;
pub fn check_attenuation(parent: &EffectiveGrant, child: &EffectiveGrant) -> Result<(), Denial>;
pub fn policy_digest(policy: &TurtlePolicy) -> Digest;
pub fn enforcement_plan(policy: &TurtlePolicy) -> EnforcementPlan;
pub fn diff_authority(old: &TurtlePolicy, new: &TurtlePolicy) -> AuthorityDiff;
```

`evaluate` / `evaluate_layers` must ignore any subject-like fields if a future request accidentally grows them. Tests inject a forged identity only in the request JSON fixture and confirm it cannot change the decision.

Eligibility implemented exactly as:

```text
eligible =
    turtle_is_active
    AND all_ancestors_are_active
    AND adapter_valid
    AND every_policy_layer_allows_the_complete_request
    AND no_matching_deny_exists
    AND disclosure_is_compatible
    AND obligations_are_satisfied
    AND applicable_budget_can_be_reserved
```

A complete allow match requires one clause whose correlated tuple contains the request action, resource, and recipient, whose constraints accept the preconditions, and whose credential binding is the clause’s own binding (not mixed with another clause).

## Complexity limits (reject, never truncate)

| Limit | Value |
|---|---|
| Manifest size | 262144 bytes |
| Grant clauses | 128 |
| Resource IDs per clause | 64 |
| Constraint fields per clause | 32 |
| Path roots | 64 |
| Input nesting | 16 |
| Maximum delegation depth | 4 |

## Registered v0 actions

`inference.generate`, `github.repository.read`, `github.repository.write`, `turtle.delegate`, `artifact.export`. Unknown action IDs are `E_UNKNOWN_ACTION` at compile and evaluate.

## Registered constraint fields

| Field | Form |
|---|---|
| `maxInputBytes` | numeric maximum |
| `maxOutputTokens` | numeric maximum |
| `maxResponseBytes` | numeric maximum |
| `minInputBytes` | numeric minimum |
| `pathSubtrees` | path subtree list |
| `approval` | required approval (`none` or `exact`) |
| `exactModel` | exact field |

Unknown constraint field names fail closed (`E_UNSUPPORTED_ENFORCEMENT` at compile).

## Digest

Canonical JSON is RFC 8785-compatible for the P0 JSON subset: objects, arrays, strings, booleans, null, and integers in `±(2^53-1)`. Floats are rejected at parse time, so ECMAScript NumberToString for non-integers is unused. Object keys are sorted by UTF-16 code units of the raw property name. Strings use JSON escaping. Integers are decimal with no exponent.

```text
digest = SHA-256( "turtle-policy-v0alpha1\n" || jcs(canonical_policy_json) )
```

Displayed as lowercase hex.

## Incremental commits

Each task ends with one commit. Messages:

1. `chore: initialize Turtle workspace and P0 plan`
2. `feat: add stable reason codes`
3. `feat: parse YAML with fail-closed strictness`
4. `feat: validate turtle-policy-v0alpha1 manifests`
5. `feat: canonicalize policy JSON and compute digests`
6. `feat: compile correlated grant clauses`
7. `feat: evaluate policies with default deny`
8. `feat: check conservative parent-to-child attenuation`
9. `feat: reserve simulated shared-domain budgets`
10. `feat: emit P0 enforcement plans without enforced status`
11. `feat: classify semantic authority diffs`
12. `feat: add turtle policy check/explain/diff CLI`
13. `test: add independent reference evaluator and properties`
14. `docs: record P0 ADRs, semantics, and evidence`

---

### Task 1: Workspace, toolchain, and reason codes

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, `.gitignore`, `LICENSE`, `AGENTS.md`, `crates/turtle-policy/Cargo.toml`, `crates/turtle-policy/src/lib.rs`, `crates/turtle-policy/src/reason.rs`, `crates/turtle-policy/src/error.rs`, `crates/turtle-policy/tests/reason_codes.rs`

**Interfaces:**
- Consumes: nothing
- Produces: `ReasonCode`, `Denial`, `PolicyError`, `Result` alias

- [ ] **Step 1: Write the failing test**

Create `crates/turtle-policy/tests/reason_codes.rs`:

```rust
use turtle_policy::reason::ReasonCode;

const REQUIRED: &[&str] = &[
    "E_SCHEMA",
    "E_UNKNOWN_ACTION",
    "E_IDENTITY",
    "E_NOT_ACTIVE",
    "E_ANCESTOR_REVOKED",
    "E_EXPIRED",
    "E_POLICY_DENY",
    "E_RESOURCE_OUTSIDE_GRANT",
    "E_DISCLOSURE",
    "E_APPROVAL_REQUIRED",
    "E_APPROVAL_STALE",
    "E_BUDGET",
    "E_DELEGATION_WIDENS",
    "E_DEPTH",
    "E_UNSUPPORTED_ENFORCEMENT",
    "E_DRIVER_DRIFT",
    "E_PRECONDITION",
    "E_OPERATION_CONFLICT",
    "E_OUTCOME_UNKNOWN",
    "E_AUDIT_UNAVAILABLE",
];

#[test]
fn every_stable_reason_code_round_trips() {
    for code in REQUIRED {
        let parsed: ReasonCode = code.parse().expect(code);
        assert_eq!(parsed.to_string(), *code);
        let json = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, format!("\"{code}\""));
        let back: ReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, parsed);
    }
}

#[test]
fn unknown_reason_code_is_rejected() {
    assert!("E_MADE_UP".parse::<ReasonCode>().is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p turtle-policy --test reason_codes`

Expected: compile fail, `turtle-policy` / `ReasonCode` not found.

- [ ] **Step 3: Write minimal implementation**

Workspace `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/turtle-policy",
    "crates/turtle-cli",
    "tests/reference/turtle-policy-ref",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
rust-version = "1.85"

[workspace.dependencies]
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = "=1.0.151"
saphyr-parser = "=0.0.12"
jsonschema = { version = "=0.56.0", default-features = false, features = ["resolve-file"] }
sha2 = "=0.10.9"
hex = "=0.4.3"
thiserror = "=2.0.20"
clap = { version = "=4.6.7", features = ["derive"] }
proptest = "=1.11.0"
turtle-policy = { path = "crates/turtle-policy" }
```

`jsonschema` default features must not include network retrieval. If `resolve-file` still allows HTTP, disable all resolve features and embed the schema bytes.

Implement `ReasonCode` as a closed `enum` with `Display`, `FromStr`, `Serialize`, `Deserialize`. `Denial` matches the required public struct. `PolicyError` is internal (`thiserror`) and maps schema/parse failures to `ReasonCode::ESchema`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p turtle-policy --test reason_codes`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml rust-toolchain.toml rustfmt.toml clippy.toml .gitignore LICENSE AGENTS.md crates/turtle-policy docs/superpowers/plans/2026-09-18-turtle-p0-semantic-kernel.md SyberLabs-Turtle-System-Design-Spec-v0.1.md
git commit -m "feat: add stable reason codes"
```

Task 1 commit message in the list above is split: first commit is workspace init if git init happens separately; reason codes may share the init commit if that is the first compilable unit. Prefer two commits: `chore: initialize Turtle workspace and P0 plan` then `feat: add stable reason codes`.

---

### Task 2: Strict YAML frontend

**Files:**
- Create: `crates/turtle-policy/src/yaml.rs`, `crates/turtle-policy/src/limits.rs`, `crates/turtle-policy/tests/yaml_strict.rs`, malformed fixtures listed above

**Interfaces:**
- Consumes: `PolicyError`, size limits
- Produces: `pub fn yaml_to_json(bytes: &[u8]) -> Result<serde_json::Value, PolicyError>`

- [ ] **Step 1: Write the failing tests**

```rust
use turtle_policy::yaml::yaml_to_json;

#[test]
fn duplicate_keys_are_rejected() {
    let err = yaml_to_json(b"a: 1\na: 2\n").unwrap_err();
    assert_eq!(err.reason_code(), turtle_policy::ReasonCode::ESchema);
}

#[test]
fn aliases_are_rejected() {
    let src = "x: &a 1\ny: *a\n";
    let err = yaml_to_json(src.as_bytes()).unwrap_err();
    assert_eq!(err.reason_code(), turtle_policy::ReasonCode::ESchema);
}

#[test]
fn merge_keys_are_rejected() {
    let src = "a: &id {x: 1}\nb: {<<: *id}\n";
    assert!(yaml_to_json(src.as_bytes()).is_err());
}

#[test]
fn custom_tags_are_rejected() {
    let src = "x: !foo 1\n";
    assert!(yaml_to_json(src.as_bytes()).is_err());
}

#[test]
fn yes_is_not_coerced_to_bool() {
    let src = "x: yes\n";
    let err = yaml_to_json(src.as_bytes()).unwrap_err();
    assert_eq!(err.reason_code(), turtle_policy::ReasonCode::ESchema);
}

#[test]
fn nonfinite_numbers_are_rejected() {
    assert!(yaml_to_json(b"x: .inf\n").is_err());
    assert!(yaml_to_json(b"x: .nan\n").is_err());
}

#[test]
fn nesting_beyond_16_is_rejected() {
    let mut s = String::new();
    for _ in 0..17 { s.push('{'); s.push_str("a: "); }
    s.push('1');
    for _ in 0..17 { s.push('}'); }
    assert!(yaml_to_json(s.as_bytes()).is_err());
}

#[test]
fn oversized_manifest_is_rejected() {
    let too_big = vec![b'a'; 262145];
    assert!(yaml_to_json(&too_big).is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p turtle-policy --test yaml_strict`

Expected: FAIL, `yaml` module missing.

- [ ] **Step 3: Write minimal implementation**

Walk `saphyr_parser::Parser` events:

1. Reject if `bytes.len() > 262144`.
2. Reject `Event::Alias`.
3. Reject any scalar/collection tag other than empty / `tag:yaml.org,2002:str` / `tag:yaml.org,2002:int` / `tag:yaml.org,2002:bool` / `tag:yaml.org,2002:null`.
4. Reject mapping key `<<`.
5. Reject duplicate keys using a `HashSet` at each mapping.
6. Scalars: `true`/`false` (lowercase only) → bool; `null`/`~` → null; integers matching `0|-?[1-9][0-9]*` in `i64` and inside `±(2^53-1)` → number; quoted strings stay strings; `yes`/`no`/`on`/`off`/`NO`/`1.0`/`0x10`/`+1`/`01` fail closed.
7. Track depth; reject `> 16`.
8. Single document only; reject empty streams and multiple documents.

- [ ] **Step 4: Run tests**

Run: `cargo test -p turtle-policy --test yaml_strict`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/turtle-policy tests/fixtures/malformed
git commit -m "feat: parse YAML with fail-closed strictness"
```

---

### Task 3: JSON Schema and TurtlePolicy compile

**Files:**
- Create: `schemas/turtle-policy-v0alpha1.schema.json`, `crates/turtle-policy/src/schema.rs`, `crates/turtle-policy/src/manifest.rs`, `crates/turtle-policy/src/ids.rs`, `crates/turtle-policy/src/path.rs`, `crates/turtle-policy/src/constraints.rs`, `crates/turtle-policy/src/actions.rs`, `crates/turtle-policy/src/grant.rs`, `tests/fixtures/valid/read-only-repo-worker.yaml`, `crates/turtle-policy/tests/manifest.rs`

**Interfaces:**
- Consumes: `yaml_to_json`
- Produces: `parse_manifest`, `TurtlePolicy`, `compile`

Schema rules (`additionalProperties: false` everywhere):

- `apiVersion` const `turtle.syberlabs.space/v0alpha1`
- `kind` const `TurtlePolicy`
- `metadata.name` ASCII `^[a-z][a-z0-9-]{0,62}$`
- `spec.profile` const `strict-local-v1`
- required: `profile`, `lifetime.maxSeconds`, `filesystem`, `network`, `data`, `credentials`, `grants`, `limits`, `delegation`, `audit`
- grant: `id`, and exactly one of `action` or `actions`, exactly one of `resource` or `resources`, `recipients` array, optional `credential`, optional `effect` (`permit` default | `deny`), optional `constraints`, optional `obligations`
- IDs: `^[a-z][a-z0-9._-]{0,127}$` for actions; resources/credentials/recipients `^[a-z0-9][a-z0-9:._-]{0,127}$`
- `maxSeconds` integer 1..=86400
- `delegation.maxDepth` integer 0..=4
- `network.mode` const `broker-only`; `rawDestinations` maxItems 0
- `credentials.export` const `false`
- path entries: relative, no `..`, no `\`, no NUL, no leading `/`

`schema.rs` loads the schema from `include_str!` and builds a validator with a retriever that returns an error for any URI, so evaluation cannot depend on the network.

- [ ] **Step 1: Failing tests** in `crates/turtle-policy/tests/manifest.rs`:

```rust
#[test]
fn minimal_worker_parses() {
    let bytes = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");
    let policy = turtle_policy::parse_manifest(bytes).unwrap();
    assert_eq!(policy.name(), "rise-worker");
    assert_eq!(policy.clauses().len(), 2);
}

#[test]
fn unknown_field_is_e_schema() {
    let src = std::fs::read("tests/fixtures/malformed/unknown-field.yaml").unwrap();
    let err = turtle_policy::parse_manifest(&src).unwrap_err();
    assert_eq!(err.reason_code(), turtle_policy::ReasonCode::ESchema);
}

#[test]
fn unknown_action_is_e_unknown_action() {
    let err = turtle_policy::parse_manifest(
        include_bytes!("../../../tests/fixtures/malformed/unknown-action.yaml"),
    )
    .unwrap_err();
    assert_eq!(err.reason_code(), turtle_policy::ReasonCode::EUnknownAction);
}

#[test]
fn path_traversal_rejected() {
    let err = turtle_policy::parse_manifest(
        include_bytes!("../../../tests/fixtures/malformed/path-traversal.yaml"),
    )
    .unwrap_err();
    assert_eq!(err.reason_code(), turtle_policy::ReasonCode::ESchema);
}

#[test]
fn absolute_path_rejected() {
    let err = turtle_policy::parse_manifest(
        include_bytes!("../../../tests/fixtures/malformed/absolute-path.yaml"),
    )
    .unwrap_err();
    assert_eq!(err.reason_code(), turtle_policy::ReasonCode::ESchema);
}

#[test]
fn excessive_clauses_rejected() {
    // build 129 grant clauses programmatically
}
```

Fixture `read-only-repo-worker.yaml` is the spec §9.1 example with synthetic registry IDs only (no secrets). `writableSubtrees: []` and `externalMutations: 0`. Keep inference + github read as in the spec example because that is a valid read-oriented worker; mutation grants are absent.

- [ ] **Step 2: Run and confirm fail**

Run: `cargo test -p turtle-policy --test manifest`

- [ ] **Step 3: Implement parse + compile**

`parse_manifest`: yaml_to_json → schema validate → semantic checks (registered actions, path normalization, clause cardinality, no overlapping writable roots, credential labels exist, recipient IDs exist, maxDepth ≤ 4, no negative quantities).

`compile` produces `EffectiveGrant` with correlated clauses. Singular action/resource become one-element sets.

Path normalization (`path.rs`): split on `/`, reject `.` after normalization only if it remains as a segment that is empty, `.`, or `..`; reject Windows prefixes and absolute paths. `/workspace/repo/src2` is not a child of `/workspace/repo/src` because comparison is segment-wise: `["workspace","repo","src2"]` vs `["workspace","repo","src"]`.

- [ ] **Step 4: Tests pass**

- [ ] **Step 5: Commit** `feat: validate turtle-policy-v0alpha1 manifests`

---

### Task 4: Canonical JSON and digests

**Files:**
- Create: `crates/turtle-policy/src/jcs.rs`, `crates/turtle-policy/src/digest.rs`, `crates/turtle-policy/tests/canonical.rs`

**Interfaces:**
- Produces: `canonical_json(&Value) -> Result<String, PolicyError>`, `policy_digest(&TurtlePolicy) -> Digest`

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn key_order_does_not_change_digest() {
    let a = turtle_policy::parse_manifest(br#"
apiVersion: turtle.syberlabs.space/v0alpha1
kind: TurtlePolicy
metadata: {name: a}
spec:
  profile: strict-local-v1
  lifetime: {maxSeconds: 10}
  filesystem:
    snapshotRef: registry:src
    mountAt: /workspace/repo
    writableSubtrees: []
    scratchMiB: 1
    exportSubtrees: []
  network: {mode: broker-only, rawDestinations: []}
  data: {readableClasses: [internal-source], recipients: [owner-local]}
  credentials: {bindings: [], export: false}
  grants:
    - id: r
      action: github.repository.read
      resource: registry:src
      recipients: [owner-local]
  mcp: {enabledTools: [], resourceReads: false, prompts: false, sampling: false, elicitation: false, asyncTasks: false}
  limits:
    domain: {providerAttempts: 1, externalMutations: 0, inferenceOutputTokens: 0, outboundPayloadBytes: 1, memoryMiB: 64, pids: 8, cpuMillisPerSecond: 100}
    local: {memoryMiB: 64, pids: 8, cpuMillisPerSecond: 100}
  delegation: {maxDepth: 0, maxLiveChildren: 0, maxTotalDescendants: 0, allowedTemplates: []}
  audit: {required: true, payloadMode: digest-and-metadata}
"#).unwrap();
    // permute grant constraint insertion via two semantically equal maps
    let d1 = turtle_policy::policy_digest(&a);
    let d2 = turtle_policy::policy_digest(&a);
    assert_eq!(d1, d2);
}

#[test]
fn different_constraints_change_digest() {
    // two policies differing only in maxResponseBytes
}
```

Use two complete fixtures rather than an incomplete YAML fragment in the real test. The snippet above shows intent; the test files will use `tests/fixtures/valid/read-only-repo-worker.yaml` plus a copy with `maxResponseBytes` changed.

- [ ] **Step 2: Fail**

- [ ] **Step 3: Implement JCS for the integer JSON subset and domain-separated SHA-256**

- [ ] **Step 4: Pass**

- [ ] **Step 5: Commit** `feat: canonicalize policy JSON and compute digests`

---

### Task 5: Evaluator — default deny, deny precedence, layers, identity, unknown action, disclosure, obligations

**Files:**
- Create: `crates/turtle-policy/src/evaluate.rs`, `crates/turtle-policy/tests/eval_invariants.rs`, `tests/adversarial/cross_product.rs`, `tests/adversarial/identity.rs`, `tests/fixtures/invalid/cross-product-request.json`

**Interfaces:**
- Consumes: `EffectiveGrant`, `EffectRequest`, `TrustedContext`
- Produces: `evaluate`, `evaluate_layers`, `Decision`

TrustedContext defaults: `adapter_valid = false`, `approval_valid = false`. Callers must set them explicitly for allow paths.

Matching algorithm for one layer:

1. If request.action is unregistered → `E_UNKNOWN_ACTION`.
2. Collect matching deny clauses (complete correlated match). If any → `E_POLICY_DENY`.
3. Collect matching permit clauses. If none → `E_RESOURCE_OUTSIDE_GRANT` when the action is known but resource/recipient/credential tuple does not match; default deny uses that code when a resource is presented, else `E_POLICY_DENY`.
4. Check clause constraints against `Preconditions` (`E_PRECONDITION` or `E_UNSUPPORTED_ENFORCEMENT`).
5. Check disclosure: request recipient must be in the matching clause recipients and in the envelope; readable class vs recipient compatibility uses a closed table. Incompatible → `E_DISCLOSURE`.
6. If matching clause has approval obligation and `ctx.approval_valid` is false → `E_APPROVAL_REQUIRED`. Stale flag in preconditions → `E_APPROVAL_STALE`.
7. If `!ctx.adapter_valid` → `E_UNSUPPORTED_ENFORCEMENT` with explanation that adapter validity was unsatisfied.
8. Lifetime: if `now` beyond expiry or elapsed > maxSeconds → `E_EXPIRED`.
9. Activity: `!turtle_active` → `E_NOT_ACTIVE`; `!ancestors_active` → `E_ANCESTOR_REVOKED`.
10. Budget reservation if a ledger is provided; else if the request would consume a domain counter and no ledger is provided → `E_BUDGET` fail closed? No: evaluate without a ledger does not reserve; `evaluate_layers` with `budget: None` skips reservation only when the action’s cost is zero. Nonzero cost without a ledger → `E_BUDGET` (missing accounting is fail-closed).

Identity: `EffectRequest` has no subject field. Adversarial test builds a JSON object with `"subject": "admin"` and deserializes with `#[serde(deny_unknown_fields)]` so extra fields fail, or if a helper parses JSON requests, unknown fields are ignored as authority and the trusted subject is used.

- [ ] **Step 1: Failing tests** covering required cases 1–5, plus disclosure/approval defaults:

```rust
#[test]
fn default_deny_when_no_complete_clause_matches() { /* read grant, write request */ }

#[test]
fn explicit_deny_overrides_matching_permit() { /* permit + deny same tuple */ }

#[test]
fn unknown_action_denied() { /* action not in registry */ }

#[test]
fn missing_adapter_validity_is_not_true() {
    // otherwise-matching request, adapter_valid left false
}

#[test]
fn missing_approval_is_not_true() {
    // clause obligation approval=exact, approval_valid false
}
```

Adversarial:

```rust
#[test]
fn cross_product_authority_is_rejected() {
    // clause read A with X, write B with Y
    // request write A denied; read B denied; read A allowed; write B allowed
}

#[test]
fn caller_supplied_identity_cannot_influence_evaluation() {
    // trusted subject worker-1; forged JSON subject admin
}
```

- [ ] **Step 2: Fail**

- [ ] **Step 3: Implement `evaluate.rs` exactly as the eligibility formula. Do not flatten clause dimensions.**

- [ ] **Step 4: Pass plus `cargo test -p turtle-policy`**

- [ ] **Step 5: Commit** `feat: evaluate policies with default deny`

---

### Task 6: Attenuation

**Files:**
- Create: `crates/turtle-policy/src/attenuate.rs`, `crates/turtle-policy/tests/attenuation.rs`, `tests/fixtures/valid/attenuated-child.yaml`, `tests/fixtures/invalid/child-widens-recipients.yaml`, `tests/fixtures/valid/all-supported-constraints.yaml`

**Interfaces:**
- Produces: `check_attenuation(parent, child) -> Result<(), Denial>`

Rules (v0):

- Child clause is valid only if **one** parent clause conservatively subsumes it. Union across parents → `E_DELEGATION_WIDENS`.
- Actions, resources, recipients: child ⊆ parent.
- Credential: equal or `Some→None`; never substituted.
- Numeric max: child ≤ parent; numeric min: child ≥ parent; exact: equal unless a registered narrower rule exists (none in P0 besides equality).
- Path subtree: segment prefix, not string prefix. Test `/workspace/repo/src2` vs `/workspace/repo/src`.
- Approval obligation: retained or strengthened (`none` < `exact`).
- Expiry: child expires no later (`expiresAt` ≤ parent, `maxSeconds` ≤ parent remaining).
- Depth/fan-out: child `maxDepth` ≤ parent remaining (`parent.maxDepth - 1`), live children and descendants cannot exceed remaining ancestor capacity. Root depth is 0. Child requesting `maxDepth` greater than remaining → `E_DEPTH`.
- Child identity `parent_id` must equal parent `id`; `root_id` must equal parent `root_id`.

- [ ] **Step 1: Failing tests** for required cases 6–11 and 19’s unit core:

```rust
#[test]
fn child_action_widening_rejected() {}
#[test]
fn child_resource_widening_rejected() {}
#[test]
fn child_recipient_widening_rejected() {}
#[test]
fn credential_substitution_rejected() {}
#[test]
fn earlier_child_expiry_accepted() {}
#[test]
fn later_child_expiry_rejected() {}
#[test]
fn src2_is_not_child_of_src() {}
#[test]
fn unsupported_child_constraint_fails_closed() {}
#[test]
fn union_of_two_parent_clauses_rejected() {}
```

- [ ] **Step 2: Fail**

- [ ] **Step 3: Implement subsumption as `fn clause_subsumes(parent: &GrantClause, child: &GrantClause) -> bool` used only through `check_attenuation`.**

- [ ] **Step 4: Pass**

- [ ] **Step 5: Commit** `feat: check conservative parent-to-child attenuation`

---

### Task 7: Simulated shared budgets

**Files:**
- Create: `crates/turtle-policy/src/budget.rs`, `crates/turtle-policy/tests/budgets.rs`

**Interfaces:**

```rust
pub struct BudgetLedger { /* Mutex<Inner> */ }
pub struct Reservation { pub operation_key: OperationKey, pub amount: u64, pub metric: BudgetMetric }

impl BudgetLedger {
    pub fn new(domain: DomainBudgets) -> Self;
    pub fn try_reserve(&self, domain_id: &str, metric: BudgetMetric, amount: u64, operation_key: &OperationKey) -> Result<Reservation, Denial>;
    pub fn spent(&self, metric: BudgetMetric) -> u64;
    pub fn reserved(&self, metric: BudgetMetric) -> u64;
}
```

Invariant: `spent + reserved <= ceiling` under concurrent `try_reserve`.

Semantics:

- Cumulative metrics only: `providerAttempts`, `externalMutations`, `inferenceOutputTokens`, `outboundPayloadBytes`.
- Same `operation_key` + metric is idempotent (returns existing reservation; does not double-charge; does not reset ceiling).
- New `operation_key` charges again.
- No `release` on child termination for cumulative metrics.
- Two threads racing the last unit: exactly one `Ok`.

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn last_unit_has_exactly_one_winner() {
    // 100 trials of two threads, ceiling=1
}

#[test]
fn retry_same_key_does_not_double_charge() {}

#[test]
fn new_operation_key_does_not_reset_ceiling() {}

#[test]
fn terminated_sibling_does_not_replenish() {
    // drop a Reservation handle; spent remains
}
```

- [ ] **Step 2: Fail**

- [ ] **Step 3: Implement mutex-serialized reservation. Do not add a database.**

- [ ] **Step 4: Pass. Also run the race test 20 times:**

`for /L %i in (1,1,20) do cargo test -p turtle-policy --test budgets last_unit_has_exactly_one_winner -- --exact --nocapture`

- [ ] **Step 5: Commit** `feat: reserve simulated shared-domain budgets`

---

### Task 8: Enforcement plan

**Files:**
- Create: `crates/turtle-policy/src/plan.rs`, `crates/turtle-policy/tests/plan.rs`

Every filesystem, network, credential, MCP, occupancy, and sandbox constraint maps to a row with `status` in `{unsupported, not_requested, external_assumption}` — never `enforced`. `limitation` includes `not deployed in P0`. Policy/attenuation/budget rows may use `status: unsupported` with mechanism `semantic-check-only` and the claim ceiling text.

- [ ] **Step 1: Test that a valid policy’s plan contains no `enforced` and contains the claim ceiling.**

- [ ] **Step 2: Fail**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Pass**

- [ ] **Step 5: Commit** `feat: emit P0 enforcement plans without enforced status`

---

### Task 9: Authority diff

**Files:**
- Create: `crates/turtle-policy/src/diff.rs`, `crates/turtle-policy/tests/diff.rs`, `tests/fixtures/diff/old.yaml`, `tests/fixtures/diff/widen.yaml`, `tests/fixtures/diff/narrow.yaml`

Classify:

- widening: added/broader actions, resources, recipients, credentials, write paths, child templates, later expiry, higher ceilings
- narrowing: removals/reductions
- unclassifiable: `potentially_widening: true`

JSON shape:

```json
{
  "widening": [{"dimension": "recipients", "detail": "..."}],
  "narrowing": [{"dimension": "maxSeconds", "detail": "..."}],
  "potentially_widening": false
}
```

- [ ] **Step 1: Tests for widen, narrow, and unknown constraint treated as potentially widening**

- [ ] **Step 2–5:** implement, pass, commit `feat: classify semantic authority diffs`

---

### Task 10: CLI

**Files:**
- Create: `crates/turtle-cli/Cargo.toml`, `crates/turtle-cli/src/main.rs`, `crates/turtle-cli/tests/cli.rs`

Commands:

```
turtle policy check <manifest>
turtle policy explain <manifest>
turtle policy diff [--format json] <old> <new>
```

`check`: exit 0 only if valid; print `digest=` hex and a one-line summary; on failure print JSON `{ "code": "E_SCHEMA", "explanation": "...", "retryable": false }` to stderr; exit 1.

`explain`: print correlated clauses, resources, recipients, credentials, obligations, lifetime, budgets; every runtime mechanism line ends with `not deployed in P0`. Must contain the claim ceiling. Must not contain the word `enforced` unless quoting `status: unsupported`.

`diff`: human text by default; `--format json` emits the machine-readable diff. Exit 0 if both manifests parse; exit 1 on parse error; exit 2 if widening or potentially_widening (so automation can gate). Document this in README.

- [ ] **Step 1: CLI tests using `assert` on `Command::cargo_bin`.** Because we are not adding `assert_cmd` unless needed, use `std::process::Command` with `env!("CARGO_BIN_EXE_turtle")` after setting `[[bin]] name = "turtle"`.

- [ ] **Step 2–5:** implement, pass, commit `feat: add turtle policy check/explain/diff CLI`

---

### Task 11: Independent reference evaluator, differential and property tests

**Files:**
- Create: `tests/reference/turtle-policy-ref/Cargo.toml`, `tests/reference/turtle-policy-ref/src/lib.rs`, `tests/reference/independence.rs`, `tests/reference/differential.rs`, `crates/turtle-policy/tests/properties.rs`

Reference crate may depend on `turtle-policy` for types and parsing only. It must not import `turtle_policy::evaluate`, `turtle_policy::evaluate_layers`, or any path under `turtle_policy::evaluate::`.

Independence test greps source:

```rust
#[test]
fn reference_crate_does_not_import_production_decide() {
    let src = include_str!("turtle-policy-ref/src/lib.rs");
    assert!(!src.contains("turtle_policy::evaluate"));
    assert!(!src.contains("evaluate_layers"));
}
```

Reference `decide` is a second implementation of the eligibility formula written independently (set scans and explicit deny loop; no shared helper with production).

Property tests (`proptest`, cases 256, freeze seed on failure via `ProptestConfig { failure_persistence: ..., source_file: ... }`):

1. Canonical equivalent object key permutations → same digest.
2. Distinct constraint integers → distinct digests.
3. Child admitted by `check_attenuation` never allows a generated supported request that the parent denies.
4. Production vs reference agreement on generated supported requests.
5. Deny precedence: adding a matching deny to an allowing grant yields deny.

Generated requests only use registered actions and IDs from the grant under test.

- [ ] **Step 1: Write failing differential test** (reference crate missing)

- [ ] **Step 2: Fail**

- [ ] **Step 3: Implement reference evaluator independently**

- [ ] **Step 4: Pass `cargo test --workspace`**

- [ ] **Step 5: Commit** `test: add independent reference evaluator and properties`

---

### Task 12: Documentation, ADRs, evidence, README

**Files:**
- Create/update: `README.md`, `docs/manifest-schema.md`, `docs/authority-semantics.md`, `docs/decisions/0001-correlated-clauses.md`, `docs/decisions/0002-one-parent-clause-subsumption.md`, `docs/decisions/0003-stateful-grants.md`, `docs/decisions/0004-fail-closed-unsupported.md`, `docs/decisions/0005-independent-reference-evaluator.md`, `docs/evidence/p0-semantic-kernel.md`

README P0 section must state capabilities and non-capabilities. Forbidden descriptions: sandbox, credential broker, secure agent runtime, production-ready authorization system.

Evidence file is filled with exact command output in Task 13, not invented numbers.

- [ ] **Step 1–5:** write docs, `cargo test --workspace`, commit `docs: record P0 ADRs, semantics, and evidence`

---

### Task 13: Completion gate

Commands (run from `D:\syberlabs\turtle`, PATH including cargo and the C toolchain):

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p turtle-policy --test budgets last_unit_has_exactly_one_winner -- --exact
# repeat race 20 times
cargo run -p turtle-cli -- policy check tests/fixtures/valid/read-only-repo-worker.yaml
cargo run -p turtle-cli -- policy explain tests/fixtures/valid/read-only-repo-worker.yaml
cargo run -p turtle-cli -- policy diff --format json tests/fixtures/diff/old.yaml tests/fixtures/diff/widen.yaml
rg -n "TODO|FIXME|unimplemented!|todo!|TBD|xxx" --glob '!docs/superpowers/plans/**' --glob '!target/**'
```

Compare implementation against spec sections 4–7, 9, 16, 18, 19. Record unimplemented requirements as out of P0 in `docs/evidence/p0-semantic-kernel.md`.

## Out of P0 (must not be implemented in this pass)

From spec §§4–7, 9, 16, 18, 19, recorded so they are not silently omitted:

- Sandbox/launcher, gVisor, cgroups, Landlock, `openat2` import/export (P1)
- Broker-only network dataplane, credential vault, OAuth, MCP gateway, provider adapters (P2)
- Daemon Unix socket APIs, SQLite persistence, dispatch permits, approvals UI (P2/P4)
- Isolated child sandboxes and cascade revocation runtime (P3)
- TLA+ / state-machine model (required before P3, not P0)
- `turtle doctor/run/inspect/tree/approvals/revoke/audit/export` (later CLI)
- Occupancy enforcement of memory/CPU/PIDs
- Live backend feature detection (`E_DRIVER_DRIFT` is stable but unused by P0 runtime except explicit trusted input)
- Audit durability (`E_AUDIT_UNAVAILABLE` stable, unused)
- Outcome unknown / operation conflict ledger beyond in-memory operation-key idempotency
- Hardware attestation, SBOM, signed releases

## TDD and execution notes

- Iron law: no production behavior without a failing test first.
- Do not weaken fail-closed semantics to make a test pass.
- User requested execution of this plan in the same implementation pass (inline execution via executing-plans).
- Do not start P1 containment in the same pass.

## Self-review

- Spec §6 correlated clauses → Tasks 3, 5, adversarial cross-product.
- Spec §6.3 attenuation → Task 6.
- Spec §6.4 budgets → Task 7.
- Spec §9 parser limits and YAML strictness → Task 2–3.
- Spec §16.2 CLI subset → Task 10.
- Spec §16.4 reason codes → Task 1.
- Spec §18.3 properties and reference evaluator → Task 11.
- Spec §19.2 repo layout → file structure above.
- No TBD/TODO placeholders remain in this plan.
- Type names in later tasks match Task 1–5 productions.
