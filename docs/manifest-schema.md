# Manifest schema reference (v0alpha1)

Canonical schema file: [`schemas/turtle-policy-v0alpha1.schema.json`](../schemas/turtle-policy-v0alpha1.schema.json)

- `apiVersion` is `turtle.syberlabs.space/v0alpha1`
- `kind` is `TurtlePolicy`
- `spec.profile` is `strict-local-v1`
- Unknown fields are rejected
- Grant clauses accept singular `action`/`resource` or plural `actions`/`resources`, never both
- Constraint field names are a closed set. Unknown constraint kinds return `E_UNSUPPORTED_ENFORCEMENT`
- Parser limits: 256 KiB, 128 clauses, 64 resource IDs per clause, 32 constraint fields per clause, 64 path roots, 16 nesting levels, delegation depth at most 4
- Excess input is rejected, never truncated

P0 validates and explains this schema. It does not deploy sandbox, network, or credential enforcement.
