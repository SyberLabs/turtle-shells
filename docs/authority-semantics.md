# Authority semantics (P0)

A grant clause is a correlated tuple:

`(actions, resources, credential_binding, recipients, constraints, obligations)`

Authority to read repository A using credential X and write repository B using credential Y does **not** imply permission to write A with Y or read B with X.

Evaluation is default deny. An explicit matching deny overrides a matching permit. Administrator, owner, and ancestor layers intersect. The evaluator takes the authenticated subject and effective grant from trusted caller context. `EffectRequest` cannot supply subject, role, or credential secrets.

Adapter validity and approval validity are trusted inputs and default to unsatisfied.

Attenuation requires **one** parent clause to conservatively subsume each child clause. Unions of parent clauses are rejected. Path comparison uses normalized segments, never string prefixes: `workspace/repo/src2` is not under `workspace/repo/src`.

Shared cumulative budgets obey `spent + reserved <= ceiling`. A retry with the same operation key does not double-charge. A new operation key, new child, or terminated sibling does not replenish spent or reserved cumulative units. Occupancy fields (memory, PIDs, CPU) are parsed and explained; they are not reserved as effect budgets.

P0 claim ceiling: pure policy evaluator, delegation checker, and simulated budgets. No containment claim.
