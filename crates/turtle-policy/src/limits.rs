//! Parser and algebra complexity limits. Excess is rejected, never truncated.

pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_GRANT_CLAUSES: usize = 128;
pub const MAX_RESOURCE_IDS_PER_CLAUSE: usize = 64;
pub const MAX_CONSTRAINT_FIELDS_PER_CLAUSE: usize = 32;
pub const MAX_PATH_ROOTS: usize = 64;
pub const MAX_NESTING: usize = 16;
pub const MAX_DELEGATION_DEPTH: u8 = 4;
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
