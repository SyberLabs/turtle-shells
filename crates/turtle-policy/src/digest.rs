//! Domain-separated SHA-256 digests. No custom cryptography.

use sha2::{Digest as _, Sha256};

use crate::error::PolicyError;
use crate::grant::TurtlePolicy;
use crate::jcs::canonical_json;

pub const POLICY_DIGEST_PREFIX: &[u8] = b"turtle-policy-v0alpha1\n";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

pub fn sha256_domain(prefix: &[u8], payload: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(payload);
    Digest(hasher.finalize().into())
}

pub fn policy_digest(policy: &TurtlePolicy) -> Result<Digest, PolicyError> {
    let canonical = canonical_json(policy.canonical_json())?;
    Ok(sha256_domain(POLICY_DIGEST_PREFIX, canonical.as_bytes()))
}

pub fn digest_bytes(bytes: &[u8]) -> Digest {
    sha256_domain(b"turtle-bytes-v0\n", bytes)
}
