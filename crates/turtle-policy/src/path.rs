//! Path subtree comparison uses normalized segments, never string prefixes.

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RelPath {
    segments: Vec<String>,
}

impl RelPath {
    pub fn parse(raw: &str) -> Result<Self, PolicyError> {
        if raw.is_empty() {
            return Err(PolicyError::schema("path must be non-empty"));
        }
        if raw.contains('\0') {
            return Err(PolicyError::schema("path contains NUL"));
        }
        if raw.contains('\\') {
            return Err(PolicyError::schema("path contains backslash"));
        }
        if raw.starts_with('/') || raw.starts_with("~/") {
            return Err(PolicyError::schema(format!(
                "absolute or home-relative path `{raw}` is not allowed"
            )));
        }
        if raw.contains(':') {
            return Err(PolicyError::schema(format!(
                "path `{raw}` contains a drive or scheme prefix"
            )));
        }
        let mut segments = Vec::new();
        for part in raw.split('/') {
            if part.is_empty() || part == "." || part == ".." {
                return Err(PolicyError::schema(format!(
                    "path `{raw}` contains traversal or empty segments"
                )));
            }
            segments.push(part.to_string());
        }
        Ok(Self { segments })
    }

    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// True when `self` is the same path as `other` or a strict descendant by segment prefix.
    pub fn is_under(&self, other: &RelPath) -> bool {
        self.segments.starts_with(&other.segments)
    }

    pub fn overlaps(&self, other: &RelPath) -> bool {
        self.is_under(other) || other.is_under(self)
    }
}

impl TryFrom<String> for RelPath {
    type Error = PolicyError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<RelPath> for String {
    fn from(value: RelPath) -> Self {
        value.segments.join("/")
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::RelPath;

    #[test]
    fn src2_is_not_under_src() {
        let src = RelPath::parse("workspace/repo/src").unwrap();
        let src2 = RelPath::parse("workspace/repo/src2").unwrap();
        assert!(!src2.is_under(&src));
        assert!(!src.is_under(&src2));
    }
}
