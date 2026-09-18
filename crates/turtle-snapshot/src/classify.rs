//! Path classification for snapshot selection. Does not open files.

use turtle_policy::path::RelPath;
use turtle_policy::PolicyError;

const EXCLUDED_NAMES: &[&str] = &[".git", ".ssh", ".aws", ".gnupg", ".docker", ".netrc"];

pub fn is_excluded_name(name: &str) -> bool {
    EXCLUDED_NAMES.contains(&name)
}

pub fn classify_relative_path(raw: &str) -> Result<RelPath, PolicyError> {
    let path = RelPath::parse(raw)?;
    if path.segments().iter().any(|seg| is_excluded_name(seg)) {
        return Err(PolicyError::schema(format!(
            "path `{raw}` includes an excluded directory"
        )));
    }
    Ok(path)
}
