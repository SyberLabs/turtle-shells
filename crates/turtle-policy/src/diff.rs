//! Semantic authority diff. Unclassifiable changes are potentially widening.

use serde::{Deserialize, Serialize};

use crate::grant::{GrantClause, TurtlePolicy};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffEntry {
    pub dimension: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDiff {
    pub widening: Vec<DiffEntry>,
    pub narrowing: Vec<DiffEntry>,
    pub potentially_widening: bool,
}

pub fn diff_authority(old: &TurtlePolicy, new: &TurtlePolicy) -> AuthorityDiff {
    let mut widening = Vec::new();
    let mut narrowing = Vec::new();

    compare_u64(
        "maxSeconds",
        old.lifetime().max_seconds,
        new.lifetime().max_seconds,
        &mut widening,
        &mut narrowing,
        true,
    );
    compare_u64(
        "providerAttempts",
        old.limits().domain.provider_attempts,
        new.limits().domain.provider_attempts,
        &mut widening,
        &mut narrowing,
        true,
    );
    compare_u64(
        "externalMutations",
        old.limits().domain.external_mutations,
        new.limits().domain.external_mutations,
        &mut widening,
        &mut narrowing,
        true,
    );
    compare_u64(
        "maxDepth",
        u64::from(old.delegation().max_depth),
        u64::from(new.delegation().max_depth),
        &mut widening,
        &mut narrowing,
        true,
    );

    let old_templates: Vec<_> = old
        .delegation()
        .allowed_templates
        .iter()
        .map(|t| t.as_str().to_string())
        .collect();
    let new_templates: Vec<_> = new
        .delegation()
        .allowed_templates
        .iter()
        .map(|t| t.as_str().to_string())
        .collect();
    set_diff(
        "childTemplates",
        &old_templates,
        &new_templates,
        &mut widening,
        &mut narrowing,
    );

    let old_paths: Vec<_> = old
        .filesystem()
        .writable_subtrees
        .iter()
        .map(ToString::to_string)
        .collect();
    let new_paths: Vec<_> = new
        .filesystem()
        .writable_subtrees
        .iter()
        .map(ToString::to_string)
        .collect();
    set_diff(
        "writePaths",
        &old_paths,
        &new_paths,
        &mut widening,
        &mut narrowing,
    );

    clause_diff(old.clauses(), new.clauses(), &mut widening, &mut narrowing);

    if old.clauses().len() != new.clauses().len() && widening.is_empty() && narrowing.is_empty() {
        widening.push(DiffEntry {
            dimension: "grants".to_string(),
            detail: "grant clause count changed in an unclassifiable way".to_string(),
        });
    }

    let potentially_widening = !widening.is_empty();
    AuthorityDiff {
        widening,
        narrowing,
        potentially_widening,
    }
}

fn compare_u64(
    dimension: &str,
    old: u64,
    new: u64,
    widening: &mut Vec<DiffEntry>,
    narrowing: &mut Vec<DiffEntry>,
    higher_is_wider: bool,
) {
    if old == new {
        return;
    }
    let wider = if higher_is_wider {
        new > old
    } else {
        new < old
    };
    let entry = DiffEntry {
        dimension: dimension.to_string(),
        detail: format!("{old} -> {new}"),
    };
    if wider {
        widening.push(entry);
    } else {
        narrowing.push(entry);
    }
}

fn set_diff(
    dimension: &str,
    old: &[String],
    new: &[String],
    widening: &mut Vec<DiffEntry>,
    narrowing: &mut Vec<DiffEntry>,
) {
    for item in new {
        if !old.contains(item) {
            widening.push(DiffEntry {
                dimension: dimension.to_string(),
                detail: format!("added {item}"),
            });
        }
    }
    for item in old {
        if !new.contains(item) {
            narrowing.push(DiffEntry {
                dimension: dimension.to_string(),
                detail: format!("removed {item}"),
            });
        }
    }
}

fn clause_diff(
    old: &[GrantClause],
    new: &[GrantClause],
    widening: &mut Vec<DiffEntry>,
    narrowing: &mut Vec<DiffEntry>,
) {
    for new_clause in new {
        match old.iter().find(|c| c.id == new_clause.id) {
            None => widening.push(DiffEntry {
                dimension: "grants".to_string(),
                detail: format!("added clause {}", new_clause.id),
            }),
            Some(old_clause) => {
                if !new_clause.actions.is_subset(&old_clause.actions) {
                    widening.push(DiffEntry {
                        dimension: "actions".to_string(),
                        detail: format!("clause {} actions widened", new_clause.id),
                    });
                } else if !old_clause.actions.is_subset(&new_clause.actions) {
                    narrowing.push(DiffEntry {
                        dimension: "actions".to_string(),
                        detail: format!("clause {} actions narrowed", new_clause.id),
                    });
                }
                if !new_clause.resources.is_subset(&old_clause.resources) {
                    widening.push(DiffEntry {
                        dimension: "resources".to_string(),
                        detail: format!("clause {} resources widened", new_clause.id),
                    });
                } else if !old_clause.resources.is_subset(&new_clause.resources) {
                    narrowing.push(DiffEntry {
                        dimension: "resources".to_string(),
                        detail: format!("clause {} resources narrowed", new_clause.id),
                    });
                }
                if !new_clause.recipients.is_subset(&old_clause.recipients) {
                    widening.push(DiffEntry {
                        dimension: "recipients".to_string(),
                        detail: format!("clause {} recipients widened", new_clause.id),
                    });
                } else if !old_clause.recipients.is_subset(&new_clause.recipients) {
                    narrowing.push(DiffEntry {
                        dimension: "recipients".to_string(),
                        detail: format!("clause {} recipients narrowed", new_clause.id),
                    });
                }
                match (&old_clause.credential, &new_clause.credential) {
                    (Some(old_c), Some(new_c)) if old_c != new_c => widening.push(DiffEntry {
                        dimension: "credentials".to_string(),
                        detail: format!("clause {} credential substituted", new_clause.id),
                    }),
                    (None, Some(new_c)) => widening.push(DiffEntry {
                        dimension: "credentials".to_string(),
                        detail: format!("clause {} added credential {new_c}", new_clause.id),
                    }),
                    (Some(_), None) => narrowing.push(DiffEntry {
                        dimension: "credentials".to_string(),
                        detail: format!("clause {} removed credential", new_clause.id),
                    }),
                    _ => {}
                }
            }
        }
    }
    for old_clause in old {
        if !new.iter().any(|c| c.id == old_clause.id) {
            narrowing.push(DiffEntry {
                dimension: "grants".to_string(),
                detail: format!("removed clause {}", old_clause.id),
            });
        }
    }
}
