use turtle_policy::path::RelPath;
use turtle_snapshot::{classify_relative_path, is_excluded_name};

#[test]
fn traversal_and_absolute_paths_are_rejected() {
    assert!(classify_relative_path("../secret").is_err());
    assert!(classify_relative_path("/etc/passwd").is_err());
    assert!(classify_relative_path("src/../etc").is_err());
    assert!(classify_relative_path("src").is_ok());
}

#[test]
fn credential_and_git_directories_are_excluded() {
    for name in [".git", ".ssh", ".aws", ".gnupg", ".docker", ".netrc"] {
        assert!(is_excluded_name(name), "{name}");
        assert!(classify_relative_path(name).is_err(), "{name}");
        assert!(
            classify_relative_path(&format!("{name}/config")).is_err(),
            "{name}/config"
        );
        assert!(
            classify_relative_path(&format!("src/{name}/config")).is_err(),
            "src/{name}/config"
        );
    }
    let src = RelPath::parse("src/lib.rs").unwrap();
    assert_eq!(classify_relative_path("src/lib.rs").unwrap(), src);
}
