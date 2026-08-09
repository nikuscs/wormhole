use std::{fs, os::unix::fs::PermissionsExt as _, sync::Arc};

use camino::Utf8Path;
use tempfile::tempdir;

use super::{LocalCertResolver, LocalCertificateAuthority};

#[test]
fn ca_is_persisted_once_with_owner_only_permissions() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let first = LocalCertificateAuthority::load_or_create(root).expect("first CA");
    let first_der = first.certificate_der();
    let certificate_path = root.join("local-ca.pem");
    let key_path = root.join("local-ca-key.pem");

    assert_eq!(
        fs::metadata(&certificate_path).expect("certificate metadata").permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::metadata(&key_path).expect("key metadata").permissions().mode() & 0o777, 0o600);
    assert_eq!(first.certificate_path(), certificate_path);

    let second = LocalCertificateAuthority::load_or_create(root).expect("reloaded CA");
    assert_eq!(first_der, second.certificate_der());
}

#[test]
fn resolver_issues_distinct_leafs_and_caches_each_hostname() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let authority = Arc::new(LocalCertificateAuthority::load_or_create(root).expect("CA"));
    let resolver = LocalCertResolver::new(authority);

    let first = resolver.resolve_name("App.Localhost").expect("first leaf");
    let cached = resolver.resolve_name("app.localhost").expect("cached leaf");
    let second = resolver.resolve_name("api.localhost").expect("second leaf");

    assert!(Arc::ptr_eq(&first, &cached));
    assert_ne!(first.cert[0], second.cert[0]);
    assert_eq!(first.cert.len(), 2);
    assert_eq!(resolver.cached_count(), 2);
}

#[test]
fn loading_rejects_non_private_ca_files() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    LocalCertificateAuthority::load_or_create(root).expect("CA");
    let key_path = root.join("local-ca-key.pem");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("permissions");

    assert!(LocalCertificateAuthority::load_or_create(root).is_err());
}
