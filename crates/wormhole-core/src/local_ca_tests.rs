use std::{fs, os::unix::fs::PermissionsExt as _, sync::Arc};

use camino::Utf8Path;
use tempfile::tempdir;

use super::{DAY_SECONDS, LEAF_VALID_DAYS, LocalCertResolver, LocalCertificateAuthority};

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
fn certificates_have_bounded_validity_and_hostname_common_name() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let authority = Arc::new(LocalCertificateAuthority::load_or_create(root).expect("CA"));
    let resolver = LocalCertResolver::new(Arc::clone(&authority));
    let leaf = resolver.resolve_name("app.localhost").expect("leaf");
    let ca_der = authority.certificate_der();
    let (_, ca) = x509_parser::parse_x509_certificate(ca_der.as_ref()).expect("CA certificate");
    let (_, leaf) =
        x509_parser::parse_x509_certificate(leaf.cert[0].as_ref()).expect("leaf certificate");

    let ca_days =
        (ca.validity().not_after.timestamp() - ca.validity().not_before.timestamp()) / DAY_SECONDS;
    let leaf_days = (leaf.validity().not_after.timestamp()
        - leaf.validity().not_before.timestamp())
        / DAY_SECONDS;
    let common_name = leaf
        .subject()
        .iter_common_name()
        .next()
        .expect("common name")
        .as_str()
        .expect("UTF-8 common name");
    assert!((3_649..=3_650).contains(&ca_days));
    assert!(leaf_days <= 398);
    assert_eq!(common_name, "app.localhost");
}

#[test]
fn resolver_renews_leafs_inside_the_renewal_window() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let authority = Arc::new(LocalCertificateAuthority::load_or_create(root).expect("CA"));
    let resolver = LocalCertResolver::new(authority);
    let now = jiff::Timestamp::now();
    let first = resolver.resolve_name_at("app.localhost", now).expect("first leaf");
    let renewal =
        jiff::Timestamp::from_second(now.as_second() + (LEAF_VALID_DAYS - 29) * DAY_SECONDS)
            .expect("renewal time");

    let renewed = resolver.resolve_name_at("app.localhost", renewal).expect("renewed leaf");

    assert!(!Arc::ptr_eq(&first, &renewed));
    assert_ne!(first.cert[0], renewed.cert[0]);
    assert_eq!(resolver.cached_count(), 1);
}

#[test]
fn partial_ca_state_names_both_files_and_recovery_action() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    fs::write(root.join("local-ca.pem"), "partial").expect("partial certificate");

    let error = match LocalCertificateAuthority::load_or_create(root) {
        Ok(_) => panic!("partial CA must fail"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("local-ca.pem"));
    assert!(error.contains("local-ca-key.pem"));
    assert!(error.contains("remove both"));
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
