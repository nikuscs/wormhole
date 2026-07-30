use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use camino::Utf8Path;
use ed25519_dalek::SigningKey;
use nix::{sys::stat::Mode, unistd::mkfifo};
use tempfile::tempdir;

use super::{Identity, PublicKeyRef, open_parent_directory, verify_challenge};
use crate::ProtoError;

fn fixed_identity() -> Identity {
    Identity { signing: SigningKey::from_bytes(&[7_u8; 32]) }
}

#[test]
fn challenge_signature_round_trips() {
    let identity = Identity::generate();
    let nonce = [11_u8; 32];
    let signature = identity.sign_challenge(&nonce, "relay.example.com", 1);

    assert!(verify_challenge(
        &identity.public_base64(),
        &nonce,
        "relay.example.com",
        1,
        &signature
    ));
}

#[test]
fn tampered_challenge_components_fail_verification() {
    let identity = fixed_identity();
    let nonce = [1_u8; 32];
    let signature = identity.sign_challenge(&nonce, "relay.example.com", 1);
    let mut tampered_nonce = nonce;
    tampered_nonce[0] ^= 1;

    assert!(!verify_challenge(
        &identity.public_base64(),
        &tampered_nonce,
        "relay.example.com",
        1,
        &signature
    ));
    assert!(!verify_challenge(
        &identity.public_base64(),
        &nonce,
        "other.example.com",
        1,
        &signature
    ));
    assert!(!verify_challenge(
        &identity.public_base64(),
        &nonce,
        "relay.example.com",
        2,
        &signature
    ));
}

#[test]
fn save_and_load_preserve_identity_with_private_modes() {
    let directory = tempdir().expect("temporary directory");
    let parent = directory.path().join("identity");
    let key_path = parent.join("id.key");
    let key_path = Utf8Path::from_path(&key_path).expect("UTF-8 temporary path");
    let identity = fixed_identity();

    identity.save(key_path).expect("identity must save");
    let loaded = Identity::load(key_path).expect("identity must load");

    assert_eq!(loaded.public_base64(), identity.public_base64());
    assert_eq!(fs::metadata(key_path).expect("key metadata").mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&parent).expect("parent metadata").mode() & 0o777, 0o700);
}

#[test]
fn malformed_private_identity_forms_are_rejected() {
    let directory = tempdir().expect("temporary directory");
    let cases = [
        "",
        "wormhole-identity-v1 AAAA\nsecond",
        "unsupported AAAA",
        "wormhole-identity-v1",
        "wormhole-identity-v1 AAAA extra",
        "wormhole-identity-v1 !!!=",
        "wormhole-identity-v1 AAAA",
    ];
    for (index, contents) in cases.into_iter().enumerate() {
        let path = directory.path().join(format!("bad-{index}.key"));
        fs::write(&path, contents).expect("write malformed identity");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let path = Utf8Path::from_path(&path).expect("UTF-8 path");
        assert!(matches!(Identity::load(path), Err(ProtoError::InvalidIdentity(_))));
    }
}

#[test]
fn load_rejects_world_readable_identity() {
    let directory = tempdir().expect("temporary directory");
    let key_path = directory.path().join("id.key");
    fs::write(&key_path, "wormhole-ed25519 BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\n")
        .expect("key fixture must write");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))
        .expect("permissions must change");
    let key_path = Utf8Path::from_path(&key_path).expect("UTF-8 temporary path");

    let Err(error) = Identity::load(key_path) else {
        panic!("public permissions must fail");
    };

    assert!(matches!(error, ProtoError::KeyPermissions { mode: 0o644, .. }));
    assert!(error.to_string().contains("0600"));
}

#[test]
fn load_rejects_oversized_identity_before_reading_contents() {
    let directory = tempdir().expect("temporary directory");
    let key_path = directory.path().join("oversized.key");
    fs::write(&key_path, vec![b'x'; super::MAX_IDENTITY_FILE_BYTES + 1]).expect("oversized key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("mode");
    let key_path = Utf8Path::from_path(&key_path).expect("UTF-8 path");

    let Err(error) = Identity::load(key_path) else {
        panic!("oversized identity must fail");
    };

    assert!(matches!(error, ProtoError::InvalidIdentity(message) if message.contains("too large")));
}

#[test]
fn load_nonblockingly_rejects_fifo_and_device_descriptors() {
    let directory = tempdir().expect("temporary directory");
    let fifo = directory.path().join("identity.fifo");
    mkfifo(&fifo, Mode::from_bits_truncate(0o600)).expect("FIFO fixture");
    let fifo = Utf8Path::from_path(&fifo).expect("UTF-8 FIFO path");

    let Err(fifo_error) = Identity::load(fifo) else {
        panic!("FIFO must fail without blocking");
    };
    let Err(device_error) = Identity::load(Utf8Path::new("/dev/null")) else {
        panic!("device must fail");
    };

    assert!(
        matches!(fifo_error, ProtoError::InvalidIdentity(message) if message.contains("regular"))
    );
    assert!(
        matches!(device_error, ProtoError::InvalidIdentity(message) if message.contains("regular"))
    );
}

#[test]
fn identity_paths_never_follow_symbolic_links() {
    let directory = tempdir().expect("temporary directory");
    let target = directory.path().join("target.key");
    let link = directory.path().join("identity.key");
    fs::write(&target, "do not replace").expect("target fixture must write");
    symlink(&target, &link).expect("symlink fixture must create");
    let link = Utf8Path::from_path(&link).expect("UTF-8 temporary path");

    assert!(matches!(Identity::load(link), Err(ProtoError::KeySymlink(_))));
    assert!(matches!(fixed_identity().save(link), Err(ProtoError::KeySymlink(_))));
    assert_eq!(fs::read_to_string(target).expect("target must remain"), "do not replace");
}

#[test]
fn ancestor_symbolic_links_are_rejected() {
    let directory = tempdir().expect("temporary directory");
    let outside = directory.path().join("outside");
    let linked_parent = directory.path().join("linked-parent");
    let target = outside.join("id.key");
    let target = Utf8Path::from_path(&target).expect("UTF-8 target path");
    fixed_identity().save(target).expect("target fixture must save");
    symlink(&outside, &linked_parent).expect("ancestor symlink must create");
    let linked_key = linked_parent.join("id.key");
    let linked_key = Utf8Path::from_path(&linked_key).expect("UTF-8 linked path");

    assert!(matches!(Identity::load(linked_key), Err(ProtoError::KeySymlink(_))));
    assert!(matches!(fixed_identity().save(linked_key), Err(ProtoError::KeySymlink(_))));
    assert_eq!(
        Identity::load(target).expect("target must remain").public_base64(),
        fixed_identity().public_base64()
    );
}

#[test]
fn bare_relative_identity_path_resolves_against_current_directory() {
    let (parent, file_name) =
        open_parent_directory(Utf8Path::new("id.key"), false).expect("relative parent must open");

    assert_eq!(file_name, "id.key");
    assert!(parent.metadata().expect("current directory metadata").is_dir());
}

#[test]
fn authorized_public_key_entry_parses_canonical_padded_base64() {
    let identity = fixed_identity();
    let encoded = identity.public_base64();
    let line = format!("{encoded} deploy key for relay");

    let public = PublicKeyRef::parse(&line).expect("authorized key must parse");

    assert!(encoded.ends_with('='));
    assert!(PublicKeyRef::parse(encoded.trim_end_matches('=')).is_err());
    assert_eq!(public.as_base64(), encoded);
    assert_eq!(public.comment(), Some("deploy key for relay"));
    assert_eq!(public.fingerprint(), identity.fingerprint());
}

#[test]
fn weak_public_keys_and_forged_signatures_are_rejected() {
    let mut weak_public = [0_u8; 32];
    weak_public[0] = 1;
    let weak_public = STANDARD.encode(weak_public);
    let mut forged_signature = [0_u8; 64];
    forged_signature[0] = 1;
    let forged_signature = STANDARD.encode(forged_signature);

    assert!(PublicKeyRef::parse(&weak_public).is_err());
    assert!(!verify_challenge(
        &weak_public,
        &[0_u8; 32],
        "relay.example.com",
        1,
        &forged_signature,
    ));
}

#[test]
fn canonical_challenge_signature_is_stable() {
    let identity = fixed_identity();
    let signature = identity.sign_challenge(&[1_u8; 32], "relay.example.com", 1);

    insta::assert_snapshot!(format!("public={}\nsignature={signature}", identity.public_base64()));
}

#[test]
fn fingerprint_is_stable() {
    insta::assert_snapshot!(fixed_identity().fingerprint());
}
