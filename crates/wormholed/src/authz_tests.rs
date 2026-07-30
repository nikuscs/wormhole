use std::{fs, sync::Arc};

use camino::Utf8Path;
use tempfile::tempdir;
use wormhole_proto::{Identity, PublicKeyRef};

use super::{AuthStore, KeyDecision, KeyLimits};
use crate::db::RelayDb;

fn store(path: &Utf8Path) -> AuthStore {
    let database = Arc::new(RelayDb::open(path).expect("database must open"));
    AuthStore::new(database, KeyLimits { max_binds: 4, max_sessions: 2, max_streams: 32 })
}

#[test]
fn unseen_public_file_is_imported_once() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let imports = path.join("authorized_keys");
    fs::create_dir(&imports).expect("import directory must create");
    let identity = Identity::generate();
    fs::write(imports.join("deploy.pub"), format!("{} deploy key\n", identity.public_base64()))
        .expect("public file must write");
    let store = store(path);

    assert_eq!(store.import_directory(&imports).expect("first import must succeed"), 1);
    assert_eq!(store.import_directory(&imports).expect("second import must succeed"), 0);
    assert!(matches!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Allowed { name, .. } if name == "deploy key"
    ));
}

#[test]
fn revoked_database_row_wins_over_public_file() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let imports = path.join("authorized_keys");
    fs::create_dir(&imports).expect("import directory must create");
    let identity = Identity::generate();
    let store = store(path);
    let fingerprint =
        store.authorize(&identity.public_base64(), "revoked").expect("key must authorize");
    store.revoke(&fingerprint).expect("key must revoke");
    fs::write(imports.join("revoked.pub"), format!("{} resurrect\n", identity.public_base64()))
        .expect("public file must write");

    assert_eq!(store.import_directory(&imports).expect("import must succeed"), 0);
    assert_eq!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Revoked
    );
}

#[test]
fn authorize_and_revoke_update_authoritative_state() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let identity = Identity::generate();
    let store = store(path);

    assert_eq!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Unknown
    );
    let fingerprint =
        store.authorize(&identity.public_base64(), "agent").expect("key must authorize");
    let expected = PublicKeyRef::parse(&identity.public_base64())
        .expect("generated key must parse")
        .fingerprint();
    assert_eq!(fingerprint, expected);
    assert!(matches!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Allowed { name, limits, .. }
            if name == "agent" && limits.max_binds == 4
    ));

    store.revoke(&fingerprint).expect("key must revoke");
    assert_eq!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Revoked
    );
}

#[test]
fn single_use_invite_enrolls_exactly_one_independent_key() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let store = store(path);
    let invite =
        store.create_invite("personal device", Some(600), Some(1)).expect("invite must create");
    let first = Identity::generate();
    let second = Identity::generate();

    assert!(matches!(
        store
            .authorize_or_redeem(&first.public_base64(), Some(&invite.token))
            .expect("first redemption"),
        KeyDecision::Allowed { name, .. } if name == "personal device"
    ));
    assert_eq!(
        store
            .authorize_or_redeem(&second.public_base64(), Some(&invite.token))
            .expect("second redemption"),
        KeyDecision::Unknown
    );
    let listed = store.list_invites().expect("invite list");
    assert_eq!(listed[0].uses, 1);
    assert_ne!(listed[0].secret_sha256, invite.token);
    let database = fs::read(path.join("state.redb")).expect("database bytes");
    assert!(!database.windows(invite.token.len()).any(|window| window == invite.token.as_bytes()));
}

#[test]
fn reusable_invite_enrolls_multiple_independently_keyed_clients() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let store = store(path);
    let invite = store.create_invite("fleet", None, None).expect("invite must create");

    for identity in [Identity::generate(), Identity::generate()] {
        let decision = store
            .authorize_or_redeem(&identity.public_base64(), Some(&invite.token))
            .expect("redemption");
        assert!(matches!(decision, KeyDecision::Allowed { .. }), "{decision:?}");
    }
    assert_eq!(store.list_invites().expect("invite list")[0].uses, 2);
}

#[test]
fn revoked_or_malformed_invites_cannot_enroll_clients() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let store = store(path);
    let invite = store.create_invite("revoked", None, None).expect("invite must create");
    store.revoke_invite(&invite.id).expect("invite must revoke");

    for token in [invite.token.as_str(), "not-an-invite", "whi_bad_bad"] {
        assert_eq!(
            store
                .authorize_or_redeem(&Identity::generate().public_base64(), Some(token))
                .expect("invalid redemption"),
            KeyDecision::Unknown
        );
    }
}

#[test]
fn revoked_key_cannot_be_resurrected_with_a_valid_invite() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let store = store(path);
    let identity = Identity::generate();
    let fingerprint =
        store.authorize(&identity.public_base64(), "revoked").expect("key must authorize");
    store.revoke(&fingerprint).expect("key must revoke");
    let invite = store.create_invite("replacement", None, None).expect("invite must create");

    assert_eq!(
        store
            .authorize_or_redeem(&identity.public_base64(), Some(&invite.token))
            .expect("authorization"),
        KeyDecision::Revoked
    );
    assert_eq!(store.list_invites().expect("invite list")[0].uses, 0);
}

#[test]
fn expired_invite_is_rejected_without_consuming_a_use() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let store = store(path);
    let invite = store.create_invite("short", Some(1), Some(1)).expect("invite must create");
    let identity = Identity::generate();

    assert_eq!(
        store
            .authorize_or_redeem_at(
                &identity.public_base64(),
                Some(&invite.token),
                invite.created_at + 2,
            )
            .expect("expired redemption"),
        KeyDecision::Unknown
    );
    assert_eq!(store.list_invites().expect("invite list")[0].uses, 0);
}

#[test]
fn concurrent_single_use_redemptions_have_exactly_one_winner() {
    use std::sync::{Arc, Barrier};

    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let store = Arc::new(store(path));
    let invite = store.create_invite("race", None, Some(1)).expect("invite must create");
    let barrier = Arc::new(Barrier::new(8));
    #[allow(clippy::needless_collect)] // All workers must spawn before any can cross the barrier.
    let workers = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let token = invite.token.clone();
            std::thread::spawn(move || {
                let identity = Identity::generate();
                barrier.wait();
                store
                    .authorize_or_redeem(&identity.public_base64(), Some(&token))
                    .expect("concurrent redemption")
            })
        })
        .collect::<Vec<_>>();
    let winners = workers
        .into_iter()
        .map(|worker| matches!(worker.join().expect("worker"), KeyDecision::Allowed { .. }))
        .filter(|won| *won)
        .count();

    assert_eq!(winners, 1);
    assert_eq!(store.list_invites().expect("invite list")[0].uses, 1);
}
