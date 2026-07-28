use tempfile::tempdir;
use wormhole_core::{EndpointSpec, Service, Target, model::ServiceProto};
use wormhole_proto::frames::Persistence;

use super::{DesiredKey, DesiredService, StateDb};

#[test]
fn desired_services_round_trip() {
    let directory = tempdir().expect("tempdir");
    let path = camino::Utf8Path::from_path(directory.path()).expect("utf8");
    let database = StateDb::open(path).expect("open");
    let desired = DesiredService {
        active: true,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: Service {
            name: "web".to_owned(),
            target: Target::Port(3000),
            proto: ServiceProto::Http,
        },
        endpoints: vec![EndpointSpec {
            proto: ServiceProto::Http,
            driver: "wormhole".to_owned(),
            qualifier: None,
            remote: Some("local".to_owned()),
            host: Some("web".to_owned()),
            domain: None,
            public_port: None,
            persist: Persistence::Persistent,
            buffer: None,
            auth: None,
            retry: None,
            inspect: false,
            inspect_assets: false,
            capture_body_max: 1024 * 1024,
            reservation: None,
        }],
        disabled_endpoints: Vec::new(),
    };

    database.put(&desired).expect("put");

    assert!(path.join("state.redb").exists());
    let restored = database.list().expect("list");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].service.name, "web");
    let key = DesiredKey::new("project".to_owned(), "web".to_owned()).expect("key");
    assert!(database.delete(&key).expect("delete"));
}

#[test]
fn desired_keys_are_collision_free_and_validate_addressable_names() {
    let first = DesiredKey::new("a".to_owned(), "b:c".to_owned()).expect("first");
    let second = DesiredKey::new("a".to_owned(), "b".to_owned()).expect("second");

    assert_ne!(first, second);
    assert!(DesiredKey::new(String::new(), String::new()).is_err());
    assert!(DesiredKey::new("a:b".to_owned(), "c".to_owned()).is_err());
    assert!(DesiredKey::new(String::new(), "a/b".to_owned()).is_ok());
}
