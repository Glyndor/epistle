use super::*;
use crate::config::ListenerKind;

#[test]
fn service_compose_updates_only_mail_ports() {
	let dir = tempfile::tempdir().unwrap();
	let path = compose_file_path(dir.path());
	fs::create_dir_all(path.parent().unwrap()).unwrap();
	let before = serde_json::json!({"name":"custom-stack", "x-epistle-managed-image":false,
        "services":{"mail":{"image":"operator/image:v1","ports":["143:143","993:993"],"environment":{"EXAMPLE":"keep"}},
            "db":{"image":"operator/db:v1"}}, "volumes":{"operator-volume":{}}});
	fs::write(&path, serde_json::to_vec(&before).unwrap()).unwrap();
	let override_path = path.parent().unwrap().join("compose.override.yaml");
	let override_bytes = b"services:\n  mail:\n    cpus: 2\n";
	fs::write(&override_path, override_bytes).unwrap();
	let listeners = vec![
		Listener {
			kind: ListenerKind::Smtp,
			addr: "::".parse().unwrap(),
			port: None,
		},
		Listener {
			kind: ListenerKind::Imaps,
			addr: "0.0.0.0".parse().unwrap(),
			port: Some(19993),
		},
		Listener {
			kind: ListenerKind::Api,
			addr: "127.0.0.1".parse().unwrap(),
			port: None,
		},
	];
	assert!(update_listener_ports(dir.path(), &listeners).unwrap());
	let after: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
	assert_eq!(
		after["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "19993:19993"]),
		"compose ports must match current listeners independently"
	);
	let mut expected = before;
	expected["services"]["mail"]["ports"] = serde_json::json!(["25:25", "19993:19993"]);
	assert_eq!(
		after, expected,
		"compose updates must preserve all other fields"
	);
	assert!(
		fs::read(override_path).unwrap() == override_bytes,
		"operator override must stay byte-for-byte unchanged"
	);
	let bytes = fs::read(&path).unwrap();
	let mtime = fs::metadata(&path).unwrap().modified().unwrap();
	assert!(update_listener_ports(dir.path(), &listeners).unwrap());
	assert!(fs::read(&path).unwrap() == bytes);
	assert_eq!(
		fs::metadata(&path).unwrap().modified().unwrap(),
		mtime,
		"identical ports must not rewrite compose"
	);
}

#[test]
fn service_compose_absent_is_a_host_install() {
	let dir = tempfile::tempdir().unwrap();
	assert!(!update_listener_ports(dir.path(), &[]).unwrap());
	assert!(
		!compose_file_path(dir.path()).exists(),
		"host edits must not create a container stack"
	);
}
