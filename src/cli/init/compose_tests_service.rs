use super::*;
use crate::config::{Listener, ListenerKind};

#[test]
fn the_staged_map_touches_only_the_mail_ports() {
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
	let staged = super::compose_publish::prepare(dir.path(), &listeners, None)
		.expect("a readable generated file")
		.expect("the map moves");
	assert_eq!(staged.path, path);
	let after: serde_json::Value = serde_json::from_slice(&staged.candidate).unwrap();
	assert_eq!(
		after["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "19993:19993"]),
		"compose ports must match current listeners independently"
	);
	let mut expected = before.clone();
	expected["services"]["mail"]["ports"] = serde_json::json!(["25:25", "19993:19993"]);
	assert_eq!(
		after, expected,
		"the staged map must preserve all other fields"
	);
	assert!(
		fs::read(override_path).unwrap() == override_bytes,
		"operator override must stay byte-for-byte unchanged"
	);
	assert!(
		fs::read(&path).unwrap() == serde_json::to_vec(&before).unwrap(),
		"staging a map must not write the generated file"
	);
	// Once the staged candidate is the file, the same listeners move nothing.
	fs::write(&path, &staged.candidate).unwrap();
	let bytes = fs::read(&path).unwrap();
	let mtime = fs::metadata(&path).unwrap().modified().unwrap();
	assert!(
		super::compose_publish::prepare(dir.path(), &listeners, None)
			.expect("a readable generated file")
			.is_none(),
		"identical ports must not stage a rewrite"
	);
	assert!(fs::read(&path).unwrap() == bytes);
	assert_eq!(
		fs::metadata(&path).unwrap().modified().unwrap(),
		mtime,
		"identical ports must not rewrite compose"
	);
}

#[test]
fn an_absent_generated_file_is_a_host_install() {
	let dir = tempfile::tempdir().unwrap();
	assert!(
		super::compose_publish::prepare(dir.path(), &[], None)
			.expect("an absent stack is not an error")
			.is_none()
	);
	assert!(
		!compose_file_path(dir.path()).exists(),
		"host edits must not create a container stack"
	);
}
