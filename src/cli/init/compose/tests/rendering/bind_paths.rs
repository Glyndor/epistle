use super::{minimal_answers, render};
use serde_json::json;

#[test]
fn colon_paths_are_preserved_in_long_bind_mounts() {
	let mut answers = minimal_answers();
	answers.data_dir = "/srv/epistle:prod".into();
	answers.config_path = "/etc/epistle:prod/mail.toml".into();
	let value = render(&answers, false);
	let mail = value["services"]["mail"]["volumes"].as_array().unwrap();
	assert_eq!(
		mail[0],
		json!({"type": "bind", "source": "/etc/epistle:prod", "target": "/etc/epistle:prod", "read_only": true, "bind": {"selinux": "Z"}}),
		"config paths containing a colon must use long bind syntax"
	);
	assert_eq!(
		mail[1],
		json!({"type": "bind", "source": "/srv/epistle:prod", "target": "/srv/epistle:prod", "read_only": false, "bind": {"selinux": "Z"}})
	);
	let mounts = value["services"]["clamav"]["volumes"].as_array().unwrap();
	assert!(mounts.contains(&json!({"type": "bind", "source": "/srv/epistle:prod/compose/clamd.conf", "target": "/etc/clamav/epistle-clamd.conf", "read_only": true, "bind": {"selinux": "Z"}})), "clamd config bind must preserve the colon path");
	for service in value["services"].as_object().unwrap().values() {
		for mount in service["volumes"].as_array().unwrap() {
			if let Some(short) = mount.as_str() {
				assert!(
					!short.starts_with('/'),
					"host binds must never use short syntax"
				);
			}
		}
	}
}
