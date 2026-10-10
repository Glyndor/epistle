use super::rewrite_default_image;
use serde_json::json;

#[test]
fn update_rewrites_only_the_managed_mail_image() {
	for managed in [true, false] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("compose.yaml");
		let original = json!({
			"name": "epistle",
			"x-epistle-managed-image": managed,
			"services": {
				"mail": {"image": "ghcr.io/glyndor/epistle:0.7.1", "ports": ["25:25"], "volumes": ["data:/data"]},
				"db": {"image": "postgres:18"}
			},
			"volumes": {"data": {}}
		});
		let bytes = serde_json::to_vec_pretty(&original).unwrap();
		std::fs::write(&path, &bytes).unwrap();
		rewrite_default_image(&path).unwrap();
		let actual: serde_json::Value =
			serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
		let expected = if managed {
			format!("ghcr.io/glyndor/epistle:{}", env!("CARGO_PKG_VERSION"))
		} else {
			"ghcr.io/glyndor/epistle:0.7.1".into()
		};
		assert_eq!(
			actual["services"]["mail"]["image"], expected,
			"update must pin the managed image to the full CLI version and retain operator images"
		);
		let mut rest = actual;
		rest["services"]["mail"]["image"] = original["services"]["mail"]["image"].clone();
		assert!(
			rest == original,
			"update must retain every other compose field"
		);
		if !managed {
			assert!(
				std::fs::read(&path).unwrap() == bytes,
				"operator image ownership must leave compose bytes untouched"
			);
		}
	}
}

#[test]
fn legacy_default_keeps_ownership_for_future_upgrades() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compose.yaml");
	std::fs::write(
		&path,
		r#"{"services":{"mail":{"image":"ghcr.io/glyndor/epistle:0.7"}}}"#,
	)
	.unwrap();
	rewrite_default_image(&path).unwrap();
	let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
	assert_eq!(
		value["x-epistle-managed-image"], true,
		"legacy upgrades must persist managed image ownership for subsequent releases"
	);
	assert_eq!(
		value["services"]["mail"]["image"],
		format!("ghcr.io/glyndor/epistle:{}", env!("CARGO_PKG_VERSION"))
	);
}

#[test]
fn legacy_custom_image_remains_byte_identical() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compose.yaml");
	let original = br#"{"services":{"mail":{"image":"registry.example.org/mail:0.7"}}}"#;
	std::fs::write(&path, original).unwrap();
	rewrite_default_image(&path).unwrap();
	assert!(
		std::fs::read(&path).unwrap() == original,
		"legacy operator images must remain byte identical"
	);
}
