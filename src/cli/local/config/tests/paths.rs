use super::*;

#[test]
fn local_config_paths_round_trip_through_toml() {
	let root = tempfile::tempdir_in(".").expect("tempdir");
	for name in [r"epistle\test", "epistle\"test", "epistle\ntest"] {
		let dir = root.path().join(name);
		std::fs::create_dir(&dir).expect("create directory");
		let cert = dir.join("cert.pem");
		let key = dir.join("key.pem");
		let dkim = dir.join("dkim.pem");
		write_mail_toml_replace(&dir, 10000, &cert, &key, &dkim, "unused").expect("write config");
		let body = std::fs::read_to_string(dir.join("mail.toml")).expect("read config");
		let parsed = toml::from_str::<toml::Value>(&body).ok();
		let expected = [
			(None, "data_dir", dir.join("data")),
			(Some("tls"), "cert_file", cert),
			(Some("tls"), "key_file", key),
			(Some("dkim"), "key_file", dkim),
		];
		for (section, field, path) in expected {
			let actual = parsed
				.as_ref()
				.and_then(|value| section.map_or(Some(value), |section| value.get(section)))
				.and_then(|value| value.get(field))
				.and_then(toml::Value::as_str);
			assert!(
				actual == Some(path.to_string_lossy().as_ref()),
				"generated local config paths must round-trip without changing bytes"
			);
		}
	}
}
