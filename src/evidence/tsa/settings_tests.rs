use super::*;

fn with(url: &str, anchors: Vec<String>) -> Settings {
	Settings {
		enabled: true,
		authorities: vec![Authority {
			url: url.to_string(),
			anchors,
		}],
	}
}

#[test]
fn the_default_is_enabled_with_the_pinned_public_authority() {
	let settings = Settings::default();
	assert!(settings.enabled);
	assert_eq!(settings.authorities[0].url, "https://timestamp.sectigo.com");
	assert_eq!(settings.authorities[0].anchor_hashes().len(), 1);
	assert_eq!(settings.validate(), Ok(()));
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(load(dir.path()).expect("load"), Settings::default());
}

#[test]
fn only_https_or_loopback_http_with_real_anchors_is_saved() {
	let anchor = DEFAULT_TSA_ANCHOR.to_string();
	assert_eq!(
		with("https://tsa.example.org/tsr", vec![anchor.clone()]).validate(),
		Ok(())
	);
	assert_eq!(
		with("http://127.0.0.1:3180/tsr", vec![anchor.clone()]).validate(),
		Ok(())
	);
	for url in [
		"http://tsa.example.org/tsr",
		"ftp://tsa.example.org",
		"https://",
		"not a url",
	] {
		let error = with(url, vec![anchor.clone()]).validate().expect_err(url);
		assert!(error.0.contains("URL"), "{url}: {error}");
	}
	let error = with("https://tsa.example.org", vec![])
		.validate()
		.expect_err("no anchor");
	assert_eq!(error.0, "each authority needs 1 to 8 anchors");
	let error = with("https://tsa.example.org", vec!["AB".repeat(32)])
		.validate()
		.expect_err("upper");
	assert!(error.0.starts_with("an anchor is"));
	let disabled_empty = Settings {
		enabled: false,
		authorities: Vec::new(),
	};
	assert_eq!(disabled_empty.validate(), Ok(()));
	let enabled_empty = Settings {
		enabled: true,
		authorities: Vec::new(),
	};
	assert!(enabled_empty.validate().is_err());
}

#[test]
fn saved_settings_load_back_and_bad_ones_are_not_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let settings = Settings {
		enabled: false,
		..Settings::default()
	};
	save(dir.path(), &settings).expect("save");
	assert_eq!(load(dir.path()).expect("load"), settings);
	let bad = with(
		"http://tsa.example.org",
		vec![DEFAULT_TSA_ANCHOR.to_string()],
	);
	assert!(save(dir.path(), &bad).is_err());
	assert_eq!(load(dir.path()).expect("load"), settings);
}
