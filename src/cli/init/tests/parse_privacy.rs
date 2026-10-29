use super::*;

#[test]
fn answers_parse_error_reports_location_without_source() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let path = dir.path().join("answers.toml");
	std::fs::write(&path, "[dns]\ntoken = \"opaque\" trailing-garbage\n").expect("write answers");
	let diagnostic = match read_answers(&path) {
		Ok(_) => String::new(),
		Err(error) => error.to_string(),
	};
	assert!(
		diagnostic == "cannot encode the desired config: invalid answers TOML at line 2, column 18",
		"answers parse diagnostic must contain only the error kind and location"
	);
}
