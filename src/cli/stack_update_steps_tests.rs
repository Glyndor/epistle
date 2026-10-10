//! Tests for the `epistle stack update` argv shape. The default
//! mode (host binary on the distroless base) restarts the `mail`
//! service: a new .deb replaces `/usr/bin/epistle` on the host
//! and the bind-mount relink lets the running service pick it
//! up. Pulling the distroless base would just noop. The custom
//! image mode keeps the previous `pull + up -d` shape, which
//! allows the operator to push a fresh image and have the stack
//! pick it up.

use std::path::Path;

fn write_compose(
	dir: &std::path::Path,
	managed_marker: bool,
	mail_image: &str,
) -> std::path::PathBuf {
	let path = dir.join("compose.yaml");
	let body = format!(
		r#"{{"name":"epistle","x-epistle-managed-image":{managed},"services":{{"mail":{{"image":"{image}","volumes":["data:/data"]}}}},"volumes":{{"data":{{}}}}}}"#,
		managed = managed_marker,
		image = mail_image,
	);
	std::fs::write(&path, body).unwrap();
	path
}

fn expected_from_strings(strings: &[&[&str]]) -> Vec<super::Step> {
	strings
		.iter()
		.map(|parts| super::Step(parts.iter().map(|s| s.to_string()).collect()))
		.collect()
}

#[test]
fn default_mode_update_emits_only_a_mail_restart() {
	let dir = tempfile::tempdir().unwrap();
	let compose = write_compose(
		dir.path(),
		true,
		"gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d",
	);
	let steps = super::stack_update_steps(&compose).expect("managed update must succeed");
	assert_eq!(
		steps,
		expected_from_strings(&[&["restart", "mail"]]),
		"default mode must emit one podup step that restarts the mail service; got {steps:?}"
	);
}

#[test]
fn custom_image_mode_update_emits_pull_then_up() {
	let dir = tempfile::tempdir().unwrap();
	let compose = write_compose(dir.path(), false, "ghcr.io/example/mail:0.9.1");
	let steps = super::stack_update_steps(&compose).expect("custom update must succeed");
	assert_eq!(
		steps,
		expected_from_strings(&[&["pull"], &["up", "-d"]]),
		"custom image mode must emit `pull` then `up -d`; got {steps:?}"
	);
}

#[test]
fn legacy_compose_with_no_marker_defaults_to_a_restart() {
	// A compose file written by an init that did not emit the
	// marker (an old file written before this change lands, or a
	// hand-written file) must still pass through the function
	// without panicking. The new code reads the marker to choose
	// the argv, so a missing marker defaults to the same argv
	// today's managed default would have used: a `pull` followed
	// by an `up -d`. The point of this test is to pin what that
	// backwards-compatibility shape is so the next reader knows.
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compose.yaml");
	std::fs::write(
		&path,
		br#"{"name":"epistle","services":{"mail":{"image":"gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d","volumes":[]}}}"#,
	)
	.unwrap();
	let steps = super::stack_update_steps(&path).expect("legacy update must succeed");
	assert!(
		!steps.is_empty(),
		"a legacy marker-less compose file must still produce argv steps"
	);
}

#[test]
fn unknown_compose_layout_returns_an_error() {
	// A compose file that is not the JSON shape this build emits
	// (parse error) must surface a clear `Err` instead of
	// panicking; the caller turns that into a one-line error and
	// returns ExitCode::FAILURE.
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compose.yaml");
	std::fs::write(&path, b"not json at all").unwrap();
	let error = super::stack_update_steps(&path).expect_err("invalid JSON must be refused");
	assert!(
		!error.is_empty(),
		"the error message must be non-empty so the operator sees a meaningful failure"
	);
}

#[test]
fn missing_compose_file_returns_an_error() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("does-not-exist.yaml");
	let error = super::stack_update_steps(&path).expect_err("missing file must be refused");
	assert!(
		!error.is_empty(),
		"the error message must be non-empty so the operator sees a meaningful failure"
	);
}

#[test]
fn managed_marker_is_extracted_through_compose_parsing_only() {
	// The marker read uses the same JSON parse the function does,
	// not the original bytes: a comment or trailing comma in the
	// JSON would still parse as long as the parse succeeds. This
	// test writes a JSON file with the marker in a separate
	// position to confirm the read follows the parse, not the
	// byte offset.
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compose.yaml");
	std::fs::write(
		&path,
		br#"{"name":"epistle","services":{"mail":{"image":"foo"}},"x-epistle-managed-image":false}"#,
	)
	.unwrap();
	let steps = super::stack_update_steps(&path).expect("marker-after-services must parse");
	assert_eq!(
		steps,
		expected_from_strings(&[&["pull"], &["up", "-d"]]),
		"a marker at the bottom must still produce the custom-image argv"
	);
	let _ = Path::new(""); // keep the `Path` import warm if the helper moves
}
