//! A second run changes nothing: no new key, no new secret.

use super::*;

#[test]
fn a_second_run_reuses_both_files_and_leaves_them_byte_for_byte() {
	let layout = layout();
	run(&layout, NOW);
	let (token, session) = (
		api_token_path(&layout.data),
		session_secret_path(&layout.data),
	);
	let before = (text(&token), text(&session), row(&layout));
	let report = run(&layout, NOW + DAY);
	assert_eq!(
		kinds(&report),
		[
			("reused", token.clone()),
			("reused", session.clone()),
			("reused", admin_id_path(&layout.data))
		]
	);
	assert_eq!((text(&token), text(&session)), (before.0, before.1));
	let after = row(&layout);
	assert_eq!(after.hash, before.2.hash, "the stored key did not change");
	assert_eq!(after.expires_at, before.2.expires_at);
}

#[test]
fn no_second_panel_key_is_minted_while_a_valid_one_exists() {
	let layout = layout();
	for day in 0..5 {
		run(&layout, NOW + day * DAY);
	}
	assert_eq!(count_keys(&layout), 1);
}

#[test]
fn a_session_secret_that_exists_is_never_overwritten() {
	let layout = layout();
	let path = session_secret_path(&layout.data);
	std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
	let mine = "a".repeat(40);
	std::fs::write(&path, &mine).expect("write");
	run(&layout, NOW);
	assert_eq!(text(&path), mine);
}

#[test]
fn a_session_secret_survives_the_key_being_renewed() {
	let layout = layout();
	run(&layout, NOW);
	let path = session_secret_path(&layout.data);
	let before = text(&path);
	run(&layout, NOW + 340 * DAY);
	assert_eq!(text(&path), before);
}

#[test]
fn a_session_secret_of_exactly_32_bytes_is_kept_and_a_line_ending_does_not_count() {
	let layout = layout();
	let path = session_secret_path(&layout.data);
	std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
	let exact = format!("{}\n", "b".repeat(32));
	std::fs::write(&path, &exact).expect("write");
	run(&layout, NOW);
	assert_eq!(text(&path), exact);
}

/// The key 0.14.0 wrote has no `grants`. `stack update` writes them, which
/// changes nothing the key reaches, and keeps the secret and the expiry.
#[test]
fn panel_key_old_shape_is_upgraded() {
	let layout = layout();
	run(&layout, NOW);
	let path = layout.data.join("api_keys.toml");
	let mut table: toml::Table = toml::from_str(&text(&path)).expect("parse");
	for key in table["keys"].as_array_mut().expect("keys") {
		key.as_table_mut().expect("table").remove("grants");
	}
	std::fs::write(&path, toml::to_string(&table).expect("write")).expect("rewrite");
	let before = row(&layout);
	assert!(before.grants.is_empty(), "written the way 0.14.0 writes it");
	let report = run(&layout, NOW + DAY);
	let after = row(&layout);
	assert_eq!(
		after.grants,
		["manage:read", "manage:write", "mail:read", "mail:write"]
	);
	assert_eq!(after.scopes, ["read", "write"]);
	assert_eq!(
		(after.hash, after.expires_at),
		(before.hash, before.expires_at)
	);
	assert_eq!(kinds(&report)[0].0, "reused");
}

/// The key is the same key before and after: no `api_keys` warning names it.
#[test]
fn panel_key_in_both_shapes_is_the_panels_and_nothing_else_is() {
	let layout = layout();
	run(&layout, NOW);
	let key = row(&layout);
	assert!(key.spans_manage_and_mail(), "it reaches both, on purpose");
	// A narrower grant set under the same label is another key: refused.
	let mut store = ApiKeyStore::open(&layout.data).expect("open");
	store
		.set_scopes(
			LABEL,
			&["manage:read".to_string(), "manage:write".to_string()],
		)
		.expect("set");
	let message = refusal(&layout, NOW);
	assert!(
		message.contains("other settings than the panel's"),
		"{message}"
	);
}
