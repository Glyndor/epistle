use super::*;
use crate::config::ListenerKind;

fn fixture(extra: &str) -> tempfile::NamedTempFile {
	let file = tempfile::NamedTempFile::new().unwrap();
	fs::write(file.path(), format!("hostname = \"mail.example.org\"\ndomains = [\"example.org\"]\ndata_dir = \"/var/lib/epistle\"\n{extra}\n[tls]\ncert_file = \"/cert.pem\"\nkey_file = \"/key.pem\"\n[api]\ntoken_hash = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n[[listeners]]\nkind = \"smtp\"\naddr = \"0.0.0.0\"\n")).unwrap();
	file
}

#[test]
fn service_listener_edits_each_kind_independently() {
	for kind in [
		ListenerKind::Imap,
		ListenerKind::Imaps,
		ListenerKind::Submission,
		ListenerKind::Submissions,
		ListenerKind::Pop3s,
		ListenerKind::ManageSieve,
		ListenerKind::WebDav,
		ListenerKind::Api,
	] {
		let file = fixture("max_connections_per_listener = 12345");
		let changed = set_listener_enabled(file.path(), kind, true).unwrap();
		assert!(
			changed,
			"enabling an absent listener must change the config"
		);
		let cfg = Config::load(file.path()).unwrap();
		assert_eq!(
			cfg.listeners.len(),
			2,
			"enable must add exactly one listener"
		);
		let listener = &cfg.listeners[1];
		assert_eq!(listener.kind, kind, "enable must add the selected kind");
		assert_eq!(listener.socket_addr().port(), kind.default_port());
		assert_eq!(
			listener.addr.to_string(),
			if kind == ListenerKind::Api {
				"127.0.0.1"
			} else {
				"0.0.0.0"
			}
		);
		assert!(set_listener_enabled(file.path(), kind, false).unwrap());
		assert_eq!(
			Config::load(file.path()).unwrap().listeners.len(),
			1,
			"disable must remove the selected listener"
		);
		let raw: toml::Value = toml::from_str(&fs::read_to_string(file.path()).unwrap()).unwrap();
		assert_eq!(
			raw["max_connections_per_listener"].as_integer(),
			Some(12345),
			"other keys must survive listener edits"
		);
	}
}

#[test]
fn service_listener_splits_pairs_and_preserves_custom_sockets() {
	for (plain, secure) in [
		(ListenerKind::Imap, ListenerKind::Imaps),
		(ListenerKind::Submission, ListenerKind::Submissions),
	] {
		let file = fixture("");
		let extra = format!(
			"\n[[listeners]]\nkind = \"{}\"\naddr = \"::\"\nport = 19999\n[[listeners]]\nkind = \"{}\"\naddr = \"::\"\n",
			secure.as_str(),
			plain.as_str()
		);
		let mut contents = fs::read_to_string(file.path()).unwrap();
		contents.push_str(&extra);
		fs::write(file.path(), contents).unwrap();
		assert!(
			set_listener_enabled(file.path(), plain, false).unwrap(),
			"disabling the plain sibling must change the config"
		);
		let cfg = Config::load(file.path()).unwrap();
		assert_eq!(cfg.listeners.len(), 2);
		assert_eq!(
			cfg.listeners[1].kind, secure,
			"disabling a plain service must preserve its TLS sibling"
		);
		assert_eq!(cfg.listeners[1].socket_addr().port(), 19999);
		assert!(set_listener_enabled(file.path(), plain, true).unwrap());
		assert!(set_listener_enabled(file.path(), secure, false).unwrap());
		assert_eq!(Config::load(file.path()).unwrap().listeners[1].kind, plain);
	}
}

#[test]
fn service_listener_smtp_refusal_leaves_file_untouched() {
	let file = fixture("");
	let before = fs::read(file.path()).unwrap();
	let result = set_listener_enabled(file.path(), ListenerKind::Smtp, false);
	assert_eq!(
		result.err().map(|e| e.to_string()).as_deref(),
		Some("the candidate config is invalid: smtp cannot be disabled: inbound mail needs it"),
		"SMTP refusal must explain the inbound mail requirement"
	);
	assert!(
		fs::read(file.path()).unwrap() == before,
		"SMTP refusal must leave all bytes untouched"
	);
}

#[test]
fn service_listener_idempotence_preserves_bytes_and_mtime() {
	let file = fixture("# keep on a no-op");
	let before = fs::read(file.path()).unwrap();
	let modified = fs::metadata(file.path()).unwrap().modified().unwrap();
	assert_eq!(
		set_listener_enabled(file.path(), ListenerKind::Smtp, true).ok(),
		Some(false),
		"enabling an existing listener must report unchanged"
	);
	assert!(!set_listener_enabled(file.path(), ListenerKind::Api, false).unwrap());
	assert!(
		fs::read(file.path()).unwrap() == before,
		"no-op must preserve original bytes"
	);
	assert_eq!(
		fs::metadata(file.path()).unwrap().modified().unwrap(),
		modified,
		"no-op must not replace the file"
	);
}

#[test]
fn service_listener_invalid_candidate_leaves_file_untouched() {
	let file = fixture("");
	let original = fs::read_to_string(file.path()).unwrap().replace(
		"[tls]\ncert_file = \"/cert.pem\"\nkey_file = \"/key.pem\"\n",
		"",
	);
	fs::write(file.path(), &original).unwrap();
	let result = set_listener_enabled(file.path(), ListenerKind::Imaps, true);
	assert_eq!(
		result.err().map(|e| e.to_string()).as_deref(),
		Some(
			"the candidate config is invalid: invalid configuration: listener 0.0.0.0:993 requires a [tls] section (logins never cross plaintext)"
		),
		"invalid listener candidate must use the normal loader diagnostic"
	);
	assert!(
		fs::read(file.path()).unwrap() == original.as_bytes(),
		"invalid candidate must leave the file untouched"
	);
}
