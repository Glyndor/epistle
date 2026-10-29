//! The listeners whose transport is HTTP without TLS, and the two files a
//! service command reconciles: the configuration and the generated compose
//! file it is paired with.

use super::command::fixture;
use super::*;

/// The `ports:` array the generated file of a stack carries.
fn ports_of(path: &std::path::Path) -> serde_json::Value {
	let document: serde_json::Value =
		serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
	document["services"]["mail"]["ports"].clone()
}

/// WebDAV answers HTTP that no TLS transport protects, so `enable` starts it
/// on loopback and the generated map publishes nothing for it. The operator
/// opens it on the host with `set --bind`, and a port of the listener is a
/// plain move instead of the refusal a wildcard bind used to produce.
#[test]
fn a_listener_without_tls_is_enabled_on_loopback_and_keeps_a_port_move() {
	let (_dir, file) = fixture();
	let config = Config::load(file.path()).unwrap();
	let compose = super::super::super::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(&compose, r#"{"services":{"mail":{"ports":["25:25"]}}}"#).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	execute_with(
		file.path(),
		ServiceCli::Enable {
			name: ServiceName::Webdav,
		},
		false,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	)
	.unwrap();
	let listeners = Config::load(file.path()).unwrap().listeners;
	assert_eq!(
		listeners[1].kind,
		ListenerKind::WebDav,
		"enable must add the listener"
	);
	assert_eq!(
		listeners[1].addr.to_string(),
		"127.0.0.1",
		"a listener that serves HTTP without TLS starts closed to the network"
	);
	assert_eq!(
		ports_of(&compose),
		serde_json::json!(["25:25"]),
		"the map must not publish an unencrypted transport on every host address"
	);
	let request = super::super::super::service::set::Request {
		name: ServiceName::Webdav,
		bind: None,
		port: Some(9000),
	};
	super::super::super::service::set::run(
		file.path(),
		request,
		false,
		false,
		&mut Vec::new(),
		&mut Vec::new(),
		|_, _| ExitCode::SUCCESS,
	)
	.unwrap();
	assert_eq!(
		Config::load(file.path()).unwrap().listeners[1]
			.socket_addr()
			.port(),
		9000,
		"a port move on a loopback listener is a move, not a refusal"
	);
	assert_eq!(ports_of(&compose), serde_json::json!(["25:25"]));
}

/// A stack written before the loopback rule carries web-dav on every host
/// address. Any command that re-renders the map takes that publication away,
/// and the operator has to read which port moved and where it went, instead of
/// being told the two files disagree when they do not.
#[test]
fn a_wide_publication_of_a_listener_without_tls_is_narrowed_out_loud() {
	let (_dir, file) = fixture();
	let mut text = std::fs::read_to_string(file.path()).unwrap();
	text.push_str("[tls]\ncert_file = '/cert.pem'\nkey_file = '/key.pem'\n");
	std::fs::write(file.path(), text).unwrap();
	execute_with(
		file.path(),
		ServiceCli::Enable {
			name: ServiceName::Webdav,
		},
		false,
		false,
		&mut Vec::new(),
		&mut Vec::new(),
		|_, _| ExitCode::SUCCESS,
	)
	.unwrap();
	let config = Config::load(file.path()).unwrap();
	let compose = super::super::super::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	// What such an install carries: the port of a listener that has no TLS
	// transport published on every address of the host.
	std::fs::write(
		&compose,
		r#"{"services":{"mail":{"ports":["25:25","8090:8090"]}}}"#,
	)
	.unwrap();
	let text = std::fs::read_to_string(file.path()).unwrap();
	let wide = text
		.replace("addr = '127.0.0.1'", "addr = '::'")
		.replace("addr = \"127.0.0.1\"", "addr = \"::\"");
	assert_ne!(
		wide, text,
		"the fixture has to publish web-dav on the network"
	);
	std::fs::write(file.path(), wide).unwrap();
	let mut status = Vec::new();
	execute_with(
		file.path(),
		ServiceCli::Enable {
			name: ServiceName::Pop3,
		},
		false,
		false,
		&mut Vec::new(),
		&mut status,
		|_, _| ExitCode::SUCCESS,
	)
	.unwrap();
	let said = String::from_utf8(status).unwrap();
	assert!(
		said.contains("was published on 8090:8090 on every address of the host")
			&& said.contains("now published on 127.0.0.1:8090:8090"),
		"the command has to say which publication it took away: {said}"
	);
	assert!(
		!said.contains("publish different ports"),
		"what moved is the notice; the two files do not disagree about anything else: {said}"
	);
	assert_eq!(
		ports_of(&compose),
		serde_json::json!(["25:25", "127.0.0.1:8090:8090", "995:995"]),
		"the map carries the narrowed publication once the command is done"
	);
}

/// `compose.yaml` is sometimes a symlink into another directory. The file is
/// read through the link, and the write replaces the link itself with a
/// regular file; the file behind the link is never named by a path that could
/// change between the read and the rename, so it is left as it was.
#[cfg(unix)]
#[test]
fn a_generated_file_that_is_a_symlink_is_read_through_it_and_replaced_by_a_regular_file() {
	let (_dir, file) = fixture();
	let mut text = std::fs::read_to_string(file.path()).unwrap();
	text.push_str("[tls]\ncert_file = '/cert.pem'\nkey_file = '/key.pem'\n");
	std::fs::write(file.path(), text).unwrap();
	let config = Config::load(file.path()).unwrap();
	let compose = super::super::super::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	let elsewhere = config.data_dir.join("generated");
	std::fs::create_dir_all(&elsewhere).unwrap();
	std::fs::write(
		elsewhere.join("compose.yaml"),
		r#"{"services":{"mail":{"ports":["25:25"]}}}"#,
	)
	.unwrap();
	std::os::unix::fs::symlink("../generated/compose.yaml", &compose).unwrap();
	execute_with(
		file.path(),
		ServiceCli::Enable {
			name: ServiceName::Imap,
		},
		false,
		false,
		&mut Vec::new(),
		&mut Vec::new(),
		|_, _| ExitCode::SUCCESS,
	)
	.unwrap();
	assert!(
		!std::fs::symlink_metadata(&compose)
			.unwrap()
			.file_type()
			.is_symlink(),
		"the link is replaced by a regular file, never followed for the write"
	);
	assert_eq!(
		std::fs::read_to_string(elsewhere.join("compose.yaml")).unwrap(),
		r#"{"services":{"mail":{"ports":["25:25"]}}}"#,
		"the file behind the link is left exactly as it was"
	);
	assert_eq!(
		ports_of(&compose),
		serde_json::json!(["25:25", "143:143"]),
		"the new regular file carries the map this command wrote, built from what the link showed"
	);
	assert_eq!(
		std::fs::read_dir(&elsewhere).unwrap().count(),
		1,
		"nothing is staged in the directory the link points at"
	);
}

/// A command killed between its two renames leaves the configuration and the
/// generated map describing different stacks: one file carries the new port
/// and the other the old one. The next command reconciles them and has to say
/// so, because the operator did not ask for the difference.
#[test]
fn a_generated_map_that_contradicts_the_config_is_reported_and_reconciled() {
	let (_dir, file) = fixture();
	let config = Config::load(file.path()).unwrap();
	let compose = super::super::super::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(
		&compose,
		r#"{"services":{"mail":{"ports":["25:25","993:993"]}}}"#,
	)
	.unwrap();
	let mut text = std::fs::read_to_string(file.path()).unwrap();
	text.push_str("[tls]\ncert_file = '/cert.pem'\nkey_file = '/key.pem'\n[[listeners]]\nkind = 'imaps'\naddr = '::'\nport = 1465\n");
	std::fs::write(file.path(), text).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	execute_with(
		file.path(),
		ServiceCli::Enable {
			name: ServiceName::Imap,
		},
		false,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	)
	.unwrap();
	let said = String::from_utf8(status).unwrap();
	assert!(
		said.contains("publish different ports")
			&& said.contains("993:993")
			&& said.contains("1465:1465"),
		"the operator has to hear what the two files disagreed about: {said}"
	);
	assert!(
		!said.contains("interrupted between its two writes"),
		"the warning must not name a cause it can not know: a port edited by hand \
		 leaves the same difference: {said}"
	);
	assert_eq!(
		ports_of(&compose),
		serde_json::json!(["25:25", "1465:1465", "143:143"]),
		"the command brings the two files together"
	);
}
