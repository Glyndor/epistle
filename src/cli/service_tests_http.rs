//! The listeners whose transport is HTTP without TLS, and the two files a
//! service command reconciles: the configuration and the generated compose
//! file it is paired with.

use super::tests_command::fixture;
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
	let compose = super::super::init::compose_file_path(&config.data_dir);
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
	let request = super::super::service_set::Request {
		name: ServiceName::Webdav,
		bind: None,
		port: Some(9000),
	};
	super::super::service_set::run(
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

/// `compose.yaml` is often a symlink into another directory of the
/// installation. Every writer of the pair reads and replaces it through the
/// link, the way it did before the staged transaction, instead of refusing it
/// as a file it must not follow.
#[cfg(unix)]
#[test]
fn a_generated_file_that_is_a_symlink_is_still_written() {
	let (_dir, file) = fixture();
	let mut text = std::fs::read_to_string(file.path()).unwrap();
	text.push_str("[tls]\ncert_file = '/cert.pem'\nkey_file = '/key.pem'\n");
	std::fs::write(file.path(), text).unwrap();
	let config = Config::load(file.path()).unwrap();
	let compose = super::super::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	let target = compose.with_file_name("generated.yaml");
	std::fs::write(&target, r#"{"services":{"mail":{"ports":["25:25"]}}}"#).unwrap();
	std::os::unix::fs::symlink(&target, &compose).unwrap();
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
	assert_eq!(
		ports_of(&compose),
		serde_json::json!(["25:25", "143:143"]),
		"a symlinked generated file must be written like any other"
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
	let compose = super::super::init::compose_file_path(&config.data_dir);
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
	assert_eq!(
		ports_of(&compose),
		serde_json::json!(["25:25", "1465:1465", "143:143"]),
		"the command brings the two files together"
	);
}
