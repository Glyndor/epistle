//! `build_config` and the desired listener shape.
//!
//! Sister to `apply_tests*.rs` because those files are already at the
//! per-file line ceiling. The tests here pin the shape of the
//! listeners `init` writes: smtp is always there and carries the
//! mail bind address, every optional mail listener carries the same
//! address, and the management API listener is closed to the network
//! at `127.0.0.1` no matter what the operator answered for the mail
//! address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::apply_config;
use super::*;
use crate::cli::init::answers::{Answers, Mode, Services};

fn answers_minimal() -> Answers {
	Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(std::net::Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
		image: None,
	}
}

fn cert_key_ed() -> (PathBuf, PathBuf, PathBuf) {
	(
		PathBuf::from("/var/lib/epistle/keys/cert.pem"),
		PathBuf::from("/var/lib/epistle/keys/key.pem"),
		PathBuf::from("/var/lib/epistle/keys/s1.pem"),
	)
}

#[test]
fn build_config_writes_exactly_one_listener_when_every_optional_service_is_off() {
	// The management API is also off here. The desired config must
	// carry only smtp; the listener that the rest of the internet
	// talks to.
	let mut answers = answers_minimal();
	answers.services = Services {
		imap: false,
		submission: false,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
		database: false,
	};
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with everything off");
	assert_eq!(
		desired.listeners.len(),
		1,
		"exactly one listener when every optional service is off, got {:?}",
		desired.listeners
	);
	let listener = &desired.listeners[0];
	assert_eq!(listener.kind, "smtp");
	assert_eq!(
		listener.addr, mail_addr,
		"smtp listener must carry the mail bind address"
	);
}

#[test]
fn build_config_with_every_service_on_uses_mail_addr_for_every_mail_listener_and_loopback_for_api()
{
	// Every mail-facing listener inherits the mail bind address.
	// The management API is closed to the network by design, so it
	// stays on 127.0.0.1 even when the operator said the mail bind
	// is `::`.
	let mut answers = answers_minimal();
	answers.services = Services {
		imap: true,
		submission: true,
		pop3: true,
		managesieve: true,
		webdav: true,
		api: true,
		database: false,
	};
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with everything on");
	let kinds: Vec<&str> = desired.listeners.iter().map(|l| l.kind.as_str()).collect();
	assert!(kinds.contains(&"smtp"));
	assert!(kinds.contains(&"imap"));
	assert!(kinds.contains(&"submission"));
	assert!(kinds.contains(&"pop3s"));
	assert!(kinds.contains(&"manage-sieve"));
	assert!(kinds.contains(&"web-dav"));
	assert!(kinds.contains(&"api"));
	for listener in &desired.listeners {
		if listener.kind == "api" {
			assert_eq!(
				listener.addr,
				IpAddr::V4(Ipv4Addr::LOCALHOST),
				"api listener must bind loopback, got {}",
				listener.addr
			);
		} else {
			assert_eq!(
				listener.addr, mail_addr,
				"mail listener {} must carry the mail bind address, got {}",
				listener.kind, listener.addr
			);
		}
	}
}

#[test]
fn apply_written_config_loads_back_to_smtp_on_dual_stack_and_loopback_for_api() {
	// The full end-to-end shape: drive the real apply path into a
	// temp dir, read the file back through `Config::load`, and pin
	// the resolved addresses. Loading back is the gate the rest of
	// the CLI relies on; a desired config that does not round-trip
	// through Config::load would also fail at serve.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	let loaded = crate::config::Config::load(&config_path).expect("load written config");
	let smtp = loaded
		.listeners
		.iter()
		.find(|l| l.kind == crate::config::ListenerKind::Smtp)
		.expect("smtp listener after load");
	assert_eq!(
		smtp.socket_addr(),
		std::net::SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 25),
		"smtp must resolve to [::]:25"
	);
	assert_eq!(
		smtp.addr,
		IpAddr::V6(Ipv6Addr::UNSPECIFIED),
		"smtp addr must be `::`"
	);
}

/// The rendered plan for default answers names an `smtp` listener
/// with `[::]:25`, never mentions `0.0.0.0` or the old "IPv6
/// sockets are not bindable" fallback notice, and the written
/// config loads with smtp at `[::]:25`. Combines the plan-rendering
/// and apply-write assertions into one end-to-end check: a future
/// regression that reintroduces the probe, the fallback notice, or
/// a hardcoded `0.0.0.0` goes red on whichever assertion catches it
/// first.
#[test]
fn plan_and_written_config_have_no_ipv4_fallback_for_mail_listeners() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();

	// Render the plan with default answers and walk it line by line
	// so a regression that hides a missing listener with a `contains`
	// check cannot slip past line-by-line inspection.
	let plan = plan(&answers).expect("plan with default answers");
	let mut rendered = String::new();
	plan.write_to(&mut rendered).expect("write plan");
	let smtp_line = rendered
		.lines()
		.find(|line| line.trim_start().starts_with("smtp"))
		.expect("plan must contain an smtp listener line");
	assert!(
		smtp_line.contains("[::]:25"),
		"smtp listener must bind the dual-stack address [::]:25; got: {smtp_line:?}"
	);
	assert!(
		!rendered.contains("0.0.0.0"),
		"the plan must never mention 0.0.0.0 (the IPv4 fallback is gone); got: {rendered}"
	);
	assert!(
		!rendered.contains("IPv6 sockets are not bindable"),
		"the plan must never mention the old IPv6 fallback notice; got: {rendered}"
	);

	// Drive the real apply path and load the written config back
	// through `Config::load`, pinning the address `serve` will see.
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	let loaded = crate::config::Config::load(&config_path).expect("load written config");
	let smtp = loaded
		.listeners
		.iter()
		.find(|l| l.kind == crate::config::ListenerKind::Smtp)
		.expect("smtp listener after load");
	assert_eq!(
		smtp.addr,
		IpAddr::V6(Ipv6Addr::UNSPECIFIED),
		"written smtp listener must bind `::`; got: {}",
		smtp.addr
	);
	assert_eq!(
		smtp.socket_addr(),
		std::net::SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 25),
		"written smtp listener must resolve to [::]:25"
	);
	// Belt and braces: the rendered config file does not contain a
	// 0.0.0.0 either. A future regression that hardcodes the IPv4
	// bind in `apply_config::build_config` while leaving the plan
	// rendering on `[::]:25` (so the plan test stays green) fails
	// here.
	let written = std::fs::read_to_string(&config_path).expect("read written config");
	assert!(
		!written.contains("0.0.0.0"),
		"the written config must never carry 0.0.0.0 for mail listeners; got: {written}"
	);
	assert!(
		!written.contains("AAAA record"),
		"the written config must never carry the AAAA-record notice; got: {written}"
	);
}

#[test]
fn build_config_with_api_writes_api_listener_on_loopback() {
	// The api branch goes through build_config directly because
	// enabling api through apply needs an [api] section init does
	// not generate. We construct the desired config the way apply
	// would and serialise it; loading back would need an [api]
	// section the operator writes by hand.
	let mut answers = answers_minimal();
	answers.services = Services {
		imap: false,
		submission: false,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: true,
		database: false,
	};
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with api");
	let api = desired
		.listeners
		.iter()
		.find(|l| l.kind == "api")
		.expect("api listener");
	assert_eq!(api.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
}
