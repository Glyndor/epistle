//! Init writes the implicit-TLS listeners (`imaps` 993, `submissions`
//! 465) alongside the STARTTLS ones (`imap` 143, `submission` 587).
//! Most mail clients default to the implicit ports, so init has to
//! bind both flavours or operators ship a server that real-world
//! clients cannot connect to. The same bind address the STARTTLS
//! listener uses applies, and compose publishes both ports.
//!
//! Sister to `apply_bind_tests.rs` and `apply_listeners_lines_tests.rs`
//! because those files are already at the per-file line ceiling and
//! this surface is its own focused seam.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::apply_config;
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
		acme: None,
	}
}

fn cert_key_ed() -> (PathBuf, PathBuf, PathBuf) {
	(
		PathBuf::from("/var/lib/epistle/keys/cert.pem"),
		PathBuf::from("/var/lib/epistle/keys/key.pem"),
		PathBuf::from("/var/lib/epistle/keys/s1.pem"),
	)
}

/// When the operator turns `services.imap` on, the desired config
/// carries both the STARTTLS listener on 143 and the implicit-TLS
/// listener on 993, each on the mail bind address. Most mail
/// clients default to 993, so init has to bind it; the STARTTLS
/// listener still ships so legacy clients (and `epistle local`)
/// can connect.
#[test]
fn build_config_writes_imap_and_imaps_when_imap_is_on() {
	let mut answers = answers_minimal();
	answers.services = Services {
		imap: true,
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
		.expect("build_config with imap on");
	let kinds: Vec<&str> = desired.listeners.iter().map(|l| l.kind.as_str()).collect();
	assert!(
		kinds.contains(&"imap"),
		"imap listener must be written when services.imap is on; got {kinds:?}"
	);
	assert!(
		kinds.contains(&"imaps"),
		"imaps listener must be written when services.imap is on (most mail clients default to 993); got {kinds:?}"
	);
	let imaps = desired
		.listeners
		.iter()
		.find(|l| l.kind == "imaps")
		.expect("imaps listener");
	assert_eq!(
		imaps.addr, mail_addr,
		"imaps listener must carry the mail bind address, got {}",
		imaps.addr
	);
	// The STARTTLS sibling carries the same address so an operator
	// who sees only one of the two in the plan can still tell the
	// two apart by port, not by bind address.
	let imap = desired
		.listeners
		.iter()
		.find(|l| l.kind == "imap")
		.expect("imap listener");
	assert_eq!(
		imap.addr, mail_addr,
		"imap listener must carry the mail bind address, got {}",
		imap.addr
	);
	// Belt and braces: the two are distinct rows in the desired
	// listeners vec, even though they share a bind address. A
	// regression that reused the same `DesiredListener` instance
	// for both kinds (and produced the same row twice) would still
	// bind the right ports at runtime but would lose one of the
	// two lines in the rendered config. The kind field is the
	// distinction we want to lock in.
	assert_ne!(
		imap.kind, imaps.kind,
		"imap and imaps are distinct rows in the listeners vec"
	);
}

/// When the operator turns `services.submission` on, the desired
/// config carries both the STARTTLS listener on 587 and the
/// implicit-TLS listener on 465, each on the mail bind address.
/// Modern clients negotiate `SUBMISSIONS` (465) before falling
/// back to STARTTLS on 587, so init has to bind 465 to reach the
/// clients that ship without a STARTTLS fallback configured.
#[test]
fn build_config_writes_submission_and_submissions_when_submission_is_on() {
	let mut answers = answers_minimal();
	answers.services = Services {
		imap: false,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
		database: false,
	};
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with submission on");
	let kinds: Vec<&str> = desired.listeners.iter().map(|l| l.kind.as_str()).collect();
	assert!(
		kinds.contains(&"submission"),
		"submission listener must be written when services.submission is on; got {kinds:?}"
	);
	assert!(
		kinds.contains(&"submissions"),
		"submissions listener must be written when services.submission is on (modern clients prefer implicit TLS); got {kinds:?}"
	);
	let submissions = desired
		.listeners
		.iter()
		.find(|l| l.kind == "submissions")
		.expect("submissions listener");
	assert_eq!(
		submissions.addr, mail_addr,
		"submissions listener must carry the mail bind address, got {}",
		submissions.addr
	);
	let submission = desired
		.listeners
		.iter()
		.find(|l| l.kind == "submission")
		.expect("submission listener");
	assert_eq!(
		submission.addr, mail_addr,
		"submission listener must carry the mail bind address, got {}",
		submission.addr
	);
}

/// When the operator turns `services.imap` off, init does not write
/// an `imaps` listener either. The implicit port has no value on its
/// own, and a listener on 993 without a matching STARTTLS listener
/// would accept only clients that can already speak TLS implicitly —
/// the inverse of the on-case test. The off-case is its own
/// assertion so a regression that always writes the implicit
/// listener fails here, not in the on-case test where the asymmetry
/// could hide.
#[test]
fn build_config_omits_imap_and_imaps_when_imap_is_off() {
	let mut answers = answers_minimal();
	answers.services = Services {
		imap: false,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
		database: false,
	};
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with imap off");
	let kinds: Vec<&str> = desired.listeners.iter().map(|l| l.kind.as_str()).collect();
	assert!(
		!kinds.contains(&"imap"),
		"imap listener must not be written when services.imap is off; got {kinds:?}"
	);
	assert!(
		!kinds.contains(&"imaps"),
		"imaps listener must not be written when services.imap is off; got {kinds:?}"
	);
}

/// When the operator turns `services.submission` off, init does not
/// write a `submissions` listener either. Symmetric with the imap
/// off-case test above.
#[test]
fn build_config_omits_submission_and_submissions_when_submission_is_off() {
	let mut answers = answers_minimal();
	answers.services = Services {
		imap: true,
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
		.expect("build_config with submission off");
	let kinds: Vec<&str> = desired.listeners.iter().map(|l| l.kind.as_str()).collect();
	assert!(
		!kinds.contains(&"submission"),
		"submission listener must not be written when services.submission is off; got {kinds:?}"
	);
	assert!(
		!kinds.contains(&"submissions"),
		"submissions listener must not be written when services.submission is off; got {kinds:?}"
	);
}

/// The compose file's `mail.ports:` array publishes 993 and 465
/// alongside 143 and 587. A publish map that omits the implicit
/// ports would forward traffic to a port nothing listens on inside
/// the container, even after the config side gained the listener.
/// The compose writer derives the published-port list from the
/// listener set init just wrote, so an asymmetry between the two
/// is what this test pins down.
#[test]
fn compose_publishes_imaps_and_submissions_alongside_imap_and_submission() {
	use crate::cli::init::compose::{render, stack_answers};

	let value = render(&stack_answers(), true);
	let ports: Vec<String> = value["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	let must = ["25:25", "143:143", "465:465", "587:587", "993:993"];
	for entry in must {
		assert!(
			ports.contains(&entry.to_string()),
			"compose ports must publish {entry} when the matching listener is on; got {ports:?}"
		);
	}
	// The api listener is closed to the network on loopback, so it
	// is not in the publish map; the assertion that 8025 is absent
	// is the negative half of the test and stops a regression that
	// publishes the management API from leaking through the
	// implicit-TLS work.
	assert!(
		!ports.iter().any(|p| p == "8025:8025"),
		"the management API is loopback-only and must not be published; got {ports:?}"
	);
	// Reference the import so the file's cargo check stays clean if
	// the loopback constant is later split into a helper.
	let _ = IpAddr::V4(Ipv4Addr::LOCALHOST);
}
