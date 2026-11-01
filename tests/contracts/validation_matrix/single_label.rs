//! The single-label domain rule, driven through every surface that can
//! receive one.
//!
//! A domain of one label (`localhost`, `intranet`) is a legal DNS name and
//! a legal RFC 5321 mailbox, but RFC 5321 section 2.3.5 says only fully
//! qualified names appear in an SMTP transaction, so mail for it never
//! reaches the public internet. epistle refuses one everywhere an address
//! or a domain is created or configured, and says why in the same words.
//!
//! This file holds the answer each surface gives, so a surface that starts
//! accepting one turns the build red instead of waiting for the next audit.
//!
//! Declared from `tests/contracts/validation_matrix.rs`; see that file for why a
//! module under `tests/` that is not a test target of its own is a module
//! rather than a file.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::common::{Row, matrix, store};
use epistle::config::Config;
use epistle::domain;
use epistle::smtp::address::Address;

/// The wording every refusal uses. The rule is one (`crate::domain::normalize`
/// refuses a domain with no dot), so the wording is one too.
const REFUSAL: &str = "needs at least one dot";

/// The surfaces this table measures, in the order the columns are read.
const PATHS: [&str; 11] = [
	"domain",
	"address",
	"store",
	"config-domain",
	"config-account",
	"config-alias",
	"config-forward",
	"cli-account",
	"cli-alias",
	"cli-domain",
	"init",
];

/// What one surface answered for a domain of one label: whether it took
/// it, and the message it refused it with when it names a rule.
struct Answer {
	accepted: bool,
	message: Option<String>,
}

impl Answer {
	/// A surface that took the value.
	fn accepted() -> Self {
		Self {
			accepted: true,
			message: None,
		}
	}

	/// A surface that refused. `message` is `None` when the surface does
	/// not speak to an operator (the rule itself and the address parser).
	fn refused(message: Option<String>) -> Self {
		Self {
			accepted: false,
			message,
		}
	}

	/// A surface that refused with a message, or that took the value when
	/// there is none.
	fn from_message(message: Option<String>) -> Self {
		match message {
			Some(message) => Self::refused(Some(message)),
			None => Self::accepted(),
		}
	}

	/// A surface that answers yes or no without a message.
	fn yes_no(accepted: bool) -> Self {
		if accepted {
			Self::accepted()
		} else {
			Self::refused(None)
		}
	}
}

/// A config file the loader accepts: owner-only permissions and a data
/// directory that exists.
pub(super) fn write_config(dir: &Path, body: &str) -> PathBuf {
	let data = dir.join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	let path = dir.join("mail.toml");
	std::fs::write(&path, body.replace("{data}", &data.to_string_lossy())).expect("write config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path
}

/// The message a config file is refused with, or `None` when it loads.
pub(super) fn config_refusal(body: &str) -> Option<String> {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = write_config(dir.path(), body);
	match Config::load(&path) {
		Ok(_) => None,
		Err(error) => Some(error.to_string()),
	}
}

/// Run the binary with `args` and return whether it took the value and
/// what it said.
pub(super) fn epistle(args: &[&str]) -> (bool, String) {
	let child = Command::new(env!("CARGO_BIN_EXE_epistle"))
		.args(args)
		.env("NO_COLOR", "1")
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("spawn epistle");
	let output = child.wait_with_output().expect("wait epistle");
	let message = String::from_utf8_lossy(&output.stderr).into_owned();
	(output.status.success(), message)
}

/// A config file the command line reads.
pub(super) fn cli_config(dir: &Path) -> String {
	write_config(
		dir,
		"hostname = \"mail.example.org\"\ndata_dir = \"{data}\"\ndomains = [\"example.org\"]\n",
	)
	.to_string_lossy()
	.into_owned()
}

/// The answer `epistle account add` gives for a single-label address.
fn cli_account(label: &str) -> Answer {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = cli_config(dir.path());
	let address = format!("user@{label}");
	let (accepted, message) = epistle(&[
		"account",
		"--config",
		&config,
		"add",
		"torre",
		"--address",
		&address,
	]);
	Answer::from_message((!accepted).then_some(message))
}

/// The answer `epistle alias add` gives for a single-label address.
fn cli_alias(label: &str) -> Answer {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = cli_config(dir.path());
	let address = format!("team@{label}");
	let (accepted, message) = epistle(&[
		"alias",
		"--config",
		&config,
		"add",
		&address,
		"alice@example.org",
	]);
	Answer::from_message((!accepted).then_some(message))
}

/// The answer `epistle domain add` gives for a single-label domain.
fn cli_domain(label: &str) -> Answer {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = cli_config(dir.path());
	let (accepted, message) = epistle(&["domain", "--config", &config, "add", label]);
	Answer::from_message((!accepted).then_some(message))
}

/// The answer `epistle init` gives for a single-label domain.
fn init(label: &str) -> Answer {
	let dir = tempfile::tempdir().expect("tempdir");
	let data = dir.path().join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	let answers = dir.path().join("answers.toml");
	std::fs::write(
		&answers,
		format!(
			"mode = \"manual\"\nhostname = \"mail.example.org\"\ndomains = [\"{label}\"]\n\
			 public_ipv4 = \"8.8.8.8\"\ndata_dir = \"{}\"\nconfig_path = \"{}\"\n\
			 image = \"localhost/epistle:dev\"\n\n[services]\ndatabase = false\n",
			data.to_string_lossy(),
			dir.path().join("mail.toml").to_string_lossy(),
		),
	)
	.expect("write answers");
	let (accepted, message) = epistle(&["init", "--answers", answers.to_str().expect("path")]);
	Answer::from_message((!accepted).then_some(message))
}

/// A domain of one label is refused by every surface that creates or
/// configures an address or a domain, and every refusal that reaches the
/// operator names the rule.
#[test]
fn a_single_label_domain_is_refused_everywhere_it_is_created() {
	let mut rows = Vec::new();
	for label in ["localhost", "intranet", "example"] {
		let address = format!("user@{label}");
		let (_, account_store) = store();
		let store_answer =
			match account_store.validate_for_add("torre", std::slice::from_ref(&address)) {
				Ok(()) => Answer::accepted(),
				Err(error) => Answer::refused(Some(error.to_string())),
			};
		let answers = vec![
			// The rule itself and the address parser that reads it: neither
			// reaches an operator, so neither carries a message.
			Answer::yes_no(domain::normalize(label).is_ok()),
			Answer::yes_no(Address::parse(&address).is_ok()),
			store_answer,
			// The configuration file.
			Answer::from_message(config_refusal(&format!(
				"hostname = \"mail.example.org\"\ndata_dir = \"{{data}}\"\ndomains = [\"{label}\"]\n"
			))),
			Answer::from_message(config_refusal(&format!(
				"hostname = \"mail.example.org\"\ndata_dir = \"{{data}}\"\ndomains = [\"example.org\"]\n\
				 [[accounts]]\nname = \"torre\"\naddresses = [\"{address}\"]\n"
			))),
			Answer::from_message(config_refusal(&format!(
				"hostname = \"mail.example.org\"\ndata_dir = \"{{data}}\"\ndomains = [\"example.org\"]\n\
				 [[alias]]\naddress = \"team@{label}\"\nmembers = [\"alice@example.org\"]\n"
			))),
			Answer::from_message(config_refusal(&format!(
				"hostname = \"mail.example.org\"\ndata_dir = \"{{data}}\"\ndomains = [\"example.org\"]\n\
				 srs_secret = \"secret\"\n[[accounts]]\nname = \"torre\"\n\
				 addresses = [\"torre@example.org\"]\nforward = [\"{address}\"]\n"
			))),
			// The command line.
			cli_account(label),
			cli_alias(label),
			cli_domain(label),
			// The first-run assistant.
			init(label),
		];
		rows.push(Row {
			what: "one label",
			value: label.to_string(),
			accepted: answers.iter().map(|answer| answer.accepted).collect(),
		});
		// Every refusal that carries a message names the rule and the domain.
		for (path, answer) in PATHS.iter().zip(answers.iter()) {
			let Some(message) = &answer.message else {
				continue;
			};
			assert!(
				message.contains(REFUSAL),
				"{path} refused {label:?} with {message:?}, which does not name the rule"
			);
			assert!(
				message.contains(label),
				"{path} refused {label:?} with {message:?}, which does not name the domain"
			);
		}
	}
	for row in &rows {
		for (index, path) in PATHS.iter().enumerate() {
			assert!(
				!row.accepted[index],
				"{path} accepted the single-label domain {:?}{}",
				row.value,
				matrix(&rows, &PATHS)
			);
		}
	}
}
