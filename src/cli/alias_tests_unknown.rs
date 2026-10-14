//! `epistle alias`: an unknown name is a refusal (exit code 2), the same
//! way `epistle account disable` refuses one. The message is preserved
//! exactly so scripts that parse `error: alias X not found` keep working.
//!
//! Lives in a sibling so `alias_tests.rs` stays under the per-file code-line
//! budget.

use std::io::Write;
use std::process::ExitCode;

use super::*;
use crate::config::Config;

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn load(path: &Path) -> Config {
	Config::load(path).expect("config must load")
}

fn assert_unknown_alias_is_refused(action: AliasCli) {
	let (_dir, file) = fixture("");
	let code = run(file.path(), action, false);
	assert_eq!(
		code,
		ExitCode::from(super::super::exit::REFUSED),
		"an unknown alias must exit 2 (usage error)"
	);
}

#[test]
fn show_unknown_alias_exits_two() {
	assert_unknown_alias_is_refused(AliasCli::Show {
		address: "ghost@example.org".to_string(),
		json: false,
	});
}

#[test]
fn show_unknown_alias_json_exits_two() {
	assert_unknown_alias_is_refused(AliasCli::Show {
		address: "ghost@example.org".to_string(),
		json: true,
	});
}

#[test]
fn remove_unknown_alias_exits_two() {
	assert_unknown_alias_is_refused(AliasCli::Remove {
		address: "ghost@example.org".to_string(),
		yes: true,
	});
}

#[test]
fn member_add_unknown_alias_exits_two() {
	assert_unknown_alias_is_refused(AliasCli::Member(MemberArgs {
		action: MemberSubcommand::Add {
			address: "ghost@example.org".to_string(),
			member: "alice@example.org".to_string(),
		},
	}));
}

#[test]
fn member_remove_unknown_alias_exits_two() {
	assert_unknown_alias_is_refused(AliasCli::Member(MemberArgs {
		action: MemberSubcommand::Remove {
			address: "ghost@example.org".to_string(),
			member: "alice@example.org".to_string(),
		},
	}));
}

#[test]
fn sender_add_unknown_alias_exits_two() {
	assert_unknown_alias_is_refused(AliasCli::Sender(SenderArgs {
		action: SenderSubcommand::Add {
			address: "ghost@example.org".to_string(),
			sender: "alice@example.org".to_string(),
		},
	}));
}

#[test]
fn sender_remove_unknown_alias_exits_two() {
	assert_unknown_alias_is_refused(AliasCli::Sender(SenderArgs {
		action: SenderSubcommand::Remove {
			address: "ghost@example.org".to_string(),
			sender: "alice@example.org".to_string(),
		},
	}));
}

#[test]
fn enable_unknown_alias_exits_two() {
	assert_unknown_alias_is_refused(AliasCli::Enable {
		address: "ghost@example.org".to_string(),
	});
}

#[test]
fn disable_unknown_alias_exits_two() {
	assert_unknown_alias_is_refused(AliasCli::Disable {
		address: "ghost@example.org".to_string(),
	});
}

#[test]
fn unknown_alias_keeps_its_message_and_leaves_the_config_alone() {
	// Scripts branch on the exit code, people read the message: the
	// refusal keeps the phrasing a log scan for "not found" matches.
	let (_dir, file) = fixture("");
	let before = std::fs::read_to_string(file.path()).expect("read config");
	let outcome = super::execute(
		file.path(),
		AliasCli::Disable {
			address: "ghost@example.org".to_string(),
		},
		false,
	);
	let super::Outcome::Refusal(message) = outcome else {
		panic!("an unknown alias must be a refusal");
	};
	assert_eq!(message, "alias ghost@example.org not found");
	assert_eq!(
		std::fs::read_to_string(file.path()).expect("read config"),
		before,
		"the file must not change when the name is unknown"
	);
	let _ = load;
}
