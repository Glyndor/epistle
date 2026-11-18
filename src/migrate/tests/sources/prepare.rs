//! A long plan, from a hostile file, against the checks that decide what an
//! import changes.

use super::bounded;
use crate::migrate::import::{Account, Plan, apply};

fn configuration(dir: &std::path::Path) -> std::path::PathBuf {
	let data = dir.join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	let file = dir.join("mail.toml");
	std::fs::write(
		&file,
		format!(
			"hostname = \"mail.new.example\"\ndata_dir = \"{}\"\ndomains = []\n",
			data.display()
		),
	)
	.expect("config");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	file
}

#[test]
fn a_long_plan_of_domains_and_accounts_is_checked_in_linear_time() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = configuration(dir.path());
	let mut plan = Plan::default();
	for index in 0..60_000 {
		// Not through add_domain: this case is about the checks in prepare.
		plan.domains.push(format!("d{index}.example"));
		plan.accounts.push(Account {
			name: format!("u{index}"),
			addresses: vec![format!("u{index}@d{index}.example")],
			catch_all: Vec::new(),
			display_name: None,
		});
	}
	let prepared = bounded(move || {
		let _dir = dir;
		apply::prepare(&plan, &file, false).expect("prepare")
	});
	assert_eq!(prepared.outcome.domains_added.len(), 60_000);
	assert_eq!(prepared.outcome.accounts_added.len(), 60_000);
}
