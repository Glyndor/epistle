use super::*;

const DAY: u64 = 86_400;
const NOW: u64 = 1_800_000_000;

/// The rules of a configuration with two tenants: `acme` owns `a.example` and
/// `b.example`, `solo` owns `c.example`, and `d.example` has none.
fn rules(queue: &str) -> Rules {
	rules_with(
		"[[tenant]]\nname = 'acme'\ndomains = ['a.example', 'b.example']\n\
[[tenant]]\nname = 'solo'\ndomains = ['c.example']\n",
		queue,
	)
}

fn rules_with(tenants: &str, queue: &str) -> Rules {
	let dir = tempfile::tempdir().expect("directory");
	let text = format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['a.example', 'b.example', 'c.example', 'd.example']\n{tenants}[queue]\n{queue}",
		dir.path()
	);
	let config = crate::config::Config::parse_text(&text, std::path::Path::new("mail.toml"))
		.expect("config");
	Rules::from_config(&config)
}

fn list() -> (tempfile::TempDir, SuppressionList) {
	let dir = tempfile::tempdir().expect("tempdir");
	let list = SuppressionList::open(dir.path()).expect("open");
	(dir, list)
}

const TARGET: &str = "gone@remote.example";

#[test]
fn by_default_a_bounce_blocks_the_account_and_its_tenant_and_nobody_else() {
	let (_dir, list) = list();
	let rules = rules("");
	list.publish_tenants(&rules).expect("publish");
	assert!(
		list.record_bounce(&rules, "alice@a.example", TARGET, "550 no such user", NOW)
			.expect("record")
	);
	// The account.
	assert!(list.is_blocked("alice@a.example", TARGET, NOW));
	// Another account of the same domain, and one of the tenant's other domain.
	assert!(list.is_blocked("bob@a.example", TARGET, NOW));
	assert!(list.is_blocked("bob@b.example", TARGET, NOW));
	// A domain of another tenant, and one with no tenant, are not blocked.
	assert!(!list.is_blocked("carol@c.example", TARGET, NOW));
	assert!(!list.is_blocked("dave@d.example", TARGET, NOW));
	// And the shared list stays empty.
	assert!(!list.is_suppressed(TARGET));
}

#[test]
fn the_scopes_are_the_operators_choice() {
	let (_dir, list) = list();
	let account_only = rules("suppression_scopes = ['account']\n");
	list.record_bounce(&account_only, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	assert!(list.is_blocked("alice@a.example", TARGET, NOW));
	assert!(
		!list.is_blocked("bob@a.example", TARGET, NOW),
		"another account is not blocked"
	);
	let server = rules("suppression_scopes = ['server']\n");
	list.record_bounce(
		&server,
		"alice@a.example",
		"other@remote.example",
		"550",
		NOW,
	)
	.expect("record");
	assert!(list.is_blocked("dave@d.example", "other@remote.example", NOW));
	assert!(list.is_suppressed("other@remote.example"));
}

#[test]
fn a_sender_with_no_account_or_tenant_has_nowhere_to_record_a_default_bounce() {
	let (_dir, list) = list();
	let rules = rules("");
	list.record_bounce(&rules, "", TARGET, "550", NOW)
		.expect("record");
	list.record_bounce(&rules, "dave@d.example", TARGET, "550", NOW)
		.expect("record");
	assert!(
		list.is_blocked("dave@d.example", TARGET, NOW),
		"the account of dave"
	);
	assert!(!list.is_blocked("erin@d.example", TARGET, NOW));
	assert!(!list.is_blocked("", TARGET, NOW));
}

#[test]
fn an_entry_stops_blocking_when_its_lifetime_ends_and_is_swept_after() {
	let (_dir, list) = list();
	let rules = rules("suppression_days = 90\n");
	list.record_bounce(&rules, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	let entry = list.entry_for("alice@a.example", TARGET).expect("entry");
	assert!(entry.automatic);
	assert_eq!(entry.until, Some(NOW + 90 * DAY));
	assert!(list.is_blocked("alice@a.example", TARGET, NOW + 90 * DAY - 1));
	assert!(!list.is_blocked("alice@a.example", TARGET, NOW + 90 * DAY));
	assert!(!list.is_blocked("bob@b.example", TARGET, NOW + 91 * DAY));
	// Ignored at once, removed by the sweep, and the sweep is bounded.
	assert!(list.entry_for("alice@a.example", TARGET).is_some());
	assert_eq!(list.sweep_expired(&rules, NOW + 89 * DAY, 100), 0);
	assert_eq!(
		list.sweep_expired(&rules, NOW + 91 * DAY, 1),
		1,
		"the cap holds"
	);
	assert_eq!(list.sweep_expired(&rules, NOW + 91 * DAY, 100), 1);
	assert!(list.entry_for("alice@a.example", TARGET).is_none());
}

#[test]
fn an_entry_with_no_lifetime_lasts_for_ever_as_it_always_did() {
	let (_dir, list) = list();
	let rules = rules("");
	list.record_bounce(&rules, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	assert_eq!(
		list.entry_for("alice@a.example", TARGET)
			.expect("entry")
			.until,
		None
	);
	assert!(list.is_blocked("alice@a.example", TARGET, NOW + 10_000 * DAY));
	assert_eq!(list.sweep_expired(&rules, NOW + 10_000 * DAY, 100), 0);
}

#[test]
fn nothing_is_suppressed_until_the_threshold_of_bounces() {
	let (_dir, list) = list();
	let rules = rules("suppression_threshold = 3\n");
	for (count, at) in [NOW, NOW + 1, NOW + 2].into_iter().enumerate() {
		let suppressed = list
			.record_bounce(&rules, "alice@a.example", TARGET, "550", at)
			.expect("record");
		assert_eq!(suppressed, count == 2, "bounce {}", count + 1);
		assert_eq!(list.is_blocked("alice@a.example", TARGET, at), count == 2);
	}
	// The count starts again after the suppression ends.
	assert!(
		!list
			.record_bounce(
				&rules,
				"alice@a.example",
				"other@remote.example",
				"550",
				NOW
			)
			.expect("record")
	);
}

#[test]
fn bounces_outside_the_window_do_not_count() {
	let (_dir, list) = list();
	let rules = rules("suppression_threshold = 2\nsuppression_days = 10\n");
	assert!(
		!list
			.record_bounce(&rules, "alice@a.example", TARGET, "550", NOW)
			.expect("record")
	);
	// Eleven days later the first one no longer counts.
	assert!(
		!list
			.record_bounce(&rules, "alice@a.example", TARGET, "550", NOW + 11 * DAY)
			.expect("record")
	);
	assert!(
		list.record_bounce(&rules, "alice@a.example", TARGET, "550", NOW + 11 * DAY + 1)
			.expect("record")
	);
	// A different sender counts on its own.
	assert!(
		!list
			.record_bounce(&rules, "bob@a.example", "x@remote.example", "550", NOW)
			.expect("record")
	);
}

#[test]
fn a_bounce_never_replaces_an_entry_added_by_hand() {
	let (_dir, list) = list();
	let rules = rules("suppression_scopes = ['server', 'account']\nsuppression_days = 30\n");
	list.suppress_because(TARGET, "kept by the operator", NOW - DAY);
	list.suppress_for_because("alice@a.example", TARGET, "kept by alice", NOW - DAY);
	list.record_bounce(&rules, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	for entry in [
		list.entry(TARGET).expect("global"),
		list.entry_for("alice@a.example", TARGET).expect("account"),
	] {
		assert!(!entry.automatic);
		assert_eq!(entry.until, None);
		assert!(
			entry
				.reason
				.as_deref()
				.is_some_and(|reason| reason.starts_with("kept by"))
		);
	}
	assert!(list.is_blocked("alice@a.example", TARGET, NOW + 1000 * DAY));
	assert_eq!(list.sweep_expired(&rules, NOW + 1000 * DAY, 100), 0);
}

#[test]
fn a_marker_from_an_older_release_still_blocks_for_ever_and_a_new_one_reads_back_in_the_old_format()
{
	let (dir, list) = list();
	let name = digest_name(TARGET);
	std::fs::write(
		dir.path().join("suppression").join(&name),
		format!("{TARGET}\n{NOW}\t550 gone\n"),
	)
	.expect("write");
	let old = list.entry(TARGET).expect("old marker");
	assert!(!old.automatic && old.until.is_none());
	assert!(list.is_blocked("anyone@d.example", TARGET, NOW + 10_000 * DAY));
	// A release that does not know the third line reads the first two.
	let content = automatic_marker(TARGET, "550 gone", NOW, NOW + DAY);
	let first_two: Vec<&str> = content.lines().take(2).collect();
	assert_eq!(first_two, [TARGET, format!("{NOW}\t550 gone").as_str()]);
}

#[test]
fn a_domain_that_moves_to_another_tenant_does_not_hand_over_the_old_tenants_entries() {
	let (_dir, list) = list();
	let before = rules("");
	list.publish_tenants(&before).expect("publish");
	list.record_bounce(&before, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	assert!(list.is_blocked("bob@b.example", TARGET, NOW));
	// a.example now belongs to `solo`, b.example stays with `acme`.
	let after = rules_with(
		"[[tenant]]\nname = 'acme'\ndomains = ['b.example']\n[[tenant]]\nname = 'solo'\ndomains = ['a.example', 'c.example']\n",
		"",
	);
	list.publish_tenants(&after).expect("publish");
	assert!(
		!list.is_blocked("zed@a.example", TARGET, NOW),
		"the new owner does not inherit"
	);
	assert!(!list.is_blocked("carol@c.example", TARGET, NOW));
	assert!(
		list.is_blocked("bob@b.example", TARGET, NOW),
		"the tenant's own domains still do"
	);
}

#[test]
fn a_domain_that_leaves_every_tenant_has_no_tenant_scope() {
	let (_dir, list) = list();
	let before = rules("");
	list.publish_tenants(&before).expect("publish");
	list.record_bounce(&before, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	let after = rules_with("[[tenant]]\nname = 'acme'\ndomains = ['b.example']\n", "");
	list.publish_tenants(&after).expect("publish");
	assert!(!list.is_blocked("zed@a.example", TARGET, NOW));
	// Only the account the bounce came from keeps its own entry.
	assert!(list.is_blocked("alice@a.example", TARGET, NOW));
}

#[test]
fn a_tenant_that_is_gone_loses_its_entries_and_another_tenants_stay() {
	let (_dir, list) = list();
	let before = rules("");
	list.publish_tenants(&before).expect("publish");
	list.record_bounce(&before, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	list.record_bounce(&before, "carol@c.example", TARGET, "550", NOW)
		.expect("record");
	assert_eq!(list.list_for_tenant("acme"), [TARGET]);
	let after = rules_with("[[tenant]]\nname = 'solo'\ndomains = ['c.example']\n", "");
	list.publish_tenants(&after).expect("publish");
	assert!(list.list_for_tenant("acme").is_empty());
	assert_eq!(list.list_for_tenant("solo"), [TARGET]);
}

#[test]
fn a_tenant_entry_is_ignored_until_the_membership_is_published() {
	let (_dir, list) = list();
	let rules = rules("");
	list.record_bounce(&rules, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	assert!(!list.is_blocked("bob@b.example", TARGET, NOW));
}

#[test]
fn a_tenant_entry_can_be_removed_and_one_of_another_tenant_is_not_touched() {
	let (_dir, list) = list();
	let rules = rules("");
	list.publish_tenants(&rules).expect("publish");
	list.record_bounce(&rules, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	list.record_bounce(&rules, "carol@c.example", TARGET, "550", NOW)
		.expect("record");
	list.remove_for_tenant("ACME", TARGET).expect("remove");
	assert!(list.list_for_tenant("acme").is_empty());
	assert_eq!(list.list_for_tenant("solo"), [TARGET]);
	list.remove_for_tenant("acme", TARGET)
		.expect("removing twice is fine");
}

#[test]
fn removing_an_account_removes_its_bounce_counts() {
	let (dir, list) = list();
	let rules = rules("suppression_threshold = 3\n");
	list.record_bounce(&rules, "alice@a.example", TARGET, "550", NOW)
		.expect("record");
	let counts = dir
		.path()
		.join("suppression/pending")
		.join(digest_name("alice@a.example"));
	assert!(counts.is_dir());
	list.remove_all_for("alice@a.example").expect("remove");
	assert!(!counts.exists());
}
