use crate::config::{Config, ConfigError};

fn load(settings: &str) -> Result<Config, ConfigError> {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\", \"example.com\"]\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"example.com\"]\n{settings}"
	)
	.expect("write config");
	Config::load(file.path())
}

fn refused(settings: &str, needle: &str) {
	let error = load(settings).expect_err("must be refused").to_string();
	assert!(
		error.contains(needle),
		"{error:?} should mention {needle:?}"
	);
}

#[test]
fn a_well_formed_scope_of_each_kind_loads() {
	let config = load(
		"[[antispam_scope]]\ntenant = \"acme\"\n[antispam_scope.senders]\ndeny = [\"*.example.net\"]\n\
		 [[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\nallow = [\"example.net\"]\n\
		 [[antispam_scope]]\naccount = \"bob\"\n[antispam_scope.senders]\ndeny_recipients = [\"a@example.net\"]",
	)
	.expect("loads");
	assert_eq!(config.antispam_scopes.len(), 3);
}

#[test]
fn a_scope_names_exactly_one_target() {
	refused(
		"[[antispam_scope]]\n[antispam_scope.senders]\ndeny = [\"example.net\"]",
		"exactly one of tenant, domain or account",
	);
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\naccount = \"bob\"",
		"exactly one of tenant, domain or account",
	);
}

#[test]
fn the_target_must_exist_and_be_declared_once() {
	refused(
		"[[antispam_scope]]\ndomain = \"example.net\"",
		"not declared",
	);
	refused("[[antispam_scope]]\ntenant = \"nobody\"", "not declared");
	refused(
		"[[antispam_scope]]\naccount = \"bob\"\n[[antispam_scope]]\naccount = \"bob\"",
		"more than once",
	);
}

#[test]
fn a_bad_entry_is_refused_and_names_the_list() {
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\ndeny = [\"*bad.example.net\"]",
		"deny",
	);
	refused("[antispam.senders]\nallow = [\"not an address\"]", "allow");
}

#[test]
fn the_same_entry_in_allow_and_deny_of_one_scope_is_refused() {
	refused(
		"[antispam.senders]\nallow = [\"Example.net\"]\ndeny = [\"example.net\"]",
		"both allow and deny",
	);
}

#[test]
fn a_scope_cannot_loosen_the_attachment_policy_of_the_server() {
	let server = "[attachments]\nmode = \"quarantine\"\nmacros = \"quarantine\"\nmax_attachment_bytes = 2000000\n";
	refused(
		&format!(
			"{server}[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.attachments]\nmode = \"flag\""
		),
		"weaker",
	);
	refused(
		&format!(
			"{server}[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.attachments]\nmacros = \"flag\""
		),
		"weaker",
	);
	refused(
		&format!(
			"{server}[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.attachments]\nmax_attachment_bytes = 3000000"
		),
		"above the server",
	);
	// The control: the same section tightening loads.
	load(&format!("{server}[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.attachments]\nmode = \"reject\"\nmacros = \"quarantine\"\nmax_attachment_bytes = 1000000"))
		.expect("tightening loads");
}

#[test]
fn attachment_scopes_need_a_server_policy_that_is_on() {
	refused(
		"[attachments]\nmode = \"off\"\n[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.attachments]\nmode = \"reject\"",
		"only tightens",
	);
}

#[test]
fn bad_attachment_values_are_refused() {
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.attachments]\nblock_mime_types = [\"Image\"]",
		"block_mime_types",
	);
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.attachments]\nblock_extensions = [\"a b\"]",
		"block_extensions",
	);
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.attachments]\nmax_attachment_bytes = 0",
		"max_attachment_bytes",
	);
	refused(
		"[attachments]\nblock_mime_types = [\"x\"]",
		"block_mime_types",
	);
	refused(
		"[attachments]\nmax_attachment_bytes = 0",
		"max_attachment_bytes",
	);
}

#[test]
fn thresholds_and_delays_of_a_scope_are_checked() {
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\nbayes_junk_at = 1.5",
		"bayes_junk_at",
	);
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\nbayes_junk_at = 0.9\nbayes_reject_at = 0.8",
		"at least bayes_junk_at",
	);
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\ngreylist_delay_secs = 90000",
		"greylist_delay_secs",
	);
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\nfirst_time_sender_delay_secs = 301",
		"first_time_sender_delay_secs",
	);
	// The control: values at the limits load.
	let config = load(
		"[[antispam_scope]]\ndomain = \"example.org\"\nbayes_junk_at = 0.9\nbayes_reject_at = 0.9\n\
		 greylist_delay_secs = 86400\nfirst_time_sender_delay_secs = 300",
	)
	.expect("limits load");
	assert!(config.greylisting_anywhere());
	assert!(!load("").expect("loads").greylisting_anywhere());
}

#[test]
fn the_checks_of_a_scope_are_validated() {
	for value in ["\"block\"", "\"Reject\"", "true", "1"] {
		for key in ["dkim", "arc", "reverse_dns"] {
			refused(
				&format!(
					"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.checks]\n{key} = {value}"
				),
				key,
			);
		}
	}
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.checks]\ndkim_require_signature = \"yes\"",
		"dkim_require_signature",
	);
	refused(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.checks]\nspf = \"reject\"",
		"spf",
	);
	let config = load(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.checks]\n\
		 dkim = \"reject\"\ndkim_require_signature = true\narc = \"annotate\"\nreverse_dns = \"off\"",
	)
	.expect("loads");
	let checks = config.antispam_scopes[0].checks;
	assert_eq!(checks.dkim, Some(crate::config::CheckPolicy::Reject));
	assert_eq!(checks.dkim_require_signature, Some(true));
	assert_eq!(checks.arc, Some(crate::config::CheckPolicy::Annotate));
	assert_eq!(checks.reverse_dns, Some(crate::config::CheckPolicy::Off));
	assert!(
		load("[[antispam_scope]]\ndomain = \"example.org\"")
			.expect("loads")
			.antispam_scopes[0]
			.checks
			.is_empty()
	);
}
