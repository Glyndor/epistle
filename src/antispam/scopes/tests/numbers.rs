use super::*;
use crate::config::Config;

fn scopes(extra: &str) -> Scopes {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.com\", \"example.org\", \"example.net\"]\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"example.com\"]\n{extra}"
	)
	.expect("write config");
	Scopes::from_config(&Config::load(file.path()).expect("config loads"))
}

fn target(domain: &str, account: Option<&str>) -> Target {
	Target {
		domain: domain.into(),
		account: account.map(str::to_string),
	}
}

const SERVER: SpamNumbers = SpamNumbers {
	junk_at: 0.95,
	reject_at: None,
	greylist_delay_secs: 0,
	first_time_delay_secs: 0,
};

#[test]
fn without_scopes_the_server_numbers_stand() {
	let scopes = scopes("");
	assert_eq!(
		scopes.spam_numbers(&[target("example.org", None)], SERVER),
		SERVER
	);
	assert_eq!(scopes.spam_numbers(&[], SERVER), SERVER);
}

#[test]
fn the_most_specific_scope_wins() {
	let scopes = scopes(
		"[[antispam_scope]]\ntenant = \"acme\"\nbayes_junk_at = 0.9\nbayes_reject_at = 0.99\ngreylist_delay_secs = 60\n\
		 [[antispam_scope]]\ndomain = \"example.com\"\nbayes_junk_at = 0.8\n\
		 [[antispam_scope]]\naccount = \"bob\"\nbayes_junk_at = 0.7\ngreylist_delay_secs = 0",
	);
	let numbers = |target: Target| scopes.spam_numbers(&[target], SERVER);
	// The domain overrides the tenant's threshold and keeps its other values.
	let domain = numbers(target("example.com", None));
	assert_eq!(domain.junk_at, 0.8);
	assert_eq!(domain.reject_at, Some(0.99));
	assert_eq!(domain.greylist_delay_secs, 60);
	// The account overrides the domain, and `0` turns greylisting off there.
	let bob = numbers(target("example.com", Some("bob")));
	assert_eq!(bob.junk_at, 0.7);
	assert_eq!(bob.greylist_delay_secs, 0);
	// Another domain is untouched.
	assert_eq!(numbers(target("example.org", None)), SERVER);
}

#[test]
fn a_scope_can_turn_greylisting_on_where_the_server_has_it_off() {
	let scopes = scopes(
		"[[antispam_scope]]\ndomain = \"example.org\"\ngreylist_delay_secs = 300\nfirst_time_sender_delay_secs = 20",
	);
	let numbers = scopes.spam_numbers(&[target("example.org", None)], SERVER);
	assert_eq!(numbers.greylist_delay_secs, 300);
	assert_eq!(numbers.first_time_delay_secs, 20);
}

#[test]
fn a_reject_threshold_is_never_below_the_junk_one() {
	// The domain raises the junk threshold above the server's reject one.
	let server = SpamNumbers {
		reject_at: Some(0.97),
		..SERVER
	};
	let scopes = scopes("[[antispam_scope]]\ndomain = \"example.org\"\nbayes_junk_at = 0.99");
	let numbers = scopes.spam_numbers(&[target("example.org", None)], server);
	assert_eq!(numbers.junk_at, 0.99);
	assert_eq!(numbers.reject_at, Some(0.99));
}

#[test]
fn several_recipients_get_the_strictest_numbers() {
	let scopes = scopes(
		"[[antispam_scope]]\ndomain = \"example.org\"\nbayes_junk_at = 0.8\ngreylist_delay_secs = 30\n\
		 [[antispam_scope]]\ndomain = \"example.net\"\nbayes_junk_at = 0.99\nbayes_reject_at = 0.995\ngreylist_delay_secs = 90",
	);
	let both = scopes.spam_numbers(
		&[target("example.org", None), target("example.net", None)],
		SERVER,
	);
	assert_eq!(both.junk_at, 0.8, "the lower threshold");
	assert_eq!(
		both.reject_at,
		Some(0.995),
		"a rejection when any recipient has one"
	);
	assert_eq!(both.greylist_delay_secs, 90, "the longer delay");
	// The control: each recipient alone keeps its own.
	assert_eq!(
		scopes
			.spam_numbers(&[target("example.net", None)], SERVER)
			.junk_at,
		0.99
	);
}
