use super::*;
use crate::config::Config;

fn parse(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\", \"other.example\"]\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"example.org\"]\n{extra}"
	))
	.expect("parse")
}

fn refusal(extra: &str) -> String {
	parse(extra)
		.validate_undo_send()
		.expect_err("must be refused")
		.to_string()
}

#[test]
fn absent_section_holds_nothing() {
	let config = parse("");
	assert_eq!(config.queue.undo_send, UndoSend::default());
	assert_eq!(config.queue.undo_send.delay_secs, 0);
	assert_eq!(config.queue.undo_send.max_secs, DEFAULT_MAX_SECS);
	assert!(config.validate_undo_send().is_ok());
}

#[test]
fn a_delay_up_to_the_ceiling_is_accepted_and_one_over_is_refused() {
	let ok = parse("[queue.undo_send]\ndelay_secs = 120\n");
	assert!(ok.validate_undo_send().is_ok());
	let message = refusal("[queue.undo_send]\ndelay_secs = 121\n");
	assert!(
		message.contains("delay_secs (121) must not exceed max_secs (120)"),
		"{message}"
	);
}

#[test]
fn the_ceiling_itself_is_bounded() {
	let ok = parse("[queue.undo_send]\nmax_secs = 600\ndelay_secs = 600\n");
	assert!(ok.validate_undo_send().is_ok());
	let message = refusal("[queue.undo_send]\nmax_secs = 601\n");
	assert!(
		message.contains("max_secs must be between 0 and 600"),
		"{message}"
	);
}

#[test]
fn a_scope_over_the_ceiling_is_refused_at_the_ceiling_accepted() {
	let ok = parse(
		"[queue.undo_send]\nmax_secs = 90\n[[queue.undo_send.scope]]\ndomain = \"example.org\"\ndelay_secs = 90\n",
	);
	assert!(ok.validate_undo_send().is_ok());
	let message = refusal(
		"[queue.undo_send]\nmax_secs = 90\n[[queue.undo_send.scope]]\ndomain = \"example.org\"\ndelay_secs = 91\n",
	);
	assert!(
		message.contains("delay_secs (91) must not exceed max_secs (90)"),
		"{message}"
	);
}

#[test]
fn a_scope_names_exactly_one_declared_target_once() {
	let none = refusal("[[queue.undo_send.scope]]\ndelay_secs = 10\n");
	assert!(
		none.contains("exactly one of tenant, domain or account"),
		"{none}"
	);
	let two = refusal(
		"[[queue.undo_send.scope]]\ndomain = \"example.org\"\naccount = \"a\"\ndelay_secs = 10\n",
	);
	assert!(
		two.contains("exactly one of tenant, domain or account"),
		"{two}"
	);
	let unknown_domain =
		refusal("[[queue.undo_send.scope]]\ndomain = \"nowhere.example\"\ndelay_secs = 10\n");
	assert!(
		unknown_domain.contains("is not declared in this file"),
		"{unknown_domain}"
	);
	let unknown_tenant =
		refusal("[[queue.undo_send.scope]]\ntenant = \"ghost\"\ndelay_secs = 10\n");
	assert!(
		unknown_tenant.contains("is not declared in this file"),
		"{unknown_tenant}"
	);
	let twice = refusal(
		"[[queue.undo_send.scope]]\naccount = \"a\"\ndelay_secs = 10\n[[queue.undo_send.scope]]\naccount = \"A\"\ndelay_secs = 20\n",
	);
	assert!(twice.contains("is declared more than once"), "{twice}");
	let fine = parse(
		"[[queue.undo_send.scope]]\ntenant = \"acme\"\ndelay_secs = 10\n[[queue.undo_send.scope]]\naccount = \"a\"\ndelay_secs = 0\n",
	);
	assert!(fine.validate_undo_send().is_ok());
}
