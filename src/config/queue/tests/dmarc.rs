//! `[queue] dmarc_reports` and `[queue] dmarc_report_from`.

use super::*;

fn config(queue: &str) -> crate::config::Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n[queue]\n{queue}"
	))
	.expect("parse")
}

#[test]
fn dmarc_reports_default_on_and_can_be_turned_off() {
	assert!(Queue::default().dmarc_reports);
	let absent: Queue = toml::from_str("tlsrpt_reports = false").expect("parse");
	assert!(absent.dmarc_reports);
	let off: Queue = toml::from_str("dmarc_reports = false").expect("parse");
	assert!(!off.dmarc_reports);
	assert!(off.tlsrpt_reports, "one switch does not turn the other off");
}

#[test]
fn the_reports_come_from_postmaster_unless_configured() {
	assert_eq!(Queue::default().dmarc_report_from, None);
	assert_eq!(
		config("").dmarc_report_from(),
		"postmaster@mail.example.org"
	);
	assert_eq!(
		config("dmarc_report_from = \"dmarc@example.org\"").dmarc_report_from(),
		"dmarc@example.org"
	);
}

#[test]
fn a_plain_mailbox_is_accepted() {
	config("").validate().expect("absent is valid");
	config("dmarc_report_from = \"dmarc@example.org\"")
		.validate()
		.expect("a plain mailbox is valid");
}

#[test]
fn a_value_that_is_not_one_plain_mailbox_is_refused_at_load() {
	for bad in [
		"dmarc",
		"dmarc@example.org, other@example.net",
		"a@b@example.org",
		"\\\"a b\\\"@example.org",
		"Reports <dmarc@example.org>",
		"dmarc@example.org\\r\\nBcc: victim@example.net",
		"dmarc@example.org\\nBcc: victim@example.net",
		"dmarc@[192.0.2.1]",
	] {
		let error = config(&format!("dmarc_report_from = \"{bad}\""))
			.validate()
			.expect_err(bad)
			.to_string();
		assert!(
			error.contains("[queue] dmarc_report_from") && error.contains("plain mailbox"),
			"{bad}: {error}"
		);
		assert!(
			!error.contains('\r') && !error.contains('\n'),
			"the refusal quotes the value escaped: {error:?}"
		);
	}
}

#[test]
fn a_mailbox_whose_domain_is_not_a_dns_name_is_refused_at_load() {
	for bad in ["dmarc@-example.org", "dmarc@example..org"] {
		let error = config(&format!("dmarc_report_from = \"{bad}\""))
			.validate()
			.expect_err(bad)
			.to_string();
		assert!(
			error.contains("[queue] dmarc_report_from domain"),
			"{bad}: {error}"
		);
	}
}
