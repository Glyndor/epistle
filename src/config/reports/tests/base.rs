use super::*;

fn config(reports: &str) -> crate::config::Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\"]\n[reports]\n{reports}"
	))
	.expect("parse")
}

#[test]
fn the_receiver_is_off_until_a_mailbox_is_named() {
	let reports = Reports::default();
	assert_eq!(reports.fbl_mailbox(), None);
	assert!(!reports.suppresses());
	assert!(!reports.trusts_sender("fbl@arf.example.net"));
}

#[test]
fn suppression_follows_the_mailbox_unless_it_is_switched_off() {
	assert!(
		config("fbl_mailbox = \"fbl@example.org\"")
			.reports
			.suppresses()
	);
	let off = config("fbl_mailbox = \"fbl@example.org\"\nfbl_suppress = false");
	assert!(!off.reports.suppresses());
}

#[test]
fn the_mailbox_is_compared_in_lowercase() {
	let reports = config("fbl_mailbox = \"FBL@Example.org\"").reports;
	assert_eq!(reports.fbl_mailbox().as_deref(), Some("fbl@example.org"));
}

#[test]
fn an_enrolled_address_or_domain_is_trusted_and_nothing_else() {
	let reports = config(
		"fbl_mailbox = \"fbl@example.org\"\n\
		 fbl_senders = [\"fbl@arf.example.net\", \"complaints.example.com\"]",
	)
	.reports;
	assert!(reports.trusts_sender("FBL@arf.example.net"));
	assert!(!reports.trusts_sender("other@arf.example.net"));
	assert!(reports.trusts_sender("anyone@complaints.example.com"));
	assert!(reports.trusts_sender("anyone@eu.complaints.example.com"));
	assert!(!reports.trusts_sender("anyone@notcomplaints.example.com"));
	assert!(!reports.trusts_sender("anyone@example.com"));
	assert!(!reports.trusts_sender(""));
}

#[test]
fn a_valid_section_loads() {
	config("").validate().expect("absent is valid");
	config(
		"fbl_mailbox = \"fbl@example.org\"\nfbl_senders = [\"arf.example.net\", \"fbl@mail.example.net\"]",
	)
	.validate()
	.expect("a hosted mailbox and enrolled senders are valid");
}

#[test]
fn a_mailbox_that_cannot_receive_is_refused_at_load() {
	for bad in [
		"fbl",
		"fbl@example.net",
		"Reports <fbl@example.org>",
		"a@b@example.org",
		"fbl@example.org\\r\\nBcc: x@example.net",
	] {
		let error = config(&format!("fbl_mailbox = \"{bad}\""))
			.validate()
			.expect_err(bad)
			.to_string();
		assert!(error.contains("[reports] fbl_mailbox"), "{bad}: {error}");
	}
}

#[test]
fn the_settings_that_act_on_a_mailbox_need_one() {
	for line in ["fbl_suppress = true", "fbl_senders = [\"arf.example.net\"]"] {
		let error = config(line).validate().expect_err(line).to_string();
		assert!(error.contains("need fbl_mailbox"), "{line}: {error}");
	}
}

#[test]
fn a_sender_that_is_not_an_address_or_a_domain_is_refused() {
	for bad in ["not a domain", "a@b@example.net", "<fbl@example.net>"] {
		let line = format!("fbl_mailbox = \"fbl@example.org\"\nfbl_senders = [\"{bad}\"]");
		assert!(config(&line).validate().is_err(), "{bad}");
	}
}

#[test]
fn a_provider_on_a_hosted_domain_is_refused() {
	for bad in ["example.org", "fbl@example.org", "eu.example.org"] {
		let line = format!("fbl_mailbox = \"fbl@example.org\"\nfbl_senders = [\"{bad}\"]");
		let error = config(&line).validate().expect_err(bad).to_string();
		assert!(error.contains("hosted domain"), "{bad}: {error}");
	}
}

#[test]
fn a_public_mailbox_provider_cannot_be_enrolled() {
	for bad in [
		"gmail.com",
		"fbl@yahoo.com",
		"Outlook.com",
		"complaints@mail.ru",
	] {
		let line = format!("fbl_mailbox = \"fbl@example.org\"\nfbl_senders = [\"{bad}\"]");
		let error = config(&line).validate().expect_err(bad).to_string();
		assert!(error.contains("public mailbox provider"), "{bad}: {error}");
	}
	// The address a provider's loop sends from, on a domain of its own, is fine.
	config("fbl_mailbox = \"fbl@example.org\"\nfbl_senders = [\"arf.mail.yahoo.com\"]")
		.validate()
		.expect("a dedicated subdomain is allowed");
}

#[test]
fn the_hourly_cap_defaults_and_cannot_be_zero() {
	let reports = config("fbl_mailbox = \"fbl@example.org\"").reports;
	assert_eq!(reports.max_per_hour(), DEFAULT_MAX_PER_HOUR);
	let set = config("fbl_mailbox = \"fbl@example.org\"\nfbl_max_per_hour = 7");
	assert_eq!(set.reports.max_per_hour(), 7);
	let zero = config("fbl_mailbox = \"fbl@example.org\"\nfbl_max_per_hour = 0");
	assert!(zero.validate().is_err());
}

#[test]
fn an_unknown_key_is_refused() {
	let parsed: Result<Reports, _> = toml::from_str("fbl_mailboxes = []");
	assert!(parsed.is_err());
}
