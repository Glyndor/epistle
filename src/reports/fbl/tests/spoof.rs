//! A report that comes from nobody the operator enrolled, or that this
//! server did not prove came from one, changes nothing however well formed
//! it is. `sender_verified` is set on every message here: it is the relaxed
//! flag, and none of these may lean on it.

use super::*;

fn untouched(message: &AcceptedMessage, fbl: &Fbl) {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Metrics::new();
	let outcome = process(fbl, dir.path(), &directory(), message, Some(&metrics));
	assert_eq!(outcome, Outcome::Untrusted, "{}", message.reverse_path);
	let list = SuppressionList::open(dir.path()).expect("list");
	assert!(list.entries_for("alice").is_empty());
	assert!(list.entries().is_empty());
	assert_eq!(metrics.snapshot()["fbl_complaints"], 0);
}

fn from(sender: &str, header: &str) -> AcceptedMessage {
	let mut message = stamped_with(valid_report("victim@example.com"), header);
	message.reverse_path = sender.into();
	message
}

#[test]
fn a_legitimate_report_from_the_enrolled_address_is_counted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let message = verified(valid_report("victim@example.com"));
	assert!(matches!(
		process(&fbl(""), dir.path(), &directory(), &message, None),
		Outcome::Counted { .. }
	));
}

#[test]
fn a_dkim_pass_by_the_enrolled_domain_is_enough_without_spf() {
	let dir = tempfile::tempdir().expect("tempdir");
	let message = stamped_with(
		valid_report("victim@example.com"),
		&stamp(None, Some("arf.example.net")),
	);
	assert!(matches!(
		process(&fbl(""), dir.path(), &directory(), &message, None),
		Outcome::Counted { .. }
	));
}

#[test]
fn an_enrolled_address_that_this_server_did_not_prove_is_a_forgery() {
	// Nothing stamped at all, then a stamp that only says fail or none.
	let mut message = verified(valid_report("victim@example.com"));
	message.data = valid_report("victim@example.com");
	untouched(&message, &fbl(""));
	for header in [
		"Authentication-Results: mail.example.org; spf=fail smtp.mailfrom=arf.example.net\r\n",
		"Authentication-Results: mail.example.org; spf=none; dkim=none\r\n",
	] {
		untouched(&from(PROVIDER, header), &fbl(""));
	}
}

#[test]
fn an_authentication_result_another_server_wrote_is_not_ours() {
	let header =
		"Authentication-Results: mx.elsewhere.example; spf=pass smtp.mailfrom=arf.example.net\r\n";
	untouched(&from(PROVIDER, header), &fbl(""));
}

#[test]
fn spf_for_another_domain_proves_nothing() {
	// The relaxed flag would pass a sibling of the same organization.
	let header = stamp(Some("mail.example.net"), None);
	untouched(&from(PROVIDER, &header), &fbl(""));
}

#[test]
fn a_dkim_pass_by_another_domain_proves_nothing() {
	for d in ["example.net", "evil.example", "eu.arf.example.net"] {
		let header = stamp(None, Some(d));
		untouched(&from(PROVIDER, &header), &fbl(""));
	}
}

#[test]
fn a_verified_sender_that_is_no_enrolled_provider_is_ignored() {
	for sender in [
		"fbl@elsewhere.example",
		"other@arf.example.net",
		"fbl@arf.example.net.evil.example",
		"",
	] {
		let domain = sender.rsplit_once('@').map_or("", |(_, d)| d);
		let header = stamp(Some(domain), Some(domain));
		untouched(&from(sender, &header), &fbl(""));
	}
}

#[test]
fn a_local_account_that_logged_in_cannot_suppress_anyone() {
	// The session logged in, so the server stamped nothing about the sender.
	let mut message = from("mallory@example.org", "");
	message.sender_verified = true;
	untouched(&message, &fbl(""));
}

#[test]
fn nobody_is_trusted_until_a_provider_is_enrolled() {
	let reports: Reports = toml::from_str("fbl_mailbox = \"fbl@example.org\"").expect("reports");
	let fbl = Fbl::new(&reports, HOSTNAME, vec!["s1".to_string()]).expect("fbl");
	untouched(&verified(valid_report("victim@example.com")), &fbl);
}

#[test]
fn an_enrolled_domain_covers_its_subdomains_only_with_a_proof_for_them() {
	let enrolled: Reports =
		toml::from_str("fbl_mailbox = \"fbl@example.org\"\nfbl_senders = [\"arf.example.net\"]")
			.expect("reports");
	let wide = Fbl::new(&enrolled, HOSTNAME, vec!["s1".to_string()]).expect("fbl");
	let dir = tempfile::tempdir().expect("tempdir");
	let proved = from(
		"x@eu.arf.example.net",
		&stamp(Some("eu.arf.example.net"), None),
	);
	assert!(matches!(
		process(&wide, dir.path(), &directory(), &proved, None),
		Outcome::Counted { .. }
	));
	let lookalike = from(
		"x@evilarf.example.net",
		&stamp(Some("evilarf.example.net"), None),
	);
	untouched(&lookalike, &wide);
	let unproved = from(
		"x@eu.arf.example.net",
		&stamp(Some("arf.example.net"), None),
	);
	untouched(&unproved, &wide);
}

#[test]
fn only_the_report_mailbox_is_read() {
	let fbl = fbl("");
	assert!(fbl.is_mailbox("FBL@example.org"));
	assert!(!fbl.is_mailbox("alice@example.org"));
}
