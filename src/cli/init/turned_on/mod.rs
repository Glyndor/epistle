//! What `init` turned on, and how each thing is turned off.
//!
//! The report says what was written; this says what the written server now
//! does that it did not do before, and the one edit that stops each thing.
//! The lines are advisory: nothing here changes what the run does.

use std::io::Write;

use super::Answers;

/// The lines that close a successful run.
pub(super) fn render(answers: &Answers, out: &mut dyn Write) {
	let config = answers.config_path.display();
	let _ = writeln!(out, "init turned on:");
	let _ = writeln!(
		out,
		"  the public endpoint on port 443 (autoconfigs): the client setup documents and the \
		 MTA-STS policy"
	);
	let _ = writeln!(
		out,
		"    to turn it off: remove the [[listeners]] entry with kind = \"autoconfigs\" from \
		 {config}"
	);
	let _ = writeln!(
		out,
		"  the MTA-STS policy, written at {}",
		crate::cli::init::apply::mta_sts_policy_dir(&answers.data_dir).display()
	);
	let _ = writeln!(
		out,
		"    to turn it off: remove the [mta_sts] section from {config}"
	);
	let _ = writeln!(
		out,
		"  the autoconfig and autodiscover names, and the _autoconfig._tcp locator, of every \
		 hosted domain"
	);
	let _ = writeln!(
		out,
		"    to turn them off: add \"client-locators\" to the [dns_publish] skip list in {config}"
	);
	if let Some(mailbox) = answers
		.first_account
		.as_ref()
		.and_then(|first| first.fbl_address())
	{
		fbl_steps(&mailbox, &config.to_string(), out);
	}
}

/// What is left to do once the complaint mailbox exists: the providers send
/// nothing until the address is enrolled, and the server believes no report
/// until the sending address of each provider is named.
fn fbl_steps(mailbox: &str, config: &str, out: &mut dyn Write) {
	let _ = writeln!(
		out,
		"  the complaint mailbox {mailbox} ([reports] in {config})"
	);
	let _ = writeln!(
		out,
		"    it reads nothing yet: enrol {mailbox} with each provider, then name the address the \
		 provider sends the reports from in fbl_senders"
	);
	let _ = writeln!(
		out,
		"    Yahoo: Complaint Feedback Loop, add the domain and subscribe {mailbox}; Microsoft: \
		 JMRP, in SNDS, with {mailbox} as the report address"
	);
	let _ = writeln!(
		out,
		"    the steps of each provider are in docs/operations/providers.md and the settings in \
		 docs/configuration.md#reports"
	);
	let _ = writeln!(
		out,
		"    to turn it off: remove the [reports] section from {config}"
	);
}
