//! `stack update` keeps the split as the stack runs it, and the switch
//! moves the credential between the two services.

use super::{regenerate, regenerate_with};
use crate::cli::init::answers::DnsAnswers;
use crate::cli::init::apply::listeners_to_write;
use crate::cli::init::compose::{render_for, stack_answers};

fn answers(certs: bool) -> crate::cli::init::Answers {
	let mut answers = stack_answers();
	answers.services.certs = certs;
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".into(),
		zone: "example.org".into(),
		token_env: Some("EPI_DNS_TOKEN".into()),
		token_file: Some("/secure/dns/token".into()),
		..Default::default()
	});
	answers
}

#[test]
fn a_split_stack_regenerates_byte_for_byte_with_the_credential_in_certs() {
	let answers = answers(true);
	let written = render_for(&answers, true).expect("render");
	let listeners = listeners_to_write(&answers).expect("listeners");
	let again = regenerate(&answers.data_dir, &listeners, &written).expect("regenerate");
	assert_eq!(again.text, written);
}

#[test]
fn turning_the_split_on_and_off_moves_the_credential_between_services() {
	let listeners = listeners_to_write(&answers(false)).expect("listeners");
	let data_dir = answers(false).data_dir;
	let whole = render_for(&answers(false), true).expect("render");
	let split = render_for(&answers(true), true).expect("render");

	let on = regenerate_with(&data_dir, &listeners, &whole, Some(true)).expect("on");
	assert_eq!(on.text, split);
	let off = regenerate_with(&data_dir, &listeners, &split, Some(false)).expect("off");
	assert_eq!(off.text, whole);
}

/// `mail` of a split stack mounts `<data_dir>/acme` read-only at its own
/// path, the shape a token file has; it must not be read back as one.
#[test]
fn the_shared_pair_directory_is_not_taken_for_a_token() {
	let mut answers = answers(true);
	answers.dns = None;
	let written = render_for(&answers, true).expect("render");
	let listeners = listeners_to_write(&answers).expect("listeners");
	let off =
		regenerate_with(&answers.data_dir, &listeners, &written, Some(false)).expect("regenerate");
	assert_eq!(
		off.text,
		render_for(&stack_answers(), true).expect("render")
	);
	assert!(!off.text.contains("/var/lib/epistle/acme"), "{}", off.text);
}
