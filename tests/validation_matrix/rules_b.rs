//! The boundary table of the name, credential and network rules, driven through
//! every surface that reaches them.
//!
//! The other half is `tests/validation_matrix.rs`, which holds the identity
//! rules. Together they are the premise the validation audit rests on: each
//! case asserts the *observed* answer, and a refusal names the row it belongs
//! to, so a rule that drifts between two surfaces turns the build red.
//!
//! These are the rules that decide what a name may *look like*, and what a
//! credential, a network range or a size is allowed to be.
//!
//! Declared from `tests/validation_matrix.rs` rather than discovered on its
//! own: a file under `tests/` that is not a test target of its own runs only if
//! something names it, which is the orphan `tests/test_discovery_premise.rs`
//! watches for.

use super::common::fixture_password;
use epistle::cidr::Cidr;
use epistle::managesieve::store as sieve_store;
use epistle::password::{self, Policy};
use epistle::util::mailbox_path;
use epistle::util::validation;

#[test]
fn a_sieve_script_name_answers_the_same_for_manage_sieve_and_jmap() {
	// ManageSieve and JMAP share the store, so one check answers both, and the
	// JMAP capability advertises the same octet cap the store enforces.
	assert_eq!(
		sieve_store::MAX_NAME_BYTES,
		200,
		"JMAP advertises maxSizeScriptName and the store enforces MAX_NAME_BYTES"
	);
	for (what, name, accepted) in [
		("empty", "", false),
		("one character", "a", true),
		("plain", "keep-spam", true),
		("a dot", "keep.spam", true),
		("a space inside", "keep spam", true),
		("a space around", " keep ", false),
		("a slash", "keep/spam", false),
		("a backslash", "keep\\spam", false),
		("NUL", "keep\0spam", false),
		("CR LF", "keep\r\nspam", false),
		("a bidi override", "keep\u{202e}spam", false),
		("a right-to-left mark", "keep\u{200f}spam", false),
		("an Arabic letter mark", "keep\u{061c}spam", false),
		("an isolate", "keep\u{2066}spam", false),
		("a line separator", "keep\u{2028}spam", false),
		("non-ASCII", "spam-\u{f1}", true),
		("NFD of n-tilde", "san\u{0303}", false),
		("NFC of n-tilde", "sañ", true),
		("a quote", "keep\"spam", true),
		("a plus", "keep+spam", true),
		("a dot name", ".", false),
		("a double dot name", "..", false),
	] {
		let got = sieve_store::is_valid_name(name);
		assert_eq!(
			got, accepted,
			"Sieve script name {name:?} ({what}): observed {got}, this table says {accepted}"
		);
	}
	assert!(
		sieve_store::is_valid_name(&"a".repeat(sieve_store::MAX_NAME_CHARS)),
		"a name at the character cap is accepted"
	);
	assert!(
		!sieve_store::is_valid_name(&"a".repeat(sieve_store::MAX_NAME_CHARS + 1)),
		"one over the character cap is refused"
	);
	// A name whose composed form is longer than the octet cap is refused even
	// though its character count is inside it, so both caps are live.
	let octet_over = "\u{f1}".repeat(sieve_store::MAX_NAME_BYTES / 2 + 1);
	assert!(
		octet_over.chars().count() <= sieve_store::MAX_NAME_CHARS,
		"the fixture is inside the character cap"
	);
	assert!(
		!sieve_store::is_valid_name(&octet_over),
		"a name over the octet cap is refused whatever its character count is"
	);
}

#[test]
fn a_password_answers_the_same_under_both_policies() {
	// Drawn at run time rather than written out: the bundled breached-password
	// list holds the memorable twelve-character strings, and a literal in a
	// test file is also what the code-scanning rules read as a credential.
	let at_64 = fixture_password(64);
	let at_65 = fixture_password(65);
	for (what, value, ascii, unicode) in [
		("empty", "", false, false),
		("one character", "a", false, false),
		("at 11 characters", &fixture_password(11), false, false),
		("at 12 characters", &fixture_password(12), true, true),
		("at 64 characters", at_64.as_str(), true, true),
		("at 65 characters", at_65.as_str(), false, false),
		("a space", &format!("{} ", "x".repeat(12)), true, true),
		(
			"a non-ASCII letter",
			&format!("{}\u{e4}", "x".repeat(12)),
			false,
			true,
		),
		(
			"NFD of n-tilde",
			&format!("{}n\u{0303}", "x".repeat(11)),
			false,
			true,
		),
		(
			"a control character",
			&format!("{}a\r", "x".repeat(12)),
			false,
			false,
		),
		("NUL", &format!("{}a\0", "x".repeat(12)), false, false),
		(
			"a bidi override",
			&format!("{}a\u{202e}", "x".repeat(12)),
			false,
			false,
		),
	] {
		let got_ascii = password::validate(value).is_ok();
		let got_unicode = Policy::unicode().validate(value).is_ok();
		assert_eq!(
			got_ascii, ascii,
			"ASCII password {what}: observed {got_ascii}, this table says {ascii}"
		);
		assert_eq!(
			got_unicode, unicode,
			"Unicode password {what}: observed {got_unicode}, this table says {unicode}"
		);
	}
	// The Unicode policy normalises with NFKC, so the composed and the
	// decomposed spelling of one password are both accepted and both reach the
	// same stored form.
	let composed = format!("{}a\u{00e9}b", "x".repeat(11));
	let decomposed = format!("{}a\u{0065}\u{0301}b", "x".repeat(11));
	for value in [&composed, &decomposed] {
		assert!(
			Policy::unicode().validate(value).is_ok(),
			"both spellings of one password are accepted: {value:?}"
		);
	}
	assert_eq!(
		Policy::unicode().login_form(&composed),
		Policy::unicode().login_form(&decomposed),
		"both spellings reach the same bytes"
	);
	// Length is counted on the normalised form, so a decomposed spelling that
	// normalises shorter than 12 is still refused.
	let decomposed_long = format!("{}n\u{0303}", "x".repeat(12));
	assert!(
		Policy::unicode()
			.login_form(&decomposed_long)
			.chars()
			.count() > 12,
		"the decomposed fixture is longer than the cap before normalisation"
	);
	assert_eq!(
		Policy::unicode()
			.login_form(&decomposed_long)
			.chars()
			.count(),
		13,
		"and one character shorter after it"
	);
}
#[test]
fn a_display_name_answers_the_same_through_every_surface() {
	use epistle::directory_store::display_name;
	for (what, value, accepted) in [
		("empty", "", true),
		("one character", "a", true),
		("plain", "Ada Lovelace", true),
		("with spaces around", "  Ada  ", true),
		("a newline", "Ada\nLovelace", false),
		("a carriage return", "Ada\rLovelace", false),
		("a tab", "Ada\tLovelace", false),
		("NUL", "Ada\0Lovelace", false),
		(
			"non-ASCII",
			"Ada \u{00d1}u\u{00f1}ez \u{65e5}\u{672c}\u{8a9e}",
			true,
		),
	] {
		let got = display_name::validate(value).is_ok();
		assert_eq!(
			got, accepted,
			"display name {what}: observed {got}, this table says {accepted}"
		);
	}
	assert!(
		display_name::validate(&"a".repeat(display_name::MAX_CHARS)).is_ok(),
		"a name at the character cap is accepted"
	);
	assert!(
		display_name::validate(&"a".repeat(display_name::MAX_CHARS + 1)).is_err(),
		"one over the character cap is refused"
	);
	// An empty name clears the field rather than failing it.
	assert_eq!(display_name::validate("   "), Ok(None));
}

#[test]
fn a_cidr_spec_answers_the_same_wherever_it_is_read() {
	for (what, spec, accepted) in [
		("empty", "", false),
		("a bare IPv4", "203.0.113.5", true),
		("an IPv4 network", "203.0.113.0/24", true),
		("a /0", "0.0.0.0/0", true),
		("a bare IPv6", "2001:db8::1", true),
		("an IPv6 network", "2001:db8::/32", true),
		("a /32 on IPv4", "203.0.113.0/32", true),
		("a /33 on IPv4", "203.0.113.0/33", false),
		("a /129 on IPv6", "2001:db8::/129", false),
		("a prefix that is not a number", "203.0.113.0/x", false),
		("an address that is not one", "203.0.113.256/24", false),
		("a host name", "example.org/24", false),
		("a bare prefix", "/24", false),
		("surrounded by spaces", " 203.0.113.0/24 ", true),
	] {
		let got = Cidr::parse(spec).is_some();
		assert_eq!(
			got, accepted,
			"CIDR {spec:?} ({what}): observed {got}, this table says {accepted}"
		);
	}
	// Host bits set in the spec are masked, so the block matches the network.
	let cidr = Cidr::parse("203.0.113.5/24").expect("parse");
	assert!(
		cidr.contains("203.0.113.9".parse().expect("ip")),
		"a host inside the masked block is contained"
	);
	assert!(
		!cidr.contains("203.0.114.9".parse().expect("ip")),
		"a host outside the block is not"
	);
}

#[test]
fn a_mailbox_name_answers_the_same_as_a_folder_at_every_depth() {
	for (what, name, accepted) in [
		("empty", "", false),
		("one character", "a", true),
		("plain", "Lists", true),
		("lower-case inbox", "inbox", false),
		("a child of INBOX", "INBOX/Lists", true),
		("a child of lower-case inbox", "inbox/Lists", true),
		("two levels", "Lists/Rust", true),
		("an empty level", "Lists//Rust", false),
		("a leading dot", ".hidden", false),
		("a trailing space", "Lists ", false),
		("a space inside", "Project A", true),
		("the disk spelling of the delimiter", "A&AC8-o", false),
		("non-ASCII in modified UTF-7", "A&APE-o", true),
		("a raw non-ASCII name", "A\u{f1}o", false),
	] {
		let got = mailbox_path::valid_folder(name);
		assert_eq!(
			got, accepted,
			"mailbox {name:?} ({what}): observed {got}, this table says {accepted}"
		);
	}
	let levels = |count: usize| {
		(0..count)
			.map(|index| format!("l{index}"))
			.collect::<Vec<_>>()
			.join("/")
	};
	assert!(
		mailbox_path::valid_folder(&levels(mailbox_path::MAX_DEPTH)),
		"a name at MAX_DEPTH levels is accepted"
	);
	assert!(
		!mailbox_path::valid_folder(&levels(mailbox_path::MAX_DEPTH + 1)),
		"one level over MAX_DEPTH is refused"
	);
}

#[test]
fn a_memory_size_reads_the_same_wherever_it_is_written() {
	// `init` validates an operator's answer and `status` reads the compose file
	// back with the same shape, so both go through this one function.
	for (what, value, accepted) in [
		("empty", "", false),
		("a bare number", "4", false),
		("kilobytes", "64k", true),
		("kilobytes upper", "64K", true),
		("megabytes", "512m", true),
		("gigabytes", "4g", true),
		("terabytes", "1t", false),
		("zero", "0g", false),
		("zero spelled with leading zeros", "00m", false),
		("a fraction", "1.5g", false),
		("a negative", "-1g", false),
		("a unit alone", "g", false),
		("a number, a unit and more", "4gg", false),
		("a value past u64", "99999999999999999999g", false),
	] {
		let got = validation::parse_memory_size(value).is_some();
		assert_eq!(
			got, accepted,
			"memory size {value:?} ({what}): observed {got}, this table says {accepted}"
		);
	}
	// The two spellings of one value are one number.
	assert_eq!(
		validation::parse_memory_size("4g"),
		validation::parse_memory_size("4G"),
		"the case of the unit does not change the value"
	);
	// The shape and the read are two rules. `stack resources set` answers a
	// value of the right shape that no 64-bit size reaches with its own
	// message, so folding the overflow into the shape check is what moved it.
	let past_u64 = "99999999999g";
	assert!(
		validation::is_memory_size_shape(past_u64),
		"a value written the compose way keeps its shape whatever it holds"
	);
	assert_eq!(
		validation::parse_memory_size(past_u64),
		None,
		"and no 64-bit size reads it"
	);
}
