//! Answers TOML deserialisation. Two tests exercise the answers
//! TOML path (the file `init --answers` consumes): one round-trips
//! a minimal TOML block, the other round-trips the full
//! `Answers::template()` with every optional example uncommented to
//! keep the template honest. The `Warning` Display format is pinned
//! here too because it is the rendered output a fresh operator sees
//! on stderr.

use super::*;

#[test]
fn deserialise_from_template_minimal() {
	let toml_text = "mode = \"manual\"\n\
		hostname = \"mail.example.org\"\n\
		domains = [\"example.org\"]\n\
		data_dir = \"/var/lib/epistle\"\n\
		config_path = \"/etc/epistle/mail.toml\"\n\n\
		[services]\n\
		imap = true\n\
		submission = true\n\
		database = false\n"
		.to_string();
	let parsed: Answers = toml::from_str(&toml_text).expect("deserialise");
	assert_eq!(parsed.hostname, "mail.example.org");
	let warnings = parsed.validate().expect("minimal answers validate");
	assert!(warnings.is_empty());
}

/// The `--print-answers` template must remain a usable
/// starting point: every commented example in it has to
/// live in a place where uncommenting it does not move it
/// into a different table. The `image = ...` line was
/// rendered under `[services]` while the field itself lives
/// at the root, so an operator who uncommented the example
/// saw the parser fail with `unknown field image`; the
/// fix is to move the example to the top level. The test
/// uncomments every commented example and asserts the
/// resulting TOML parses with the same `Answers` shape the
/// file path uses (the validation side is exercised by the
/// other answers tests; the example values are
/// documentation placeholders and not all of them survive
/// a full validate).
#[test]
fn deserialise_from_template_with_every_example_uncommented() {
	let body = Answers::template();
	// The template is a string of TOML where every optional
	// field is shown as a commented `key = "value"` line.
	// An operator copies the template, uncomments the
	// optional fields they want, and runs `init --answers`.
	// The test simulates that workflow: drop the leading
	// `# ` from any commented line that has the shape of a
	// TOML key/value pair (i.e. a `=` after the comment
	// marker). Header comments and prose stay as comments.
	let mut uncommented = String::new();
	for line in body.lines() {
		let trimmed = line.trim_start();
		// A full-line comment that itself contains a `=`
		// (after the `#`) is an example the operator
		// uncomments. Drop the leading `# ` and keep the
		// rest. The `=` check is what distinguishes an
		// example (`# key = "value"`) from prose
		// (`# use this file as a starting point`); prose
		// without `=` stays a comment.
		if let Some(rest) = trimmed.strip_prefix("# ") {
			if rest.contains('=') {
				uncommented.push_str(rest);
			} else {
				uncommented.push_str(line);
			}
		} else {
			uncommented.push_str(line);
		}
		uncommented.push('\n');
	}
	let parsed: Answers =
		toml::from_str(&uncommented).expect("template with examples uncommented parses as Answers");
	// The image example now lives at the top level, where
	// the field actually lives. The previous template put
	// the example under `[services]`, so uncommenting it
	// would have moved the field into a table that does
	// not own it and the parser would have rejected the
	// file with `unknown field image`.
	assert!(
		parsed.image.is_some(),
		"the uncommented image example must populate the top-level image field; got: {:?}",
		parsed.image
	);
	// Every other example landed where the field actually
	// lives, so the file parses without unknown-field
	// errors. The previous shape reported `unknown field
	// image` for the example under `[services]`.
	assert_eq!(
		parsed.public_ipv4.as_ref().map(|a| a.to_string()),
		Some("203.0.113.10".to_string()),
		"the uncommented public_ipv4 example must populate the field"
	);
	assert_eq!(
		parsed.public_ipv6.as_ref().map(|a| a.to_string()),
		Some("2001:db8::10".to_string()),
		"the uncommented public_ipv6 example must populate the field"
	);
	assert!(
		!parsed.services.pop3,
		"the uncommented pop3 example (`pop3 = false`) must leave the field at its example value"
	);
}

#[test]
fn warning_display_names_field_and_message() {
	// The warning text rendered on stderr is \"<field>: <message>\"; a
	// change that drops either side would leave the operator guessing
	// which answer to revisit.
	let warning = Warning {
		field: "dns.token".to_string(),
		message: "inline token in the answers file".to_string(),
	};
	let rendered = format!("{warning}");
	assert_eq!(rendered, "dns.token: inline token in the answers file");
}
