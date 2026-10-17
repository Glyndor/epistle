//! What one run of a script can make the server spend: memory for the
//! strings it builds, steps, and matching work.

use super::interp::{Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::parser::parse;

fn run_with(script: &str, raw: &[u8]) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	evaluate(&commands, &Message::parse(raw))
}

fn run(script: &str) -> Outcome {
	run_with(script, b"Subject: hi\r\n\r\nx\r\n")
}

#[test]
fn doubling_a_variable_cannot_build_a_huge_string() {
	// 610 octets of script doubled a variable on every line until the
	// process held two gigabytes. Twenty doublings are ten mebibytes
	// without a limit, and the limit is 4096 octets.
	let mut script =
		String::from("require [\"variables\", \"reject\"];\nset \"a\" \"0123456789\";\n");
	for _ in 0..20 {
		script.push_str("set \"a\" \"${a}${a}\";\n");
	}
	script.push_str("reject \"${a}\";\n");
	let outcome = run(&script);
	assert_eq!(outcome.reject.as_deref().map(str::len), Some(4096));
	assert!(!outcome.aborted);
}

#[test]
fn a_string_built_from_many_references_stays_near_the_script_text() {
	let mut script = String::from("require [\"variables\", \"reject\"];\nset \"a\" \"");
	script.push_str(&"y".repeat(4096));
	script.push_str("\";\nreject \"");
	script.push_str(&"${a}".repeat(2000));
	script.push_str("\";\n");
	let outcome = run(&script);
	let reject = outcome.reject.expect("rejected");
	assert_eq!(
		reject.len(),
		8000,
		"no more than the octets of the template"
	);
	assert!(reject.starts_with('y'));
}

#[test]
fn a_run_with_too_many_steps_stops_where_it_is() {
	let script = format!("discard;\n{}fileinto \"Z\";\n", "keep;\n".repeat(25_000));
	let outcome = run(&script);
	assert!(outcome.aborted, "a run over 20000 steps stops");
	assert!(outcome.discarded, "what it had decided stays decided");
	assert!(outcome.fileinto.is_empty() && outcome.redirects.is_empty());
}

#[test]
fn a_run_inside_its_steps_is_not_abandoned() {
	let script = format!("{}fileinto \"Z\";\n", "keep;\n".repeat(19_000));
	let outcome = run(&script);
	assert!(!outcome.aborted);
	assert_eq!(outcome.fileinto, vec!["Z".to_string()]);
}

#[test]
fn matching_work_is_budgeted_across_the_run() {
	// Each of these tests tries a 200-character segment at every position of
	// an 8000-character subject: about 1.6 million comparisons. Two hundred
	// and fifty of them are past the budget of a run.
	let key = format!("*{}b*", "a".repeat(200));
	let test = format!("if header :matches \"subject\" \"{key}\" {{ discard; }}\n");
	let raw = format!("Subject: {}\r\n\r\nx\r\n", "a".repeat(8000));
	let outcome = run_with(&test.repeat(250), raw.as_bytes());
	assert!(
		outcome.aborted,
		"250 large matches are more than a run may ask for"
	);
	assert!(outcome.keep && !outcome.discarded);
	let outcome = run_with(&test.repeat(5), raw.as_bytes());
	assert!(!outcome.aborted);
}

#[test]
fn what_the_sender_captures_does_not_use_up_the_scripts_variables() {
	// 17 wildcards over a 69 KB Subject capture 17 x 4096 octets, which used
	// to fill the 64 KiB the script's own variables share, so the `set` after
	// it was ignored and `fileinto "${dest}"` filed nowhere.
	let script = "require [\"variables\", \"fileinto\"];\n\
		if header :matches \"subject\" \"*,*,*,*,*,*,*,*,*,*,*,*,*,*,*,*,*\" { }\n\
		set \"dest\" \"topic1\";\n\
		fileinto \"${dest}\";\n";
	let subject = vec!["y".repeat(4096); 17].join(",");
	let raw = format!("Subject: {subject}\r\n\r\nx\r\n");
	let outcome = run_with(script, raw.as_bytes());
	assert_eq!(outcome.fileinto, vec!["topic1".to_string()]);
	assert!(!outcome.aborted);
}

#[test]
fn a_set_that_does_not_fit_stops_the_run_instead_of_being_ignored() {
	let mut script =
		String::from("require [\"variables\", \"fileinto\", \"reject\"];\nset \"big\" \"");
	script.push_str(&"y".repeat(4000));
	script.push_str("\";\n");
	for n in 0..20 {
		script.push_str(&format!("set \"v{n}\" \"${{big}}${{big}}\";\n"));
	}
	script.push_str("discard;\n");
	let outcome = run(&script);
	assert!(
		outcome.aborted,
		"twenty variables of 4000 octets do not fit 64 KiB"
	);
	assert!(!outcome.discarded, "and the run stopped there");
	// A name that is too long is not silence either.
	let outcome = run(&format!(
		"require \"variables\";\nset \"{}\" \"x\";\ndiscard;\n",
		"n".repeat(100)
	));
	assert!(outcome.aborted && !outcome.discarded);
}

#[test]
fn numbered_captures_are_those_of_the_last_match() {
	let script = "require [\"variables\", \"reject\"];\n\
		if header :matches \"subject\" \"a*c\" { }\n\
		if header :matches \"subject\" \"?*\" { reject \"${1}${2}\"; }\n";
	let outcome = run_with(script, b"Subject: abc\r\n\r\nx\r\n");
	assert_eq!(outcome.reject.as_deref(), Some("abc"));
}

#[test]
fn a_key_over_the_caps_is_a_false_test_and_the_rest_of_the_script_runs() {
	// Keys written before the caps may be longer than 256 characters. The
	// test is false (and noted for the log); the run is not stopped, so the
	// rules after it still apply and the `discard` before it is not lost.
	let long = "a".repeat(300);
	let script = format!(
		"require \"fileinto\";\n\
		if header :matches \"subject\" \"{long}\" {{ discard; }}\n\
		fileinto \"After\";\n"
	);
	let outcome = run(&script);
	assert!(!outcome.aborted && outcome.pattern_over_caps, "{outcome:?}");
	assert!(!outcome.discarded);
	assert_eq!(outcome.fileinto, vec!["After".to_string()]);
}
