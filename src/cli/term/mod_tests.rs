//! When a stream is decorated, and the small fitting helpers every renderer
//! shares.

use std::ffi::OsStr;
use std::time::Duration;

use super::*;

/// The colour variables, set from `pairs` and unset otherwise.
fn env<'a>(pairs: &[(&str, &'a str)]) -> Env<'a> {
	let get = |name: &str| {
		pairs
			.iter()
			.find(|(key, _)| *key == name)
			.map(|(_, value)| OsStr::new(*value))
	};
	Env {
		no_color: get("NO_COLOR"),
		term: get("TERM"),
		clicolor: get("CLICOLOR"),
		clicolor_force: get("CLICOLOR_FORCE"),
	}
}

#[test]
fn only_a_terminal_without_no_color_dumb_clicolor_0_or_json_is_decorated() {
	let xterm = env(&[("TERM", "xterm-256color")]);
	assert!(decorates(true, &xterm, false));
	assert!(
		decorates(true, &env(&[("NO_COLOR", "")]), false),
		"empty NO_COLOR does not count"
	);
	assert!(!decorates(false, &xterm, false), "a pipe stays plain");
	assert!(
		!decorates(true, &env(&[("NO_COLOR", "1")]), false),
		"NO_COLOR"
	);
	assert!(
		!decorates(true, &env(&[("TERM", "dumb")]), false),
		"TERM=dumb"
	);
	assert!(
		!decorates(true, &env(&[("CLICOLOR", "0")]), false),
		"CLICOLOR=0"
	);
	assert!(!decorates(true, &xterm, true), "--json");
	assert!(
		!decorates(false, &env(&[("CLICOLOR_FORCE", "1")]), false),
		"CLICOLOR_FORCE colours a pipe, it never draws a table or a spinner into one"
	);
}

#[test]
fn colour_follows_the_terminal_unless_no_color_or_clicolor_force_says_otherwise() {
	assert!(colours(true, &env(&[("TERM", "xterm-256color")])));
	assert!(!colours(false, &env(&[])), "a pipe");
	assert!(!colours(true, &env(&[("TERM", "dumb")])), "TERM=dumb");
	assert!(!colours(true, &env(&[("CLICOLOR", "0")])), "CLICOLOR=0");
	assert!(
		colours(false, &env(&[("CLICOLOR_FORCE", "1")])),
		"forced on a pipe"
	);
	assert!(
		colours(true, &env(&[("CLICOLOR_FORCE", "1"), ("TERM", "dumb")])),
		"forced beats dumb"
	);
	assert!(
		!colours(false, &env(&[("CLICOLOR_FORCE", "0")])),
		"CLICOLOR_FORCE=0 forces nothing"
	);
	assert!(
		!colours(true, &env(&[("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")])),
		"NO_COLOR wins over everything"
	);
}

#[test]
fn the_test_build_never_decorates_unless_a_test_asks() {
	assert_eq!(stdout(false), None);
	assert_eq!(stderr(false), None);
	let decor = Decor::coloured(40);
	fake::with_stdout(decor, || {
		assert_eq!(stdout(false), Some(decor));
		assert_eq!(stdout(true), None, "--json is never decorated");
	});
	assert_eq!(stdout(false), None, "the fake is undone");
}

#[test]
fn every_state_word_has_one_symbol_and_red_is_only_for_failure() {
	assert_eq!(badge("ok"), "✔ ok");
	assert_eq!(badge("enabled"), "✔ enabled");
	assert_eq!(badge("warn"), "⚠ warn");
	assert_eq!(badge("held"), "⚠ held");
	assert_eq!(badge("fail"), "✘ fail");
	assert_eq!(badge("disabled"), "✘ disabled");
	assert_eq!(badge("queued"), "queued");
	assert_eq!(Tone::Bad.style().render().to_string(), "\x1b[31m");
	assert_eq!(Tone::Off.style().render().to_string(), "\x1b[2m");
}

#[test]
fn fit_cuts_with_an_ellipsis_and_pad_fills_to_the_width() {
	assert_eq!(fit("alice", 10), "alice");
	assert_eq!(fit("alice@example.org", 8), "alice@e…");
	assert_eq!(fit("alice", 0), "");
	assert_eq!(pad("ok", 4), "ok  ");
	assert_eq!(pad("✔ enabled", 6), "✔ ena…");
}

#[test]
fn paint_adds_escapes_only_with_colour() {
	let green = Tone::Good.style();
	assert_eq!(paint(green, "✔", false), "✔");
	assert_eq!(paint(green, "✔", true), "\x1b[32m✔\x1b[0m");
}

#[test]
fn elapsed_keeps_tenths_under_a_minute() {
	assert_eq!(elapsed(Duration::from_millis(400)), "0.4s");
	assert_eq!(elapsed(Duration::from_millis(12_900)), "12.9s");
	assert_eq!(elapsed(Duration::from_secs(63)), "1m03s");
}

#[test]
fn a_descriptor_that_is_not_a_terminal_gets_the_fallback_width() {
	assert_eq!(width_of(-1), 80);
}
