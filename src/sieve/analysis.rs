//! What can be said about a parsed script without running it: the walks that
//! the upload check uses to refuse what the interpreter would refuse to run.
//!
//! Scripts nest at most [`super::parser::MAX_NESTING_DEPTH`] deep, but every
//! walk here keeps its own stack anyway, so none of them depends on that.

use super::ast::{Argument, Command, Test};
use super::compare::{MAX_PATTERN_CHARS, MAX_WILDCARDS};

/// Call `action` on every action command and `test` on every test of
/// `commands`, at any depth.
pub fn walk<'a>(
	commands: &'a [Command],
	mut action: impl FnMut(&'a str, &'a [Argument]),
	mut test: impl FnMut(&'a Test),
) {
	let mut blocks: Vec<&[Command]> = vec![commands];
	let mut tests: Vec<&Test> = Vec::new();
	while let Some(block) = blocks.pop() {
		for command in block {
			match command {
				Command::Action { name, args } => action(name, args),
				Command::If(conditional) => {
					for branch in &conditional.branches {
						tests.push(&branch.test);
						blocks.push(&branch.body);
					}
					blocks.extend(conditional.otherwise.as_deref());
				}
			}
		}
		while let Some(next) = tests.pop() {
			test(next);
			tests.extend(&next.children);
		}
	}
}

/// The first `:matches` key a script holds that the matcher would refuse
/// (too long, or with too many wildcards), as a reason for the upload check.
/// A key built from variables is not known until the script runs, and the
/// matcher refuses it then.
pub fn pattern_problem(commands: &[Command]) -> Option<String> {
	let mut problem = None;
	walk(
		commands,
		|_, _| {},
		|test| {
			if problem.is_some()
				|| !test
					.args
					.iter()
					.any(|a| matches!(a, Argument::Tag(t) if t == "matches"))
			{
				return;
			}
			for key in test.args.iter().flat_map(|arg| match arg {
				Argument::Str(s) => vec![s.as_str()],
				Argument::StrList(list) => list.iter().map(String::as_str).collect(),
				_ => Vec::new(),
			}) {
				let wildcards = key.chars().filter(|c| matches!(c, '*' | '?')).count();
				if key.chars().count() > MAX_PATTERN_CHARS {
					problem = Some(format!(
						"a :matches key is longer than {MAX_PATTERN_CHARS} characters"
					));
					return;
				}
				if wildcards > MAX_WILDCARDS {
					problem = Some(format!(
						"a :matches key has more than {MAX_WILDCARDS} wildcards"
					));
					return;
				}
			}
		},
	);
	problem
}

/// Whether running the script can make the server send mail: a `redirect`
/// forwards the message, `vacation` answers it, `reject` and `ereject`
/// bounce it. A script that does none of these only files, flags or drops
/// what it is given. Text that is not a script sends nothing (the upload
/// check refuses it).
pub fn sends_mail(script: &str) -> bool {
	let Ok(tokens) = super::lexer::tokenize(script) else {
		return false;
	};
	let Ok(commands) = super::parser::parse(&tokens) else {
		return false;
	};
	let mut sends = false;
	walk(
		&commands,
		|name, _| {
			// Identifiers are not case-sensitive (RFC 5228 section 2.1).
			sends |= ["redirect", "vacation", "reject", "ereject"]
				.iter()
				.any(|action| name.eq_ignore_ascii_case(action));
		},
		|_| {},
	);
	sends
}
