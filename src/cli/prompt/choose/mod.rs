//! Pick one value from a numbered list, for a command run without an
//! argument it needs.

use super::Console;
use crate::cli::term;

/// Answers that are not a choice before the pick gives up.
const ATTEMPTS: usize = 3;

/// Ask the operator to pick one of `options`, a list of `what` (`account`,
/// `alias`). `None` when nobody can answer, the list is empty, the operator
/// cancels, or three answers in a row are not a choice.
pub(crate) fn choose(console: &mut Console<'_>, what: &str, options: &[String]) -> Option<String> {
	if !console.interactive {
		return None;
	}
	if options.is_empty() {
		let _ = writeln!(console.err, "there is no {what} to pick from");
		return None;
	}
	let article = if what.starts_with(['a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U']) {
		"an"
	} else {
		"a"
	};
	let _ = writeln!(console.err, "Pick {article} {what}:");
	for (index, option) in options.iter().enumerate() {
		let _ = writeln!(console.err, "  {}) {}", index + 1, term::sanitize(option));
	}
	for _ in 0..ATTEMPTS {
		let _ = write!(
			console.err,
			"Number (1-{}, empty to cancel): ",
			options.len()
		);
		let _ = console.err.flush();
		let mut line = String::new();
		match console.input.read_line(&mut line) {
			Ok(0) | Err(_) => {
				let _ = writeln!(console.err);
				return None;
			}
			Ok(_) => {}
		}
		let answer = line.trim();
		if answer.is_empty() {
			return None;
		}
		let by_number = answer
			.parse::<usize>()
			.ok()
			.and_then(|number| number.checked_sub(1))
			.and_then(|index| options.get(index));
		if let Some(picked) = by_number.or_else(|| options.iter().find(|option| *option == answer))
		{
			return Some(picked.clone());
		}
		let _ = writeln!(console.err, "  type a number from 1 to {}", options.len());
	}
	None
}

/// [`choose`] on the process's stdin and stderr.
pub(crate) fn pick(what: &str, options: &[String]) -> Option<String> {
	super::with_console(super::Input::Stdin, |console| {
		choose(console, what, options)
	})
}

#[cfg(test)]
mod tests;
