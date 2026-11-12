//! Keeping what a hostile configuration file echoes back in an error short.

/// The longest line of an error message that quotes the file.
const MAX_LINE: usize = 1000;

/// `text` with every line cut to [`MAX_LINE`] characters. The parser quotes
/// the line it stopped at, so a file with one huge line would otherwise
/// make an error message as large as the file, in the log and on the
/// terminal, while the part that says what is wrong (the lines around the
/// quote) stays whole.
pub(super) fn lines(text: &str) -> String {
	let mut out = String::with_capacity(text.len().min(4 * MAX_LINE));
	for (index, line) in text.split('\n').enumerate() {
		if index > 0 {
			out.push('\n');
		}
		out.push_str(&line[..cut(line, MAX_LINE)]);
		if line.len() > cut(line, MAX_LINE) {
			out.push_str("...");
		}
	}
	out
}

/// The name of an environment variable a reference spells, cut to `limit`
/// characters when it is longer.
pub(super) fn name(name: &str, limit: usize) -> String {
	let end = cut(name, limit);
	if end == name.len() {
		name.to_string()
	} else {
		format!("{}...", &name[..end])
	}
}

/// The largest index of `text` at most `limit` that is a character boundary.
fn cut(text: &str, limit: usize) -> usize {
	let mut end = limit.min(text.len());
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	end
}
