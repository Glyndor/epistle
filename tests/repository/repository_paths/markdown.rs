//! The lines of a Markdown file that can carry a citation.

/// The lines of a Markdown file outside example fences, numbered from 1.
pub fn lines(text: &str) -> Vec<(usize, String)> {
	let mut fence: Option<(char, usize, bool)> = None;
	let mut out = Vec::new();
	for (index, line) in text.lines().enumerate() {
		let was_example = matches!(fence, Some((_, _, true)));
		if let Some((mark, len, info)) = fence_marker(line) {
			match fence {
				None => {
					fence = Some((
						mark,
						len,
						info.split_whitespace().any(|word| word == "example"),
					))
				}
				Some((open, open_len, _))
					if mark == open && len >= open_len && info.trim().is_empty() =>
				{
					fence = None
				}
				Some(_) => {}
			}
		}
		if !was_example && !matches!(fence, Some((_, _, true))) {
			out.push((index + 1, line.to_string()));
		}
	}
	out
}

/// The fence character, its run length and the info string, when `line`
/// opens or closes a fenced block. A backtick run whose info string holds
/// another backtick is inline code that starts a line, not a fence.
fn fence_marker(line: &str) -> Option<(char, usize, &str)> {
	let trimmed = line.trim_start();
	let mark = trimmed.chars().next().filter(|c| matches!(c, '`' | '~'))?;
	let len = trimmed.chars().take_while(|&c| c == mark).count();
	let info = &trimmed[len..];
	(len >= 3 && !(mark == '`' && info.contains('`'))).then_some((mark, len, info))
}
