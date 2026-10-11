use std::fmt::Write;
use std::path::Path;

pub(super) fn unified(path: &Path, old: &str, new: &str) -> String {
	if old == new {
		return String::new();
	}
	let old_lines: Vec<_> = old.split_inclusive('\n').collect();
	let new_lines: Vec<_> = new.split_inclusive('\n').collect();
	let prefix = old_lines
		.iter()
		.zip(&new_lines)
		.take_while(|(a, b)| a == b)
		.count();
	let suffix = old_lines[prefix..]
		.iter()
		.rev()
		.zip(new_lines[prefix..].iter().rev())
		.take_while(|(a, b)| a == b)
		.count();
	let start = prefix.saturating_sub(3);
	let old_end = (old_lines.len() - suffix + 3).min(old_lines.len());
	let new_end = (new_lines.len() - suffix + 3).min(new_lines.len());
	let mut output = format!("--- {}\n+++ {}\n", path.display(), path.display());
	let _ = writeln!(
		output,
		"@@ -{},{} +{},{} @@",
		if old_end == start { start } else { start + 1 },
		old_end - start,
		if new_end == start { start } else { start + 1 },
		new_end - start
	);
	for line in &old_lines[start..prefix] {
		emit(&mut output, ' ', line);
	}
	for line in &old_lines[prefix..old_lines.len() - suffix] {
		emit(&mut output, '-', line);
	}
	for line in &new_lines[prefix..new_lines.len() - suffix] {
		emit(&mut output, '+', line);
	}
	for line in &old_lines[old_lines.len() - suffix..old_end] {
		emit(&mut output, ' ', line);
	}
	output
}

fn emit(output: &mut String, marker: char, line: &str) {
	output.push(marker);
	output.push_str(line);
	if !line.ends_with('\n') {
		output.push_str("\n\\ No newline at end of file\n");
	}
}
