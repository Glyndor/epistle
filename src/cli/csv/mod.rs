//! Writing one CSV field for output an operator may open in a spreadsheet.

/// Whether a spreadsheet would read `text` as a formula once any leading
/// apostrophes (the mark that makes it plain text) are taken off.
pub(super) fn starts_formula(text: &str) -> bool {
	text.trim_start_matches('\'')
		.starts_with(['=', '+', '-', '@'])
}

/// A CSV field: quoted when it holds a comma, a quote or a leading or
/// trailing space, and prefixed with an apostrophe when a spreadsheet would
/// read it as a formula. `suppression import` removes that apostrophe.
pub(super) fn field(text: &str) -> String {
	let flat: String = text
		.chars()
		.map(|c| if c.is_control() { ' ' } else { c })
		.collect();
	let flat = if starts_formula(&flat) {
		format!("'{flat}")
	} else {
		flat
	};
	if flat.contains([',', '"']) || flat != flat.trim() {
		format!("\"{}\"", flat.replace('"', "\"\""))
	} else {
		flat
	}
}

#[cfg(test)]
mod tests;
