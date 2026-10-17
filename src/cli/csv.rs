//! Writing one CSV field for output an operator may open in a spreadsheet.

/// A CSV field: quoted when it holds a comma, a quote or a leading or
/// trailing space, and prefixed with an apostrophe when a spreadsheet would
/// read it as a formula. `suppression import` removes that apostrophe.
pub(super) fn field(text: &str) -> String {
	let flat: String = text
		.chars()
		.map(|c| if c.is_control() { ' ' } else { c })
		.collect();
	let flat = if flat.starts_with(['=', '+', '-', '@']) {
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
#[path = "csv_tests.rs"]
mod tests;
