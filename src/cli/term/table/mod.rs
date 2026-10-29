//! Aligned list tables for a terminal.
//!
//! Each column is as wide as its widest cell. When the rows do not fit the
//! terminal, the last column is shortened first, then the widest of the
//! others, each cut cell ending in an ellipsis; a row is never wrapped, so
//! the columns stay lined up at any width. A state column (`enabled`, `ok`,
//! `held`) is drawn with its symbol and painted after the fitting, because
//! escape sequences take no columns and would throw the measuring off.
//!
//! Only used when stdout is decorated; the plain form of every list stays
//! whatever the command printed before.

use std::io::Write;

use anstyle::Style;

use super::{Decor, Tone, badge, columns, fit, pad, paint, sanitize, tone_of};

/// Spaces between two columns.
const GAP: usize = 2;

/// The narrowest a column is shortened to, so a cut cell still shows a
/// couple of characters before its ellipsis.
const MIN_COLUMN: usize = 4;

/// A list rendered as aligned columns.
#[derive(Debug, Default)]
pub(crate) struct Table {
	headers: Vec<String>,
	state_cols: Vec<usize>,
	rows: Vec<Vec<String>>,
}

impl Table {
	/// A table with these column headers.
	pub(crate) fn new(headers: &[&str]) -> Self {
		Table {
			headers: headers.iter().map(|header| (*header).to_string()).collect(),
			state_cols: Vec::new(),
			rows: Vec::new(),
		}
	}

	/// Mark column `col` as holding state words, drawn with their symbol
	/// and colour.
	pub(crate) fn state_col(mut self, col: usize) -> Self {
		self.state_cols.push(col);
		self
	}

	/// Append a row. Missing cells are blank; extra cells are dropped.
	pub(crate) fn push(&mut self, cells: Vec<String>) {
		let mut row: Vec<String> = cells
			.into_iter()
			.take(self.headers.len())
			.enumerate()
			.map(|(col, cell)| {
				let cell = sanitize(&cell);
				if self.state_cols.contains(&col) {
					badge(&cell)
				} else {
					cell
				}
			})
			.collect();
		row.resize(self.headers.len(), String::new());
		self.rows.push(row);
	}

	/// The header and one line per row, fitted to `decor.width`.
	pub(crate) fn render(&self, decor: Decor) -> Vec<String> {
		let widths = self.widths(decor.width);
		let mut lines = Vec::with_capacity(self.rows.len() + 1);
		let header = self.line(&self.headers, &widths, None, decor.width);
		lines.push(paint(Style::new().bold(), &header, decor.colour));
		for row in &self.rows {
			lines.push(self.line(row, &widths, Some(decor.colour), decor.width));
		}
		lines
	}

	/// Each column's width: its widest cell, then shortened until the row
	/// fits `width`. The last column goes first because it is the free
	/// text (members, addresses); a state column is never shortened.
	fn widths(&self, width: usize) -> Vec<usize> {
		let mut widths: Vec<usize> = (0..self.headers.len())
			.map(|col| {
				std::iter::once(&self.headers[col])
					.chain(self.rows.iter().map(|row| &row[col]))
					.map(|cell| columns(cell))
					.max()
					.unwrap_or(0)
			})
			.collect();
		let gaps = GAP * self.headers.len().saturating_sub(1);
		let mut over = (widths.iter().sum::<usize>() + gaps).saturating_sub(width);
		let last = self.headers.len().saturating_sub(1);
		if over > 0 && !self.state_cols.contains(&last) {
			let cut = over.min(widths[last].saturating_sub(MIN_COLUMN));
			widths[last] -= cut;
			over -= cut;
		}
		while over > 0 {
			let widest = (0..widths.len())
				.filter(|col| !self.state_cols.contains(col) && widths[*col] > MIN_COLUMN)
				.max_by_key(|col| widths[*col]);
			let Some(col) = widest else { break };
			widths[col] -= 1;
			over -= 1;
		}
		widths
	}

	/// One row, each cell fitted to its column. `colour` is `None` for the
	/// header (painted as a whole) and the decoration's colour for a row,
	/// whose state cells are painted once they are fitted.
	fn line(
		&self,
		cells: &[String],
		widths: &[usize],
		colour: Option<bool>,
		width: usize,
	) -> String {
		let last = cells.len().saturating_sub(1);
		let mut plain = Vec::with_capacity(cells.len());
		let mut painted = Vec::with_capacity(cells.len());
		for (col, cell) in cells.iter().enumerate() {
			let text = if col == last {
				fit(cell, widths[col])
			} else {
				pad(cell, widths[col])
			};
			let tone = self
				.state_cols
				.contains(&col)
				.then(|| state_tone(cell))
				.flatten();
			painted.push(match (colour, tone) {
				(Some(true), Some(tone)) => paint_state(&text, tone),
				_ => text.clone(),
			});
			plain.push(text);
		}
		let gap = " ".repeat(GAP);
		let plain = plain.join(&gap).trim_end().to_string();
		if columns(&plain) > width {
			// The minimums did not leave room: cut the row itself, without
			// its colour, rather than let the terminal wrap it.
			return fit(&plain, width);
		}
		painted.join(&gap).trim_end().to_string()
	}

	/// [`Table::render`] written to `out`, one line each.
	pub(crate) fn write(&self, decor: Decor, out: &mut impl Write) -> std::io::Result<()> {
		for line in self.render(decor) {
			writeln!(out, "{line}")?;
		}
		Ok(())
	}
}

/// The tone of a state cell that already carries its symbol.
fn state_tone(cell: &str) -> Option<Tone> {
	let word = cell.split_once(' ').map_or(cell, |(_, word)| word);
	tone_of(word)
}

/// A fitted state cell with its symbol and word painted and the padding
/// left bare, so the colour stops where the word does.
fn paint_state(text: &str, tone: Tone) -> String {
	let trimmed = text.trim_end();
	let padding = &text[trimmed.len()..];
	format!("{}{padding}", paint(tone.style(), trimmed, true))
}

#[cfg(test)]
pub(crate) mod tests;
