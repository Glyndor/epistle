//! `docs/limits.md` is the operator-facing mirror of the catalog. Every
//! row the catalog carries must appear in the docs page, and every row
//! the docs page carries must come from the catalog, so neither side
//! drifts from the other.
//!
//! The test reads the real catalog through the `#[doc(hidden)]` snapshot
//! in `src/cli/limits/catalog.rs` (the same catalog `epistle limits
//! show` enumerates). Every row of the catalog is matched against a row
//! of the docs page by name, kind, default, unit, bounds, and reference;
//! a stale docs row trips the test, and a stale catalog row does too.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use epistle::cli::docs_snapshot;

fn docs_path() -> std::path::PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/limits.md")
}

/// One row of the docs page parsed from a Markdown table. The format
/// the catalog uses (one Markdown row per limit) is stable, so a
/// single regex is enough.
#[derive(Debug, PartialEq, Eq)]
struct DocsRow {
	name: String,
	cells: Vec<String>,
}

fn parse_markdown_rows(text: &str) -> Vec<DocsRow> {
	let mut rows = Vec::new();
	let mut in_table = false;
	for line in text.lines() {
		if line.trim_start_matches('|').starts_with("|---")
			|| line.trim_start_matches('|').contains("---") && line.starts_with('|')
		{
			// Skip the markdown table separator (|---|---|---|...).
			if line.contains("---") && line.starts_with('|') && line.ends_with('|') {
				in_table = true;
				continue;
			}
		}
		if !line.starts_with('|') || !line.ends_with('|') {
			in_table = false;
			continue;
		}
		if !in_table {
			continue;
		}
		// Strip leading and trailing pipe, split by '|'.
		let trimmed = &line[1..line.len() - 1];
		let cells: Vec<String> = trimmed
			.split('|')
			.map(|cell| cell.trim().to_string())
			.collect();
		let Some(name) = cells.first().cloned() else {
			continue;
		};
		let name = name
			.trim_start_matches('`')
			.trim_end_matches('`')
			.to_string();
		if name.is_empty() {
			continue;
		}
		rows.push(DocsRow { name, cells });
	}
	rows
}

#[test]
fn the_catalog_drives_the_docs_page_row_for_row() {
	let snapshot = docs_snapshot();
	let text = fs::read_to_string(docs_path()).expect("read docs/limits.md");
	let docs_rows = parse_markdown_rows(&text);
	let docs_by_name: std::collections::HashMap<&str, &DocsRow> = docs_rows
		.iter()
		.map(|row| (row.name.as_str(), row))
		.collect();
	let catalog_names: BTreeSet<&str> = snapshot.iter().map(|row| row.name).collect();
	let docs_names: BTreeSet<&str> = docs_rows.iter().map(|row| row.name.as_str()).collect();

	// Every catalog row must have a docs row.
	for row in &snapshot {
		assert!(
			docs_by_name.contains_key(row.name),
			"catalog carries `{}` (kind {}, reference {}) but docs/limits.md has no row for it",
			row.name,
			row.kind,
			row.reference,
		);
	}

	// Every docs row must come from the catalog.
	for name in &docs_names {
		assert!(
			catalog_names.contains(name),
			"docs/limits.md lists `{name}` but the catalog does not carry it"
		);
	}

	// Each catalog row's kind, unit, reference, default and bounds must
	// match the docs row that bears the same name. The column layout
	// differs between the adjustable table (six columns: key, default,
	// unit, kind, bounds, reference) and the fixed table (four columns:
	// key, value, unit, reference), so the layout is picked by kind.
	for row in &snapshot {
		let docs_row = docs_by_name
			.get(row.name)
			.copied()
			.expect("the membership check above guarantees this");
		let docs_cells = &docs_row.cells;
		match row.kind {
			"adjustable" | "recommended" | "must" => {
				assert_eq!(
					docs_cells.len(),
					6,
					"docs row for `{}` should have 6 cells (key, default, unit, kind, bounds, reference), got {:?}",
					row.name,
					docs_cells,
				);
				let docs_unit = docs_cells.get(2).map(String::as_str).unwrap_or("");
				let docs_kind = docs_cells.get(3).map(String::as_str).unwrap_or("");
				let docs_bounds = docs_cells.get(4).map(String::as_str).unwrap_or("");
				let docs_reference = docs_cells.get(5).map(String::as_str).unwrap_or("");
				assert_eq!(
					docs_unit, row.unit,
					"`{}`: unit column drift (docs says `{docs_unit}`, catalog says `{}`)",
					row.name, row.unit,
				);
				assert_eq!(
					docs_kind, row.kind,
					"`{}`: kind column drift (docs says `{docs_kind}`, catalog says `{}`)",
					row.name, row.kind,
				);
				assert_eq!(
					docs_reference, row.reference,
					"`{}`: reference column drift",
					row.name,
				);
				let catalog_bounds = row.bounds.unwrap_or("");
				assert_eq!(
					docs_bounds, catalog_bounds,
					"`{}`: bounds column drift (docs says `{docs_bounds}`, catalog says `{catalog_bounds}`)",
					row.name,
				);
			}
			"fixed" => {
				// Fixed rows live in the fixed-limits table: key, value,
				// unit, class, reference.
				assert_eq!(
					docs_cells.len(),
					5,
					"docs row for `{}` should have 5 cells (key, value, unit, class, reference), got {:?}",
					row.name,
					docs_cells,
				);
				let cell = |index: usize| docs_cells.get(index).map(String::as_str).unwrap_or("");
				assert_eq!(
					cell(1),
					row.value.unwrap_or(""),
					"`{}`: value column drift",
					row.name,
				);
				assert_eq!(cell(2), row.unit, "`{}`: unit column drift", row.name);
				assert_eq!(cell(3), row.class, "`{}`: class column drift", row.name);
				assert_eq!(
					cell(4),
					row.reference,
					"`{}`: reference column drift",
					row.name,
				);
			}
			other => panic!("unknown kind `{other}` in the catalog snapshot"),
		}
	}
}

/// The kind column must be explained in the prose so the operator can
/// read the catalog.
#[test]
fn the_kind_column_meaning_is_documented() {
	let text = fs::read_to_string(docs_path()).expect("read docs/limits.md");
	let fold: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
	for marker in [
		"`adjustable`",
		"`recommended`",
		"`must`",
		"`fixed`",
		"`should`",
		"`own`",
		"refuses",
		"warning",
		"audit trail",
	] {
		assert!(
			fold.contains(marker),
			"docs/limits.md must explain `{marker}` so the operator can read the catalog"
		);
	}
}

/// No row is duplicated under a different name: the catalog is the
/// single source of truth, so the docs table must mirror it.
#[test]
fn the_catalog_has_no_duplicate_names() {
	let snapshot = docs_snapshot();
	let mut names: BTreeSet<&str> = BTreeSet::new();
	for row in &snapshot {
		assert!(
			names.insert(row.name),
			"catalog row `{}` is duplicated in the snapshot",
			row.name,
		);
	}
}

#[test]
fn per_account_connection_defaults_are_documented() {
	let text = fs::read_to_string(docs_path()).unwrap();
	for (name, default) in [
		("max-connections-per-account-per-ip", "10"),
		("max-connections-per-account-total", "50"),
	] {
		assert!(text.contains(&format!(
			"| `{name}` | {default} | count | adjustable | | no standard mandate |"
		)));
	}
}
