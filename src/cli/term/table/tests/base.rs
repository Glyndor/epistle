//! The list table against a fake terminal: colour on and off, 120 and 40
//! columns, and the rule that a row is shortened rather than wrapped.

use super::*;

/// The visible text of a rendered line: the escape sequences removed.
pub(crate) fn visible(line: &str) -> String {
	let mut out = String::new();
	let mut chars = line.chars().peekable();
	while let Some(c) = chars.next() {
		if c == '\x1b' {
			for next in chars.by_ref() {
				if next.is_ascii_alphabetic() {
					break;
				}
			}
			continue;
		}
		out.push(c);
	}
	out
}

fn aliases() -> Table {
	let mut table = Table::new(&["ADDRESS", "STATE", "MEMBERS"]).state_col(1);
	table.push(vec![
		"team@example.org".into(),
		"enabled".into(),
		"alice@example.org,bob@example.org".into(),
	]);
	table.push(vec![
		"sales-and-partnerships-for-the-long-name@example.net".into(),
		"disabled".into(),
		"alice@example.org".into(),
	]);
	table
}

#[test]
fn wide_and_plain_symbols_align_the_columns_without_escapes() {
	let lines = aliases().render(Decor {
		colour: false,
		width: 120,
	});
	assert_eq!(
		lines,
		[
			"ADDRESS                                               STATE       MEMBERS",
			"team@example.org                                      ✔ enabled   alice@example.org,bob@example.org",
			"sales-and-partnerships-for-the-long-name@example.net  ✘ disabled  alice@example.org",
		]
	);
}

#[test]
fn wide_and_coloured_the_header_is_bold_and_the_state_is_painted() {
	let lines = aliases().render(Decor::coloured(120));
	assert!(
		lines[0].starts_with("\x1b[1mADDRESS"),
		"bold header: {:?}",
		lines[0]
	);
	assert!(
		lines[1].contains("\x1b[32m✔ enabled"),
		"green state: {:?}",
		lines[1]
	);
	assert!(
		lines[2].contains("\x1b[2m✘ disabled"),
		"a disabled entry is dimmed, not red: {:?}",
		lines[2]
	);
	let plain = aliases().render(Decor {
		colour: false,
		width: 120,
	});
	let stripped: Vec<String> = lines.iter().map(|line| visible(line)).collect();
	assert_eq!(stripped, plain, "colour adds escapes and nothing else");
}

#[test]
fn narrow_rows_are_cut_with_an_ellipsis_and_never_pass_the_width() {
	for colour in [false, true] {
		let lines = aliases().render(Decor { colour, width: 40 });
		assert_eq!(lines.len(), 3);
		for line in &lines {
			let seen = visible(line);
			assert!(
				seen.chars().count() <= 40,
				"{} columns: {seen:?}",
				seen.chars().count()
			);
		}
		let long = visible(&lines[2]);
		assert!(long.contains('…'), "the long address is cut: {long:?}");
		assert!(
			long.contains("✘ disabled"),
			"the state survives the cut: {long:?}"
		);
	}
}

#[test]
fn the_state_column_keeps_its_place_at_forty_columns() {
	let lines = aliases().render(Decor {
		colour: false,
		width: 40,
	});
	let at = |line: &str| visible(line).chars().position(|c| c == '✔' || c == '✘');
	assert!(
		at(&lines[1]).is_some(),
		"the state is on screen: {lines:#?}"
	);
	assert_eq!(at(&lines[1]), at(&lines[2]), "{lines:#?}");
}

#[test]
fn a_control_character_in_a_cell_is_escaped_before_it_reaches_the_terminal() {
	let mut table = Table::new(&["NAME", "STATE"]).state_col(1);
	table.push(vec!["evil\x1b[2Jname".into(), "enabled".into()]);
	let lines = table.render(Decor {
		colour: false,
		width: 120,
	});
	assert!(!lines[1].contains('\x1b'), "{:?}", lines[1]);
	assert!(lines[1].contains("evil\\u{1b}[2Jname"), "{:?}", lines[1]);
}

#[test]
fn a_word_without_a_state_is_left_as_it_is() {
	let mut table = Table::new(&["SERVICE", "STATE"]).state_col(1);
	table.push(vec!["smtp".into(), "queued".into()]);
	let lines = table.render(Decor {
		colour: true,
		width: 120,
	});
	assert_eq!(visible(&lines[1]), "smtp     queued");
}
