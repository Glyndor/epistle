//! `status` and `check` drawn for a terminal: symbols, colour, the width,
//! and the plain form left exactly as it was.

use super::super::CheckArea;
use super::*;
use crate::cli::term::Decor;
use crate::cli::term::table::tests::visible;

fn reports() -> Vec<(CheckArea, AreaReport)> {
	vec![
		(CheckArea::Config, AreaReport::ok("mail.toml loads")),
		(
			CheckArea::Ports,
			AreaReport::from_items(
				vec![Item::new(
					"smtp 127.0.0.1:25",
					Level::Fail,
					"connection refused by the listener on the loopback address",
				)],
				"0 of 1 listeners answer",
			),
		),
		(
			CheckArea::Tls,
			AreaReport::single(Level::Warn, "no [tls] certificate is configured"),
		),
	]
}

fn render(show_items: bool, decor: Option<Decor>) -> String {
	let mut out = Vec::new();
	render_table(&reports(), show_items, decor, &mut out).expect("render");
	String::from_utf8(out).expect("utf-8")
}

#[test]
fn without_a_terminal_the_report_is_the_plain_one() {
	assert_eq!(
		render(true, None),
		"config     ok    mail.toml loads\n\
		 ports      fail  0 of 1 listeners answer\n  \
		 fail  smtp 127.0.0.1:25: connection refused by the listener on the loopback address\n\
		 tls        warn  no [tls] certificate is configured\n"
	);
}

#[test]
fn on_a_wide_terminal_each_area_carries_its_symbol() {
	let text = render(
		false,
		Some(Decor {
			colour: false,
			width: 120,
		}),
	);
	assert_eq!(
		text,
		"AREA    STATE   DETAIL\n\
		 config  ✔ ok    mail.toml loads\n\
		 ports   ✘ fail  0 of 1 listeners answer\n\
		 tls     ⚠ warn  no [tls] certificate is configured\n"
	);
}

#[test]
fn with_colour_the_symbols_are_green_yellow_and_red() {
	let text = render(false, Some(Decor::coloured(120)));
	assert!(text.contains("\x1b[32m✔ ok"), "{text:?}");
	assert!(text.contains("\x1b[33m⚠ warn"), "{text:?}");
	assert!(text.contains("\x1b[31m✘ fail"), "{text:?}");
}

#[test]
fn check_lists_the_findings_under_their_area_inside_the_width() {
	for colour in [false, true] {
		let text = render(true, Some(Decor { colour, width: 40 }));
		let lines: Vec<String> = text.lines().map(visible).collect();
		assert_eq!(lines.len(), 5, "{lines:#?}");
		assert!(
			lines[3].starts_with("  ✘ fail  smtp 127.0.0.1:25: conn"),
			"{lines:#?}"
		);
		for line in &lines {
			assert!(line.chars().count() <= 40, "{line:?}");
		}
		assert!(lines[3].ends_with('…'), "{lines:#?}");
	}
}
