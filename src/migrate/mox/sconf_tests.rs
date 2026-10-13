use super::*;

#[test]
fn maps_lists_and_nested_blocks() {
	let doc =
		Doc::parse("A: 1\nB:\n\tC: two words\n\tL:\n\t\t- x\n\t\t-\n\t\t\tK: v\n# comment\nD: \n")
			.expect("parse");
	assert_eq!(doc.get(&path(&["A"])), Some("1"));
	assert_eq!(doc.get(&path(&["B", "C"])), Some("two words"));
	assert_eq!(
		doc.list(&path(&["B", "L"])),
		vec!["x".to_string(), String::new()]
	);
	let item = [path(&["B", "L"]), vec![Seg::Index(1)], path(&["K"])].concat();
	assert_eq!(doc.get(&item), Some("v"));
	assert_eq!(
		doc.keys(&path(&["B"])),
		vec!["C".to_string(), "L".to_string()]
	);
}

#[test]
fn bad_indentation_is_an_error_with_the_line() {
	assert_eq!(
		Doc::parse("A:\n  B: 1\n").err(),
		Some(SconfError::Indentation(2))
	);
	assert_eq!(
		Doc::parse("A: 1\n\t\tB: 2\n").err(),
		Some(SconfError::Indentation(2))
	);
	assert_eq!(
		Doc::parse("A:\n\tjust words\n").err(),
		Some(SconfError::Syntax(2))
	);
}

#[test]
fn depth_and_size_are_bounded() {
	let mut deep = String::new();
	for level in 0..=MAX_DEPTH {
		deep.push_str(&"\t".repeat(level));
		deep.push_str("K:\n");
	}
	assert!(matches!(Doc::parse(&deep), Err(SconfError::TooDeep(_))));
	let mut ok = String::new();
	for level in 0..MAX_DEPTH {
		ok.push_str(&"\t".repeat(level));
		ok.push_str("K:\n");
	}
	assert!(Doc::parse(&ok).is_ok());
	assert_eq!(
		Doc::parse(&"x".repeat(MAX_BYTES + 1)).err(),
		Some(SconfError::TooLarge)
	);
}

#[test]
fn the_fixture_parses() {
	let doc = Doc::parse(super::super::fixture::DOMAINS_CONF).expect("parse");
	assert_eq!(doc.keys(&path(&["Domains"])).len(), 2);
	assert_eq!(
		doc.list(&path(&["Domains", "example.com", "DKIM", "Sign"])),
		["2024a", "2024b"]
	);
}
