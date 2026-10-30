//! The scanner against fixtures. They cite missing paths on purpose, which is
//! why `every_cited_path_exists` does not read this file.

use std::path::Path;

use super::{citations, cited_paths, glob_match, markdown, problem, rust_source};

fn found(segments: Vec<(usize, String)>) -> Vec<String> {
	cited_paths(&segments)
		.into_iter()
		.map(|(line, path)| format!("{line}:{path}"))
		.collect()
}

#[test]
fn a_citation_stops_where_the_path_stops() {
	let text = "see `src/a.rs::f`, src/b.rs:12, (docs/c.md) and docs/d.md.";
	let paths: Vec<String> = citations(text).into_iter().map(|(_, path)| path).collect();
	assert_eq!(paths, ["src/a.rs", "src/b.rs", "docs/c.md", "docs/d.md"]);
}

#[test]
fn a_path_glued_to_a_longer_one_is_not_a_citation() {
	let text = "crates/common/src/x.rs apt/tests/y.sh https://h.example/docs/z.md contests/a";
	assert!(citations(text).is_empty(), "{:?}", citations(text));
}

#[test]
fn a_placeholder_is_not_a_citation() {
	let shapes = "src/<domain>/mod.rs src/{name}.rs src/{} src/{a b}";
	assert!(citations(shapes).is_empty(), "{:?}", citations(shapes));
	let alternatives = citations("src/{imap,pop3}/mod.rs");
	assert_eq!(alternatives, [(0, "src/{imap,pop3}/mod.rs".to_string())]);
}

#[test]
fn a_missing_path_is_reported_and_a_present_one_is_not() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	assert_eq!(problem("docs/a.md", "src/lib.rs", &[], root), None);
	assert_eq!(
		problem("docs/a.md", "src/no_such_file.rs", &[], root),
		Some("does not exist")
	);
	assert_eq!(problem("docs/api.md", "../src/lib.rs", &[], root), None);
	assert_eq!(
		problem("README.md", "../src/lib.rs", &[], root),
		Some("points outside the repository")
	);
}

#[test]
fn a_glob_must_match_at_least_one_file() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	let tree = [
		"src/b.rs".to_string(),
		"src/imap/mod.rs".into(),
		"tests/db/core/database_x.rs".into(),
	];
	for pattern in [
		"src/imap/**",
		"src/**/*.rs",
		"src/*.rs",
		"tests/db/core/database*.rs",
		"src/{pop3,imap}/mod.rs",
		"src/{pop3,imap}/",
	] {
		assert_eq!(
			problem("docs/a.md", pattern, &tree, root),
			None,
			"{pattern}"
		);
	}
	for pattern in [
		"src/pop3/**",
		"src/*/x.rs",
		"tests/*.sh",
		"src/{pop3,smtp}/mod.rs",
		"src/{pop3,smtp}/",
	] {
		assert_eq!(
			problem("docs/a.md", pattern, &tree, root),
			Some("matches no file"),
			"{pattern}"
		);
	}
	assert!(
		!glob_match(b"src/*.rs", b"src/imap/mod.rs"),
		"a single star crossed a directory"
	);
}

#[test]
fn only_a_fence_marked_example_is_skipped() {
	let text = "src/a.rs\n```text example\nsrc/b.rs\n```\n```sh\nsrc/c.rs\n```\n\
	            ~~~~markdown example\n```\nsrc/d.rs\n```\n~~~~\nsrc/e.rs\n\
	            ```` ```text example ```` is inline code, not a fence\nsrc/f.rs\n";
	assert_eq!(
		found(markdown::lines(text)),
		["1:src/a.rs", "6:src/c.rs", "13:src/e.rs", "15:src/f.rs"]
	);
}

#[test]
fn comments_and_strings_are_told_apart_in_rust() {
	let source = "let q = '\"'; // src/a.rs\n\
	              let s = \"src/b.rs\"; /* src/c.rs\n src/d.rs */\n\
	              let r = r#\"src/e.rs \"q\"\"#; fn f<'a>(x: &'a str) {} // tests/f.rs\n";
	assert_eq!(
		found(rust_source::segments(source, false)),
		["1:src/a.rs", "2:src/c.rs", "3:src/d.rs", "4:tests/f.rs"]
	);
	assert_eq!(
		found(rust_source::segments(source, true)),
		[
			"1:src/a.rs",
			"2:src/b.rs",
			"2:src/c.rs",
			"3:src/d.rs",
			"4:src/e.rs",
			"4:tests/f.rs"
		]
	);
}
