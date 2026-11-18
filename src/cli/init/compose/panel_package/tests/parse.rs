//! What the pin file may say: the fixed repository and a plain tag, nothing
//! else. Each rejection asserts which rule fired, and each is paired with an
//! accepted line of the same shape just inside the limit.

use super::*;

const GOOD: &str = "ghcr.io/glyndor/epistle-panel:0.3.1";

#[test]
fn the_line_the_package_writes_is_accepted() {
	assert_eq!(parse(&format!("{GOOD}\n")).as_deref(), Ok(GOOD));
	assert_eq!(parse(GOOD).as_deref(), Ok(GOOD));
}

#[test]
fn tags_with_a_revision_a_prerelease_or_an_underscore_are_accepted() {
	for tag in ["0.3.1-1", "1.0.0-rc.1", "_edge", "2026.11.11", "v1"] {
		let line = format!("{REPOSITORY}:{tag}\n");
		assert_eq!(parse(&line).as_deref(), Ok(line.trim_end()), "{tag}");
	}
}

#[test]
fn a_tag_of_128_characters_is_accepted_and_one_of_129_is_not() {
	let longest = format!("{REPOSITORY}:{}", "a".repeat(128));
	assert_eq!(parse(&longest), Ok(longest.clone()));
	let error = parse(&format!("{longest}a")).expect_err("129");
	assert!(error.contains("1 to 128"), "{error}");
}

#[test]
fn an_empty_file_is_refused() {
	for text in ["", "\n"] {
		assert_eq!(parse(text), Err("it is empty".to_string()), "{text:?}");
	}
}

#[test]
fn a_digest_is_refused_because_the_package_has_none() {
	let error = parse(&format!("{GOOD}@sha256:{}\n", "a".repeat(64))).expect_err("digest");
	assert!(error.contains("the tag"), "{error}");
}

#[test]
fn a_reference_without_a_tag_is_refused() {
	for line in [REPOSITORY.to_string(), format!("{REPOSITORY}:")] {
		let error = parse(&line).expect_err("no tag");
		assert!(
			error.contains("is not ghcr.io/glyndor/epistle-panel:<tag>")
				|| error.contains("the tag"),
			"{error}"
		);
	}
}

#[test]
fn another_repository_is_refused_even_with_a_valid_tag() {
	for line in [
		"ghcr.io/glyndor/epistle:0.3.1",
		"ghcr.io/glyndor/epistle-panelx:0.3.1",
		"ghcr.io/glyndor/epistle-panel-extra:0.3.1",
		"ghcr.io/other/epistle-panel:0.3.1",
		"evil.example/glyndor/epistle-panel:0.3.1",
		"docker.io/ghcr.io/glyndor/epistle-panel:0.3.1",
		"GHCR.IO/glyndor/epistle-panel:0.3.1",
	] {
		let error = parse(line).expect_err(line);
		assert!(
			error.contains("is not ghcr.io/glyndor/epistle-panel:<tag>"),
			"{line}: {error}"
		);
	}
}

#[test]
fn a_second_line_or_stray_whitespace_is_refused() {
	for text in [
		format!("{GOOD}\n{GOOD}\n"),
		format!("{GOOD}\n\n"),
		format!("{GOOD}\r\n"),
		format!(" {GOOD}"),
		format!("{GOOD} "),
		format!("{GOOD}\t"),
		format!("{GOOD}\0"),
		format!("{GOOD} extra\n"),
	] {
		let error = parse(&text).expect_err(&format!("{text:?}"));
		assert!(
			error.contains("one reference on one line"),
			"{text:?}: {error}"
		);
	}
}

#[test]
fn a_tag_outside_the_oci_grammar_is_refused() {
	for tag in ["-1", ".1", "1:2", "1/2", "1+b1", "1~rc1", "1@2", "é"] {
		let error = parse(&format!("{REPOSITORY}:{tag}")).expect_err(tag);
		assert!(error.contains("the tag"), "{tag}: {error}");
	}
}
