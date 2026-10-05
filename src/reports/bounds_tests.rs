use super::*;
use crate::reports::bounds as bounds_mod;

#[test]
fn a_plain_name_is_kept() {
	assert_eq!(file_component("google.com"), "google.com");
	assert_eq!(file_component("Yahoo-Inc"), "Yahoo-Inc");
}

#[test]
fn separators_and_parent_references_are_mapped() {
	let component = file_component("../../etc/cron.d/x");
	assert_eq!(component, ".._.._etc_cron.d_x");
	assert!(!component.contains('/'), "{component}");
	// The exact shape the file-component mapping must hold: a hostile
	// `org_name` cannot leave the day directory it is joined to.
	assert_eq!(file_component("../../etc/passwd"), ".._.._etc_passwd");
	assert_eq!(file_component("a\\b\0c"), "a_b_c");
}

#[test]
fn names_made_of_dots_and_the_empty_name_map_to_unknown() {
	for name in ["", ".", "..", "....."] {
		assert_eq!(file_component(name), "unknown", "{name:?}");
	}
	// A dot next to anything else is an ordinary name.
	assert_eq!(file_component("..a"), "..a");
}

#[test]
fn non_ascii_letters_become_underscores() {
	let component = file_component("Correo Ñandú");
	assert_eq!(component, "Correo__and_");
	assert!(component.is_ascii());
}

#[test]
fn a_name_at_the_component_limit_is_kept_whole() {
	let name = "a".repeat(MAX_FILE_COMPONENT);
	assert_eq!(file_component(&name), name);
}

#[test]
fn a_name_over_the_component_limit_is_cut() {
	let name = "a".repeat(MAX_FILE_COMPONENT + 1);
	assert_eq!(file_component(&name).len(), MAX_FILE_COMPONENT);
	let huge = "é/".repeat(5_000);
	assert_eq!(huge.len(), 15_000);
	let component = file_component(&huge);
	assert_eq!(component.len(), MAX_FILE_COMPONENT);
	assert!(component.chars().all(|c| c == '_'), "{component}");
}

#[test]
fn text_at_the_limit_is_kept_whole() {
	let text = "é".repeat(MAX_TEXT);
	assert_eq!(cap_text(&text, MAX_TEXT), text);
}

#[test]
fn text_over_the_limit_is_cut_on_a_character_boundary() {
	let text = "é".repeat(MAX_TEXT + 1);
	let capped = cap_text(&text, MAX_TEXT);
	assert_eq!(capped.chars().count(), MAX_TEXT);
	assert_eq!(capped, "é".repeat(MAX_TEXT));
}

#[test]
fn control_characters_do_not_survive() {
	assert_eq!(
		cap_text("a\x1b[2Jb\r\n", MAX_TEXT),
		"a\u{FFFD}[2Jb\u{FFFD}\u{FFFD}"
	);
	let mut text = String::from("ok\x07");
	cap_in_place(&mut text, MAX_TEXT);
	assert_eq!(text, "ok\u{FFFD}");
}

#[derive(Debug, serde::Deserialize)]
struct Holder {
	#[serde(deserialize_with = "three")]
	items: Vec<u8>,
}

fn three<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
	bounds_mod::capped_seq(deserializer, 3)
}

#[test]
fn a_list_at_the_limit_is_collected() {
	let holder: Holder = serde_json::from_str(r#"{"items":[1,2,3]}"#).expect("three fit");
	assert_eq!(holder.items, [1, 2, 3]);
}

#[test]
fn a_list_over_the_limit_is_capped_at_max_plus_one() {
	// `capped_seq` stops reading at max+1 entries: the four input
	// elements become four output entries so the caller can detect
	// overflow via length.
	let holder: Holder = serde_json::from_str(r#"{"items":[1,2,3,4]}"#).expect("capped");
	assert_eq!(holder.items.len(), 4, "{holder:?}");
}

#[test]
fn truncate_returns_a_flag_and_a_truncated_vec() {
	let (flag, kept) = bounds_mod::truncate(vec![1, 2, 3, 4, 5], 3);
	assert!(flag);
	assert_eq!(kept, vec![1, 2, 3]);
	let (flag, kept) = bounds_mod::truncate(vec![1, 2, 3], 3);
	assert!(!flag);
	assert_eq!(kept, vec![1, 2, 3]);
}
