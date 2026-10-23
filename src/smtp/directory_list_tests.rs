//! The mailing-list fields of an alias with a `list_id`, as the address and
//! the configured identifier are spelled on the wire. A third review
//! (2026-10-15) found the block interpolated raw: an alias local part carrying
//! `?`, `&` or `%` produced a `mailto` whose query was never the unsubscribe,
//! while the bulk `List-Unsubscribe` encoded the same address, and a `list_id`
//! with a bracket went straight into the field.

use super::Directory;
use crate::smtp::directory::AliasSpec;

fn with_list(alias: &str, list_id: &str) -> Directory {
	Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_aliases([(
		alias.to_string(),
		AliasSpec {
			members: vec!["alice@example.org".to_string()],
			senders: Vec::new(),
			hidden: true,
			list_id: Some(list_id.to_string()),
		},
	)])
}

#[test]
fn the_list_mailtos_encode_the_address_the_way_the_bulk_one_does() {
	for (alias, encoded) in [
		("a?b&c%d@example.org", "a%3Fb%26c%25d"),
		// A slash is atext, so it is one more character a local part may
		// carry, and one more delimiter a URI reads it as: the path of the
		// one-click URL, which RFC 6068 spells as `%2F`.
		("a/b@example.org", "a%2Fb"),
	] {
		let list = with_list(alias, "a.example.org");
		assert_eq!(
			list.list_identity(alias).as_deref(),
			Some(
				format!(
					"List-Id: <a.example.org>\r\nList-Post: <mailto:{encoded}@example.org>\r\n"
				)
				.as_str()
			)
		);
		assert_eq!(
			list.list_unsubscribe(alias).as_deref(),
			Some(
				format!("List-Unsubscribe: <mailto:{encoded}@example.org?subject=unsubscribe>\r\n")
					.as_str()
			)
		);
	}
}

#[test]
fn a_local_part_outside_ascii_is_encoded_rather_than_written_raw() {
	let list = with_list("equipo@example.org", "equipo.example.org");
	let identity = list.list_identity("equipo@example.org").expect("identity");
	assert!(
		identity.contains("<mailto:equipo@example.org>"),
		"{identity}"
	);
	// A configured identifier outside ASCII cannot be composed, so the field
	// goes out without it rather than raw.
	let list = with_list("team@example.org", "equipo\u{00e1}.example.org");
	assert_eq!(list.list_identity("team@example.org"), None);
}

#[test]
fn a_list_id_the_composer_refuses_leaves_the_list_field_out_entirely() {
	// The configuration refuses these at load; the composer is the second
	// gate, for a directory built in process rather than from a config file.
	for list_id in [
		"team>\r\nX-Forged: injected\r\nList-Id: <other",
		"equipo\u{00e1}.example.org",
	] {
		let list = with_list("team@example.org", list_id);
		assert_eq!(
			list.list_identity("team@example.org"),
			None,
			"{list_id:?} reached the message"
		);
		// The unsubscribe names the alias, not the identifier, so it is unaffected.
		assert_eq!(
			list.list_unsubscribe("team@example.org").as_deref(),
			Some("List-Unsubscribe: <mailto:team@example.org?subject=unsubscribe>\r\n")
		);
	}
}

#[test]
fn the_canonical_address_is_the_one_the_fields_name() {
	let list = with_list("Team@EXAMPLE.org", "team.example.org");
	assert_eq!(
		list.list_identity("TEAM@example.ORG").as_deref(),
		Some("List-Id: <team.example.org>\r\nList-Post: <mailto:team@example.org>\r\n")
	);
	assert_eq!(
		list.list_unsubscribe("TEAM@example.ORG").as_deref(),
		Some("List-Unsubscribe: <mailto:team@example.org?subject=unsubscribe>\r\n")
	);
}
