//! What an alias may declare as its list identity. RFC 2369 and RFC 2919 put
//! the phrase between angle brackets of a `List-Id` field, and the list block
//! writes that phrase as it stands, so a value carrying a bracket or a line
//! break would put headers of its own into every copy the list receives.

use super::*;

fn alias(list_id: Option<&str>) -> Alias {
	Alias {
		address: "team@example.org".to_string(),
		members: vec!["alice@example.org".to_string()],
		senders: Vec::new(),
		hidden: true,
		list_id: list_id.map(str::to_string),
	}
}

#[test]
fn an_alias_with_a_phrase_it_can_carry_is_accepted() {
	for list_id in ["team.example.org", "Team List team.example.org"] {
		assert!(
			alias(Some(list_id)).validate().is_ok(),
			"{list_id} is a phrase a List-Id can carry"
		);
	}
	assert!(
		alias(None).validate().is_ok(),
		"a plain alias is not a list"
	);
}

#[test]
fn a_list_id_that_would_end_the_field_is_refused() {
	for list_id in [
		"",
		">",
		"team>\r\nX-Forged: injected\r\nList-Id: <other",
		"team>extra",
		// RFC 2919 allows a phrase of the form `Team List <team.example.org>`,
		// but the value is written between the brackets the server adds, so
		// one written that way cannot be carried.
		"Team List <team.example.org>",
		"team\nexample.org",
		"team\texample.org",
		"team\u{0}example.org",
		"equipo\u{00e1}.example.org",
	] {
		assert!(
			alias(Some(list_id)).validate().is_err(),
			"{list_id:?} must not reach a List-Id field"
		);
	}
}

#[test]
fn an_alias_with_no_members_is_refused_before_its_list_id() {
	let mut alias = alias(Some(">"));
	alias.members.clear();
	assert!(alias.validate().is_err());
}
