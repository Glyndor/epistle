//! What an alias may declare as its list identity. The list block writes the
//! value between the angle brackets of a `List-Id` field as it stands, so only
//! an identifier RFC 2919 can carry there is accepted: a bracket or a line
//! break would put headers of its own into every copy the list receives, and a
//! phrase would be read as two words rather than as the identifier.

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
fn an_alias_with_an_identifier_it_can_carry_is_accepted() {
	for list_id in [
		"team.example.org",
		"TEAM.Example.Org",
		"list+team.example.org",
	] {
		assert!(
			alias(Some(list_id)).validate().is_ok(),
			"{list_id} is an identifier a List-Id can carry"
		);
	}
	assert!(
		alias(None).validate().is_ok(),
		"a plain alias is not a list"
	);
}

#[test]
fn a_list_id_that_would_end_the_field_or_is_not_an_identifier_is_refused() {
	for list_id in [
		"",
		// An empty value once the surrounding whitespace is gone.
		"   ",
		">",
		">other.example",
		// A `<` opens a second pair of brackets inside the ones the server
		// writes, so the identifier reaches the field half open.
		"<other.example",
		"team.example.org<",
		"team>\r\nX-Forged: injected\r\nList-Id: <other",
		"team>extra",
		// RFC 2919 allows a phrase of the form `Team List <team.example.org>`,
		// but the value is written between the brackets the server adds, so
		// one written that way cannot be carried, and a bare phrase is not an
		// identifier either.
		"Team List <team.example.org>",
		"Team List team.example.org",
		"team\nexample.org",
		"team\texample.org",
		"team\u{0}example.org",
		"equipo\u{00e1}.example.org",
		// A dot-atom has no empty atom between its dots or at either end.
		".team.example.org",
		"team..example.org",
		"team.example.org.",
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
