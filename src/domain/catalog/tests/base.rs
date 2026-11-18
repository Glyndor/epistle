//! The catalog of a server that knows only its domains, and how a name is
//! matched against it.

use super::*;

fn names(list: &[&str]) -> Vec<String> {
	list.iter().map(|name| (*name).to_string()).collect()
}

#[test]
fn a_bare_catalog_marks_the_switched_off_domains_disabled() {
	let catalog = Catalog::hosting(&names(&["a.example", "b.example"]), &names(&["B.EXAMPLE"]));
	let rows = catalog.rows();
	assert_eq!(rows.len(), 2);
	assert_eq!((rows[0].enabled, rows[0].role), (true, "full"));
	assert_eq!((rows[1].enabled, rows[1].role), (false, "disabled"));
	assert!(rows.iter().all(|row| row.aliases_to.is_empty()));
}

#[test]
fn a_name_matches_without_ascii_case_and_nothing_else() {
	let catalog = Catalog::hosting(&names(&["xn--bcher-kva.example"]), &[]);
	let found = catalog.view("XN--BCHER-KVA.example").expect("ASCII case");
	assert_eq!(found.domain, "XN--BCHER-KVA.example", "named as asked");
	for other in [
		"bücher.example",
		"xn--bcher-kva.example.",
		" xn--bcher-kva.example",
		"",
	] {
		assert_eq!(catalog.view(other), None, "{other:?}");
	}
}

#[test]
fn the_row_of_a_view_carries_its_list_fields() {
	let catalog = Catalog::hosting(&names(&["a.example"]), &[]);
	let view = catalog.view("a.example").expect("hosted");
	assert_eq!(view.row(), catalog.rows()[0]);
}
