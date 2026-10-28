use super::{addresses_text, header_values};

#[test]
fn header_values_unfolds_every_occurrence() {
	let message = "X-A: one\r\n two\r\nOther: x\r\nx-a: three\r\n\r\nX-A: body\r\n";
	assert_eq!(header_values(message, "x-a"), ["one two", "three"]);
}

#[test]
fn addresses_render_names_and_groups_and_strip_comments_from_the_address() {
	assert_eq!(
		addresses_text("RealFrom <user-from@domain.org>"),
		"RealFrom <user-from@domain.org>"
	);
	// The comments become a display name; the address itself is intact.
	assert!(
		addresses_text("<user-from (comment)@ (comment) domain.org>")
			.ends_with("<user-from@domain.org>")
	);
	assert_eq!(
		addresses_text("g: a@b.c, d@e.f;, h: i@j.k;"),
		"g: a@b.c, d@e.f;, h: i@j.k;"
	);
}
