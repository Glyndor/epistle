use super::*;

#[test]
fn every_spelling_of_a_name_is_one_destination() {
	for spelling in [
		"example.com",
		"Example.COM",
		"example.com.",
		" EXAMPLE.com. ",
	] {
		assert_eq!(
			Destination::domain(spelling).as_str(),
			"example.com",
			"{spelling:?}"
		);
	}
	assert_eq!(
		Destination::domain("bücher.example").as_str(),
		"xn--bcher-kva.example"
	);
	assert_eq!(
		Destination::domain("BÜCHER.example."),
		Destination::domain("xn--bcher-kva.example")
	);
	assert_eq!(
		Destination::of_recipient("Bob@Mx.Example.COM."),
		Destination::domain("mx.example.com")
	);
	// A name IDNA refuses is still one key, whatever its case.
	assert_eq!(
		Destination::domain("XN--ZZZZ.Example.").as_str(),
		"xn--zzzz.example"
	);
}

#[test]
fn a_domain_and_an_exchanger_of_the_same_name_are_two_destinations() {
	let domain = Destination::domain("mx.example.net");
	let exchanger = Destination::exchanger("MX.example.net.");
	assert_eq!(domain.as_str(), exchanger.as_str());
	assert_ne!(domain, exchanger);
}
