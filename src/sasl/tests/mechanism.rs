use super::*;

#[test]
fn parse_is_case_insensitive_and_total() {
	assert_eq!(Mechanism::parse("plain"), Some(Mechanism::Plain));
	assert_eq!(
		Mechanism::parse("Scram-Sha-256"),
		Some(Mechanism::ScramSha256)
	);
	assert_eq!(
		Mechanism::parse("SCRAM-SHA-256-PLUS"),
		Some(Mechanism::ScramSha256Plus)
	);
	assert_eq!(Mechanism::parse("XOAUTH2"), Some(Mechanism::Xoauth2));
	assert_eq!(Mechanism::parse("DIGEST-MD5"), None);
	assert_eq!(Mechanism::parse(""), None);
}

#[test]
fn name_round_trips_through_parse() {
	for mechanism in available(true, true, true, true) {
		assert_eq!(Mechanism::parse(mechanism.name()), Some(mechanism));
	}
}
