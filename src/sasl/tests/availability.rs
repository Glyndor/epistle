use super::*;

#[test]
fn channel_binding_gates_plus() {
	assert!(available(false, false, true, false).contains(&Mechanism::ScramSha256));
	assert!(!available(false, false, true, false).contains(&Mechanism::ScramSha256Plus));
	assert!(available(false, true, true, false).contains(&Mechanism::ScramSha256Plus));
	// -PLUS is offered strongest-first (no EXTERNAL present).
	assert_eq!(
		available(false, true, true, false)[0],
		Mechanism::ScramSha256Plus
	);
}

#[test]
fn external_gates_on_client_certificate() {
	assert!(!available(false, false, true, false).contains(&Mechanism::External));
	assert!(available(true, false, true, false).contains(&Mechanism::External));
	// EXTERNAL is the strongest, offered first.
	assert_eq!(available(true, true, true, false)[0], Mechanism::External);
	assert_eq!(Mechanism::parse("external"), Some(Mechanism::External));
}

#[test]
fn oauth_gates_bearer_mechanisms() {
	assert!(!available(false, false, true, false).contains(&Mechanism::OauthBearer));
	assert!(available(false, false, true, true).contains(&Mechanism::OauthBearer));
	assert!(available(false, false, true, true).contains(&Mechanism::Xoauth2));
}

#[test]
fn scram_off_drops_scram_mechanisms_but_keeps_plain_and_login() {
	// `[auth] scram = false`: PLAIN and LOGIN stay in (the password still
	// authenticates); both SCRAM-SHA-256 and `-PLUS` disappear from the
	// advertised set and from `is_available`.
	let advertised = available(false, false, false, false);
	assert!(!advertised.contains(&Mechanism::ScramSha256));
	assert!(!advertised.contains(&Mechanism::ScramSha256Plus));
	assert!(advertised.contains(&Mechanism::Plain));
	assert!(advertised.contains(&Mechanism::Login));
	assert!(!is_available(
		Mechanism::ScramSha256,
		false,
		false,
		false,
		false
	));
	assert!(!is_available(
		Mechanism::ScramSha256Plus,
		false,
		true,
		false,
		false
	));
	// Channel binding on its own does not re-enable -PLUS when SCRAM is
	// off: a tls-server-end-point hash should not bring -PLUS back.
	let with_cbind = available(false, true, false, false);
	assert!(!with_cbind.contains(&Mechanism::ScramSha256Plus));
	assert!(!with_cbind.contains(&Mechanism::ScramSha256));
}

#[test]
fn is_available_matches_advertised() {
	assert!(is_available(Mechanism::Plain, false, false, true, false));
	assert!(!is_available(
		Mechanism::External,
		false,
		false,
		true,
		false
	));
	assert!(is_available(Mechanism::External, true, false, true, false));
	assert!(!is_available(
		Mechanism::ScramSha256Plus,
		false,
		false,
		true,
		false
	));
	assert!(is_available(
		Mechanism::ScramSha256Plus,
		false,
		true,
		true,
		false
	));
	assert!(!is_available(
		Mechanism::OauthBearer,
		false,
		false,
		true,
		false
	));
	assert!(is_available(
		Mechanism::OauthBearer,
		false,
		false,
		true,
		true
	));
}
