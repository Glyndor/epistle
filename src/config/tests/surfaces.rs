//! The HTTP surfaces of the API: which listeners serve which, and what the
//! configuration refuses.

use super::*;
use crate::api::{Surface, Surfaces};

const OAUTH: &str = "[oauth]\nissuer = \"https://mail.example.org\"\naudience = \"mail\"\n\
	algorithm = \"ES256\"\npublic_key = \"AAAA\"\nsigning_key_file = \"/run/secrets/oauth.key\"\n";

fn load(body: &str) -> Result<Config, ConfigError> {
	let file = write_temp(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\"]\n{body}"
	));
	Config::load(file.path())
}

fn served(config: &Config, kind: ListenerKind) -> Vec<&'static str> {
	Surfaces::for_listener(config, kind)
		.iter()
		.map(Surface::name)
		.collect()
}

#[test]
fn absent_surfaces_api_serves_everything() {
	let config = load("[[listeners]]\nkind = \"api\"\n[api]\n").expect("a 0.14.0 file");
	assert_eq!(
		served(&config, ListenerKind::Api),
		["manage", "jmap", "oauth", "scim"]
	);
	assert_eq!(
		Surfaces::for_listener(&config, ListenerKind::Api),
		Surfaces::all()
	);
}

#[test]
fn a_listener_of_its_own_takes_the_surface_off_api() {
	let config = load(&format!(
		"[[listeners]]\nkind = \"api\"\n[[listeners]]\nkind = \"jmap\"\n[[listeners]]\nkind = \"oauth\"\n\
		 [api]\n{OAUTH}"
	))
	.expect("loads");
	assert_eq!(served(&config, ListenerKind::Api), ["manage", "scim"]);
	assert_eq!(served(&config, ListenerKind::Jmap), ["jmap"]);
	assert_eq!(served(&config, ListenerKind::Oauth), ["oauth"]);
}

#[test]
fn surfaces_present_serve_management_and_what_is_listed() {
	let config =
		load("[[listeners]]\nkind = \"api\"\n[api]\nsurfaces = [\"scim\"]\n").expect("loads");
	assert_eq!(served(&config, ListenerKind::Api), ["manage", "scim"]);
	let config = load("[[listeners]]\nkind = \"api\"\n[api]\nsurfaces = []\n").expect("loads");
	assert_eq!(served(&config, ListenerKind::Api), ["manage"]);
}

#[test]
fn surface_listed_and_listened_is_an_error() {
	let message = load(
		"[[listeners]]\nkind = \"api\"\n[[listeners]]\nkind = \"scim\"\n\
		 [api]\nsurfaces = [\"scim\"]\n",
	)
	.expect_err("two places")
	.to_string();
	assert!(message.contains("surfaces lists \"scim\""), "{message}");
	assert!(message.contains("listener on 127.0.0.1:8027"), "{message}");
}

#[test]
fn surface_names_are_the_three_that_can_be_split_off() {
	for name in ["manage", "mail", "JMAP", ""] {
		let text = format!("[[listeners]]\nkind = \"api\"\n[api]\nsurfaces = [\"{name}\"]\n");
		assert!(load(&text).is_err(), "{name:?}");
	}
	let twice = load("[[listeners]]\nkind = \"api\"\n[api]\nsurfaces = [\"jmap\", \"jmap\"]\n");
	assert!(
		twice
			.expect_err("twice")
			.to_string()
			.contains("more than once")
	);
}

#[test]
fn a_surface_listener_needs_the_api_section() {
	for kind in ["jmap", "scim"] {
		let message = load(&format!("[[listeners]]\nkind = \"{kind}\"\n"))
			.expect_err("no [api]")
			.to_string();
		assert!(
			message.contains(&format!("\"{kind}\" but no [api]")),
			"{message}"
		);
	}
}

#[test]
fn an_oauth_listener_needs_a_signing_key() {
	let message = load("[[listeners]]\nkind = \"oauth\"\n[api]\n")
		.expect_err("no key")
		.to_string();
	assert!(message.contains("signing_key"), "{message}");
	load(&format!("[[listeners]]\nkind = \"oauth\"\n[api]\n{OAUTH}")).expect("with a key");
}

#[test]
fn the_new_kinds_have_their_ports_and_names() {
	for (kind, port, name) in [
		(ListenerKind::Jmap, 8026, "jmap"),
		(ListenerKind::Scim, 8027, "scim"),
		(ListenerKind::Oauth, 8028, "oauth"),
	] {
		assert_eq!(
			(kind.default_port(), kind.as_str(), kind.serves_api()),
			(port, name, true)
		);
	}
	assert!(ListenerKind::Api.serves_api());
	assert!(!ListenerKind::WebDav.serves_api());
}
