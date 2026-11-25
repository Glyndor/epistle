//! Enabling and disabling the listeners that split a surface off the API
//! listener: the surface is served in one place, and a disabled one is off.

use super::*;
use crate::api::{Surface, Surfaces};
use crate::config::{Config, ListenerKind};
use std::fs;

const OAUTH: &str = "[oauth]\nissuer = \"https://mail.example.org\"\naudience = \"mail\"\n\
	algorithm = \"ES256\"\npublic_key = \"AAAA\"\nsigning_key_file = \"/run/secrets/oauth.key\"\n";

fn file(api_keys: &str, listeners: &[&str]) -> tempfile::NamedTempFile {
	let mut text = String::from(
		"hostname = \"mail.example.org\"\ndomains = [\"example.org\"]\ndata_dir = \"/var/lib/epistle\"\n\
		 [[listeners]]\nkind = \"smtp\"\n",
	);
	for kind in listeners {
		text.push_str(&format!("[[listeners]]\nkind = \"{kind}\"\n"));
	}
	text.push_str(&format!("[api]\n{api_keys}\n{OAUTH}"));
	let file = tempfile::NamedTempFile::new().expect("file");
	fs::write(file.path(), text).expect("write");
	file
}

fn api_serves(path: &std::path::Path) -> Vec<&'static str> {
	let config = Config::load(path).expect("loads");
	Surfaces::for_listener(&config, ListenerKind::Api)
		.iter()
		.map(Surface::name)
		.collect()
}

#[test]
fn enabling_jmap_adds_its_listener_and_takes_jmap_off_api() {
	let file = file("", &["api"]);
	assert_eq!(api_serves(file.path()), ["manage", "jmap", "oauth", "scim"]);
	assert!(set_listener_enabled(file.path(), ListenerKind::Jmap, true).unwrap());
	let config = Config::load(file.path()).unwrap();
	let jmap = config
		.listeners
		.iter()
		.find(|listener| listener.kind == ListenerKind::Jmap)
		.expect("the listener");
	assert_eq!(jmap.socket_addr().to_string(), "127.0.0.1:8026");
	assert_eq!(api_serves(file.path()), ["manage", "oauth", "scim"]);
}

#[test]
fn enabling_a_surface_that_was_listed_unlists_it() {
	let file = file("surfaces = [\"jmap\", \"scim\"]", &["api"]);
	assert!(set_listener_enabled(file.path(), ListenerKind::Jmap, true).unwrap());
	let config = Config::load(file.path()).expect("not refused for serving jmap twice");
	assert_eq!(
		config.api.expect("[api]").surfaces,
		Some(vec!["scim".to_string()])
	);
}

#[test]
fn disable_jmap_turns_jmap_off() {
	let file = file("", &["api", "jmap"]);
	assert_eq!(api_serves(file.path()), ["manage", "oauth", "scim"]);
	assert!(set_listener_enabled(file.path(), ListenerKind::Jmap, false).unwrap());
	let config = Config::load(file.path()).unwrap();
	assert!(
		config
			.listeners
			.iter()
			.all(|listener| listener.kind != ListenerKind::Jmap)
	);
	// JMAP is not handed back to `api`, and what `api` served it still serves.
	assert_eq!(api_serves(file.path()), ["manage", "oauth", "scim"]);
	assert_eq!(
		config.api.expect("[api]").surfaces,
		Some(vec!["oauth".to_string(), "scim".to_string()])
	);
}

#[test]
fn disabling_a_surface_leaves_the_others_with_their_own_listeners() {
	let file = file("", &["api", "jmap", "scim"]);
	assert!(set_listener_enabled(file.path(), ListenerKind::Jmap, false).unwrap());
	let config = Config::load(file.path()).unwrap();
	assert_eq!(
		config.api.as_ref().expect("[api]").surfaces,
		Some(vec!["oauth".to_string()]),
		"scim keeps its listener, so `api` does not list it"
	);
	assert!(
		config
			.listeners
			.iter()
			.any(|listener| listener.kind == ListenerKind::Scim)
	);
}

#[test]
fn an_oauth_listener_without_a_signing_key_is_refused() {
	let file = tempfile::NamedTempFile::new().expect("file");
	fs::write(
		file.path(),
		"hostname = \"mail.example.org\"\ndomains = [\"example.org\"]\ndata_dir = \"/d\"\n\
		 [[listeners]]\nkind = \"smtp\"\n[api]\n",
	)
	.expect("write");
	let error = set_listener_enabled(file.path(), ListenerKind::Oauth, true).unwrap_err();
	assert!(error.contains("signing_key"), "{error}");
}

#[test]
fn enabling_a_surface_listener_creates_the_api_section() {
	let file = tempfile::NamedTempFile::new().expect("file");
	fs::write(
		file.path(),
		"hostname = \"mail.example.org\"\ndomains = [\"example.org\"]\ndata_dir = \"/d\"\n\
		 [[listeners]]\nkind = \"smtp\"\n",
	)
	.expect("write");
	assert!(set_listener_enabled(file.path(), ListenerKind::Scim, true).unwrap());
	assert!(Config::load(file.path()).unwrap().api.is_some());
}

/// `disable` on a surface that has no listener of its own but is served by the
/// `api` listener turns it off: there is no listener to remove, and that is no
/// reason to say "nothing changed".
#[test]
fn disable_turns_off_a_surface_that_only_the_api_listener_serves() {
	for (kind, name) in [
		(ListenerKind::Jmap, "jmap"),
		(ListenerKind::Scim, "scim"),
		(ListenerKind::Oauth, "oauth"),
	] {
		for api_keys in [
			String::new(),
			"surfaces = [\"jmap\", \"oauth\", \"scim\"]".to_string(),
		] {
			let file = file(&api_keys, &["api"]);
			let before = api_serves(file.path());
			assert!(before.contains(&name), "{name}: the api listener serves it");
			assert!(
				set_listener_enabled(file.path(), kind, false).unwrap(),
				"{name} {api_keys:?}: the first disable is a change"
			);
			let after = api_serves(file.path());
			assert!(!after.contains(&name), "{name}: {after:?}");
			let others: Vec<_> = before.iter().filter(|other| **other != name).collect();
			assert_eq!(
				after.iter().collect::<Vec<_>>(),
				others,
				"{name}: the rest stays"
			);
			let config = Config::load(file.path()).unwrap();
			assert_eq!(
				config
					.api
					.as_ref()
					.and_then(|api| api.token_hash.as_deref()),
				None
			);
			assert!(config.oauth.is_some(), "the [oauth] section is kept");
			let bytes = fs::read(file.path()).unwrap();
			assert!(
				!set_listener_enabled(file.path(), kind, false).unwrap(),
				"{name}: the second disable changes nothing"
			);
			assert_eq!(fs::read(file.path()).unwrap(), bytes);
		}
	}
}

#[test]
fn disable_with_no_api_listener_still_changes_nothing() {
	let file = file("", &[]);
	let bytes = fs::read(file.path()).unwrap();
	assert!(!set_listener_enabled(file.path(), ListenerKind::Jmap, false).unwrap());
	assert_eq!(fs::read(file.path()).unwrap(), bytes);
}
