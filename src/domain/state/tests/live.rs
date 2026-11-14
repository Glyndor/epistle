//! The live state reloads a valid file, keeps the running state on a file
//! the server would refuse, and tells every listener.

use std::sync::{Arc, Mutex};

use super::super::DomainsFile;
use super::Fixture;
use crate::editable::LiveConfig;

fn watched(live: &LiveConfig) -> Arc<Mutex<Vec<Vec<String>>>> {
	let seen = Arc::new(Mutex::new(Vec::new()));
	let sink = Arc::clone(&seen);
	live.on_change(move |config| sink.lock().unwrap().push(config.domains.clone()));
	seen
}

#[test]
fn a_reload_replaces_the_domains_and_tells_every_listener() {
	let fixture = Fixture::new("");
	let live = LiveConfig::new(fixture.load());
	let seen = watched(&live);
	live.reload::<DomainsFile>(
		"[[domain]]\nname = \"example.org\"\n[[domain]]\nname = \"new.example\"\n",
	)
	.expect("a valid file loads");
	assert_eq!(live.current().domains, ["example.org", "new.example"]);
	assert_eq!(
		*seen.lock().unwrap(),
		[vec!["example.org".to_string(), "new.example".to_string()]]
	);
}

#[test]
fn a_file_the_server_would_refuse_keeps_the_running_state() {
	let fixture = Fixture::new("[[listeners]]\nkind = \"smtp\"\nport = 2525\n");
	let live = LiveConfig::new(fixture.load());
	let seen = watched(&live);
	for bad in [
		"[[domain]]\nname = ",
		"[[domain]]\nname = \"example.org\"\nrole = \"everything\"\n",
		"[aliases]\n\"alias.example\" = \"nowhere.example\"\n[[domain]]\nname = \"example.org\"\n",
		"[[domain]]\nname = \"bad name\"\n",
		"surprise = 1\n",
	] {
		assert!(
			live.reload::<DomainsFile>(bad).is_err(),
			"{bad:?} is refused"
		);
	}
	assert_eq!(live.current().domains, ["example.org", "other.example.org"]);
	assert!(seen.lock().unwrap().is_empty(), "no listener was told");
}

#[test]
fn a_missing_file_puts_the_configuration_file_lists_back() {
	let fixture = Fixture::new("");
	let live = LiveConfig::new(fixture.load());
	live.reload::<DomainsFile>("[[domain]]\nname = \"only.example\"\n")
		.unwrap();
	live.reload::<DomainsFile>("")
		.expect("a missing file is the seed");
	assert_eq!(live.current().domains, ["example.org", "other.example.org"]);
}

#[test]
fn the_watcher_reaches_only_the_files_the_server_follows() {
	use crate::directory_store::file_watcher::StateReloader;
	let fixture = Fixture::new("");
	let live = LiveConfig::new(fixture.load());
	assert!(live.files().is_empty());
	assert!(
		live.reload_state("domains.toml", "").is_err(),
		"not followed yet"
	);
	live.track::<DomainsFile>();
	live.track::<DomainsFile>();
	assert_eq!(live.files(), ["domains.toml"]);
	live.reload_state("domains.toml", "[[domain]]\nname = \"example.org\"\n")
		.expect("followed");
	assert_eq!(live.current().domains, ["example.org"]);
	assert!(live.reload_state("aliases.toml", "").is_err());
}
