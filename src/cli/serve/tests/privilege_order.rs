//! No listener serves a connection before the privileges are dropped.
//!
//! The sockets are bound as root, for the low ports, and the runtime has many
//! threads: a `tokio::spawn` of the task that serves a listener starts it on
//! a worker at once, so a spawn before `drop_privileges` accepts and serves
//! with euid 0 until the main thread reaches the drop. The listener futures
//! are collected and spawned after it. These tests read the sources, because
//! the window is a few instructions wide and no run of the server can be made
//! to land in it.

const SERVE: &str = include_str!("../mod.rs");
const LISTENERS: &str = include_str!("../listeners.rs");
const WEBDAV: &str = include_str!("../webdav.rs");
const TASKS: &str = include_str!("../tasks/mod.rs");

#[test]
fn serve_spawns_nothing_before_it_drops_the_privileges() {
	let drop_at = SERVE
		.find("drop_privileges(")
		.expect("serve drops the privileges");
	let before = &SERVE[..drop_at];
	assert!(
		!before.contains("tokio::spawn"),
		"a task is spawned in serve before drop_privileges"
	);
	// And it does spawn the listeners, after the drop.
	assert!(
		SERVE[drop_at..].contains("tokio::spawn"),
		"the listener tasks are spawned after the drop"
	);
}

#[test]
fn the_helpers_that_build_a_listener_return_the_future_and_do_not_spawn_it() {
	for (name, source) in [
		("listeners.rs", LISTENERS),
		("webdav.rs", WEBDAV),
		("tasks/mod.rs", TASKS),
	] {
		assert!(
			!source.contains("tokio::spawn"),
			"{name} spawns a listener task: it has to return the future and let serve spawn it after the drop"
		);
	}
}
