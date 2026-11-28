//! The command and the routes change an account the same way: the same
//! result, the same refusals, the same addresses at the end.

use std::process::ExitCode;

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;
use crate::cli::account::actions::{address_add_with_store, address_remove_with_store};

fn cli(world: &World, verb: &str, name: &str, address: &str) -> (bool, Option<serde_json::Value>) {
	let mut out = Vec::new();
	let code = match verb {
		"add" => address_add_with_store(&world.store, name, address, &mut out, true),
		_ => address_remove_with_store(&world.store, name, address, &mut out, true),
	};
	(code == ExitCode::SUCCESS, serde_json::from_slice(&out).ok())
}

async fn route(world: &World, verb: &str, name: &str, address: &str) -> (bool, serde_json::Value) {
	let (status, body) = match verb {
		"add" => {
			call(
				&world.state,
				"POST",
				&format!("/api/v1/accounts/{name}/addresses"),
				token(),
				Some(json!({"address": address})),
			)
			.await
		}
		_ => {
			call(
				&world.state,
				"DELETE",
				&format!("/api/v1/accounts/{name}/addresses/{address}"),
				token(),
				None,
			)
			.await
		}
	};
	(
		status == StatusCode::CREATED || status == StatusCode::OK,
		body,
	)
}

#[tokio::test]
async fn the_command_and_the_route_agree_on_every_step() {
	let by_command = world();
	let by_route = world();
	for (verb, name, address) in [
		("add", "alice", "new@a.test"),
		("add", "alice", "NEW@a.test"),
		("add", "alice", "bob@b.test"),
		("add", "alice", "x@nowhere.example"),
		("add", "alice", "not an address"),
		("add", "alice", "more@a.test"),
		("add", "alice", "more2@a.test"),
		("add", "alice", "more3@a.test"),
		("add", "nobody", "x@a.test"),
		("remove", "alice", "NEW@a.test"),
		("remove", "alice", "new@a.test"),
		("remove", "bob", "bob@b.test"),
		("remove", "bob", "alice@a.test"),
		("remove", "alice", "alice2@a.test"),
		// The one place of the tenant of `c.test` goes to the first account,
		// and both refuse it to a second.
		("add", "bob", "x@c.test"),
		("add", "alice", "y@c.test"),
		("add", "bob", "z@c.test"),
	] {
		let (done_by_command, printed) = cli(&by_command, verb, name, address);
		let (done_by_route, body) = route(&by_route, verb, name, address).await;
		assert_eq!(done_by_command, done_by_route, "{verb} {name} {address}");
		if done_by_command {
			assert_eq!(
				printed.expect("the command prints its result"),
				body,
				"{verb} {name} {address}"
			);
		}
	}
	for name in ["alice", "bob", "split"] {
		assert_eq!(
			addresses(&by_command, name),
			addresses(&by_route, name),
			"{name}"
		);
	}
}
