//! The routers and `openapi.yaml` list the same operations. Adding a route
//! without describing it, describing one that is not registered, or mounting
//! a router this test does not know about fails here.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The router sources, and the path each mounts under. A router in any other
/// production file fails `no_other_file_registers_a_route`.
const ROUTERS: [(&str, &str, &str); 7] = [
	("src/api/mod.rs", include_str!("../mod.rs"), ""),
	("src/api/v1/mod.rs", include_str!("../v1/mod.rs"), "/api/v1"),
	(
		"src/api/scim/mod.rs",
		include_str!("../scim/mod.rs"),
		"/scim/v2",
	),
	("src/api/oauth/mod.rs", include_str!("../oauth/mod.rs"), ""),
	(
		"src/autodiscovery/mod.rs",
		include_str!("../../autodiscovery/mod.rs"),
		"",
	),
	(
		"src/acme/http01/mod.rs",
		include_str!("../../acme/http01/mod.rs"),
		"",
	),
	(
		"src/cli/serve_metrics.rs",
		include_str!("../../cli/serve_metrics.rs"),
		"",
	),
];

const METHODS: [&str; 7] = ["get", "post", "put", "patch", "delete", "head", "options"];

/// `source` up to its test module: the first `#[cfg(test)]` that is followed
/// (past other attributes) by a `mod`.
pub(super) fn production_part(source: &str) -> &str {
	let mut offset = 0;
	let lines: Vec<&str> = source.split_inclusive('\n').collect();
	for (at, line) in lines.iter().enumerate() {
		if line.trim() == "#[cfg(test)]" {
			let next = lines[at + 1..]
				.iter()
				.map(|line| line.trim())
				.find(|line| !line.starts_with("#["));
			if next.is_some_and(|line| line.starts_with("mod ") || line.starts_with("pub mod ")) {
				return &source[..offset];
			}
		}
		offset += line.len();
	}
	source
}

/// The text up to the parenthesis that closes a call whose `(` was just read.
fn call_arguments(after_open: &str) -> &str {
	let (mut depth, mut quoted, mut escaped) = (1usize, false, false);
	for (at, c) in after_open.char_indices() {
		if quoted {
			match (escaped, c) {
				(true, _) => escaped = false,
				(false, '\\') => escaped = true,
				(false, '"') => quoted = false,
				_ => {}
			}
			continue;
		}
		match c {
			'"' => quoted = true,
			'(' => depth += 1,
			')' => {
				depth -= 1;
				if depth == 0 {
					return &after_open[..at];
				}
			}
			_ => {}
		}
	}
	after_open
}

/// The method names called in `text` as `get(`, `.post(` or `routing::delete(`.
fn methods_in(text: &str) -> BTreeSet<String> {
	let bytes = text.as_bytes();
	let mut found = BTreeSet::new();
	for method in METHODS {
		let needle = format!("{method}(");
		for (at, _) in text.match_indices(&needle) {
			let word_before =
				at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
			if !word_before {
				found.insert(method.to_ascii_uppercase());
			}
		}
	}
	found
}

/// Every `.route("<path>", <handlers>)` call in the production part of
/// `source`, as the path and the text of the handlers. A call whose path is
/// not a string literal is skipped.
pub(super) fn route_calls(source: &str) -> Vec<(String, String)> {
	let mut found = Vec::new();
	let mut rest = production_part(source);
	while let Some(at) = rest.find(".route(") {
		let call = call_arguments(&rest[at + ".route(".len()..]);
		rest = &rest[at + ".route(".len() + call.len()..];
		if let Some(quoted) = call.trim_start().strip_prefix('"')
			&& let Some((path, handlers)) = quoted.split_once('"')
		{
			found.push((path.to_string(), handlers.to_string()));
		}
	}
	found
}

/// Every `(METHOD, path)` those calls register, with `prefix` put in front.
pub(super) fn operations_in(source: &str, prefix: &str) -> BTreeSet<(String, String)> {
	let mut found = BTreeSet::new();
	for (path, handlers) in route_calls(source) {
		for method in methods_in(&handlers) {
			found.insert((method, format!("{prefix}{path}")));
		}
	}
	found
}

fn registered() -> BTreeSet<(String, String)> {
	let mut all = BTreeSet::new();
	for (_, source, prefix) in ROUTERS {
		all.extend(operations_in(source, prefix));
	}
	all
}

fn described() -> BTreeSet<(String, String)> {
	let document = super::parsed().expect("openapi.yaml reads");
	let mut found = BTreeSet::new();
	for (path, item) in document["paths"].as_object().expect("paths") {
		for (method, _) in item.as_object().expect("path item") {
			if METHODS.contains(&method.as_str()) {
				found.insert((method.to_ascii_uppercase(), path.clone()));
			}
		}
	}
	found
}

#[test]
fn every_registered_operation_is_described_and_every_described_one_is_registered() {
	let (code, yaml) = (registered(), described());
	let undescribed: Vec<_> = code.difference(&yaml).collect();
	let unregistered: Vec<_> = yaml.difference(&code).collect();
	assert!(
		undescribed.is_empty(),
		"routes the code registers that src/api/openapi/openapi.yaml does not describe: {undescribed:?}"
	);
	assert!(
		unregistered.is_empty(),
		"operations src/api/openapi/openapi.yaml describes that no router registers: {unregistered:?}"
	);
}

#[test]
fn the_extractor_finds_what_it_is_meant_to() {
	let source = r#"
		fn router() -> Router {
			Router::new()
				.route("/a", get(a::list).post(a::create))
				.route(
					"/b/{id}",
					axum::routing::delete(b::remove).layer(Limit::max(1)),
				)
				.route("/c", get(|| async { Json(json!({ "k": "x" })) }))
				.route(path, get(other))
		}
		#[cfg(test)]
		#[path = "x_tests.rs"]
		mod tests;
		fn later() { Router::new().route("/test-only", get(t)); }
	"#;
	let found = operations_in(source, "/p");
	let expected: BTreeSet<(String, String)> = [
		("GET", "/p/a"),
		("POST", "/p/a"),
		("DELETE", "/p/b/{id}"),
		("GET", "/p/c"),
	]
	.into_iter()
	.map(|(method, path)| (method.to_string(), path.to_string()))
	.collect();
	assert_eq!(found, expected);
}

/// Source files under `dir`, as paths relative to the crate root.
fn sources_under(dir: &Path, out: &mut Vec<PathBuf>) {
	for entry in std::fs::read_dir(dir).expect("read dir") {
		let path = entry.expect("entry").path();
		if path.is_dir() {
			sources_under(&path, out);
		} else if path.extension().is_some_and(|ext| ext == "rs") {
			out.push(path);
		}
	}
}

/// Files that only exist to test, by the names this repository gives them.
fn is_test_file(path: &Path) -> bool {
	let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
	stem == "tests"
		|| stem == "fake"
		|| stem == "test_support"
		|| stem.starts_with("tests_")
		|| stem.ends_with("_tests")
		|| stem.contains("_tests_")
		|| path.components().any(|part| part.as_os_str() == "tests")
}

#[test]
fn no_other_file_registers_a_route() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	let mut files = Vec::new();
	sources_under(&root.join("src"), &mut files);
	let known: BTreeSet<&str> = ROUTERS.iter().map(|(file, _, _)| *file).collect();
	let mut strangers = Vec::new();
	for file in files.iter().filter(|file| !is_test_file(file)) {
		let text = std::fs::read_to_string(file).expect("read source");
		let relative = file.strip_prefix(root).expect("under root");
		let relative = relative.to_string_lossy();
		if known.contains(relative.as_ref()) {
			continue;
		}
		if !route_calls(&text).is_empty() {
			strangers.push(relative.into_owned());
		}
	}
	assert!(
		strangers.is_empty(),
		"these files register HTTP routes; add them to ROUTERS in route_openapi_tests.rs and describe the routes in openapi.yaml: {strangers:?}"
	);
}

#[test]
fn every_router_source_registers_something() {
	for (file, source, prefix) in ROUTERS {
		assert!(
			!operations_in(source, prefix).is_empty(),
			"{file} is listed as a router but the extractor finds no route in it"
		);
	}
}

#[test]
fn described_paths_are_plain_paths() {
	let document = super::parsed().expect("openapi.yaml reads");
	for path in document["paths"].as_object().expect("paths").keys() {
		assert!(path.starts_with('/'), "{path}");
		assert!(!path.ends_with('/') || path == "/", "{path}");
		assert!(!path.contains(['?', '#', ' ']), "{path}");
	}
}
