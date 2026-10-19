//! `openapi.yaml` is a well-formed OpenAPI 3.1 document, says what the code
//! enforces about scopes, and lists the error codes and statuses the code
//! can answer with.

use std::collections::{BTreeMap, BTreeSet};

use axum::http::Method;
use serde_json::{Value, json};

fn doc() -> Value {
	super::parsed().expect("openapi.yaml reads")
}

const HTTP_METHODS: [&str; 7] = ["get", "post", "put", "patch", "delete", "head", "options"];

/// Every `(path, method, operation)` of the document.
fn operations(doc: &Value) -> Vec<(String, String, Value)> {
	let mut found = Vec::new();
	for (path, item) in doc["paths"].as_object().expect("paths") {
		for (method, operation) in item.as_object().expect("path item") {
			if HTTP_METHODS.contains(&method.as_str()) {
				found.push((path.clone(), method.clone(), operation.clone()));
			}
		}
	}
	found
}

/// Every string a `$ref` key holds, anywhere in `value`.
fn refs(value: &Value, out: &mut Vec<String>) {
	match value {
		Value::Object(map) => {
			for (key, inner) in map {
				match (key.as_str(), inner) {
					("$ref", Value::String(target)) => out.push(target.clone()),
					_ => refs(inner, out),
				}
			}
		}
		Value::Array(items) => items.iter().for_each(|item| refs(item, out)),
		_ => {}
	}
}

/// What a local `$ref` points at.
fn resolve<'a>(doc: &'a Value, reference: &str) -> Option<&'a Value> {
	let pointer = reference.strip_prefix('#')?;
	doc.pointer(pointer)
}

#[test]
fn the_document_has_the_parts_an_openapi_31_document_needs() {
	let doc = doc();
	assert_eq!(doc["openapi"], "3.1.0");
	for field in ["title", "version"] {
		assert!(
			doc["info"][field]
				.as_str()
				.is_some_and(|text| !text.is_empty()),
			"info.{field}"
		);
	}
	assert!(!doc["paths"].as_object().expect("paths").is_empty());
	assert!(doc["components"].is_object());
	assert!(
		doc["servers"]
			.as_array()
			.is_some_and(|list| !list.is_empty()),
		"servers"
	);
}

#[test]
fn every_reference_resolves() {
	let doc = doc();
	let mut all = Vec::new();
	refs(&doc, &mut all);
	assert!(!all.is_empty());
	for reference in all {
		assert!(reference.starts_with("#/components/"), "{reference}");
		assert!(
			resolve(&doc, &reference).is_some(),
			"{reference} points at nothing"
		);
	}
}

#[test]
fn nothing_in_components_is_left_unused() {
	let doc = doc();
	let mut all = Vec::new();
	refs(&doc, &mut all);
	let used: BTreeSet<String> = all.into_iter().collect();
	let mut schemes = BTreeSet::new();
	let mut collect_schemes = |security: &Value| {
		for requirement in security.as_array().into_iter().flatten() {
			schemes.extend(
				requirement
					.as_object()
					.into_iter()
					.flat_map(|m| m.keys().cloned()),
			);
		}
	};
	collect_schemes(&doc["security"]);
	for (_, _, operation) in operations(&doc) {
		collect_schemes(&operation["security"]);
	}
	for (kind, entries) in doc["components"].as_object().expect("components") {
		for name in entries.as_object().expect("component group").keys() {
			let used_here = if kind == "securitySchemes" {
				schemes.contains(name)
			} else {
				used.contains(&format!("#/components/{kind}/{name}"))
			};
			assert!(used_here, "components.{kind}.{name} is not used");
		}
	}
}

#[test]
fn every_operation_is_complete_and_operation_ids_are_unique() {
	let doc = doc();
	let declared: BTreeSet<&str> = doc["tags"]
		.as_array()
		.expect("tags")
		.iter()
		.filter_map(|tag| tag["name"].as_str())
		.collect();
	let mut ids = BTreeSet::new();
	for (path, method, operation) in operations(&doc) {
		let at = format!("{method} {path}");
		let id = operation["operationId"]
			.as_str()
			.unwrap_or_else(|| panic!("{at}: operationId"));
		assert!(
			ids.insert(id.to_string()),
			"{at}: operationId {id} is not unique"
		);
		assert!(
			operation["summary"]
				.as_str()
				.is_some_and(|text| !text.is_empty()),
			"{at}: summary"
		);
		let tags = operation["tags"]
			.as_array()
			.unwrap_or_else(|| panic!("{at}: tags"));
		assert!(!tags.is_empty(), "{at}: tags");
		for tag in tags {
			assert!(
				declared.contains(tag.as_str().unwrap_or("")),
				"{at}: undeclared tag {tag}"
			);
		}
		let responses = operation["responses"]
			.as_object()
			.unwrap_or_else(|| panic!("{at}: responses"));
		assert!(
			responses
				.keys()
				.any(|code| code.starts_with('2') || code == "101" || code == "501"),
			"{at}: no success response (only an operation the server refuses outright, 501, may have none)"
		);
		for (code, response) in responses {
			assert!(
				code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()),
				"{at}: response code {code}"
			);
			let response = match response["$ref"].as_str() {
				Some(reference) => resolve(&doc, reference).expect("resolves"),
				None => response,
			};
			assert!(
				response["description"]
					.as_str()
					.is_some_and(|text| !text.is_empty()),
				"{at}: response {code} has no description"
			);
		}
		if let Some(body) = operation.get("requestBody") {
			assert_eq!(body["required"], true, "{at}: requestBody.required");
			for (media, content) in body["content"].as_object().expect("content") {
				assert!(media.contains('/'), "{at}: media type {media}");
				assert!(content["schema"].is_object(), "{at}: schema of {media}");
			}
		}
	}
}

#[test]
fn path_parameters_match_the_path_template() {
	let doc = doc();
	for (path, method, operation) in operations(&doc) {
		let at = format!("{method} {path}");
		let in_template: BTreeSet<&str> = path
			.split('/')
			.filter_map(|part| part.strip_prefix('{')?.strip_suffix('}'))
			.collect();
		let mut declared = BTreeSet::new();
		for parameter in operation["parameters"].as_array().into_iter().flatten() {
			let parameter = match parameter["$ref"].as_str() {
				Some(reference) => resolve(&doc, reference).expect("resolves"),
				None => parameter,
			};
			let name = parameter["name"]
				.as_str()
				.unwrap_or_else(|| panic!("{at}: parameter name"));
			let place = parameter["in"].as_str().unwrap_or("");
			assert!(
				["path", "query", "header"].contains(&place),
				"{at}: {name} in {place}"
			);
			assert!(
				parameter["description"].is_string() || parameter["schema"]["$ref"].is_string(),
				"{at}: parameter {name} has no description"
			);
			assert!(
				parameter["schema"].is_object(),
				"{at}: parameter {name} has no schema"
			);
			if place == "path" {
				assert_eq!(parameter["required"], true, "{at}: path parameter {name}");
				declared.insert(name.to_string());
			}
		}
		let declared: BTreeSet<&str> = declared.iter().map(String::as_str).collect();
		assert_eq!(in_template, declared, "{at}: path parameters");
	}
}

#[test]
fn required_properties_exist() {
	fn walk(value: &Value, at: &str) {
		if let Value::Object(map) = value {
			if let (Some(Value::Array(required)), Some(Value::Object(properties))) =
				(map.get("required"), map.get("properties"))
			{
				for name in required {
					let name = name.as_str().expect("required name");
					assert!(
						properties.contains_key(name),
						"{at}: required `{name}` is not a property"
					);
				}
			}
			for (key, inner) in map {
				walk(inner, &format!("{at}/{key}"));
			}
		}
		if let Value::Array(items) = value {
			items.iter().for_each(|item| walk(item, at));
		}
	}
	walk(&doc(), "#");
}

#[test]
fn each_operation_names_the_scope_the_bearer_check_infers() {
	let doc = doc();
	for (path, method, operation) in operations(&doc) {
		let at = format!("{method} {path}");
		let scopes: BTreeSet<String> = operation["x-epistle-scope"]
			.as_array()
			.unwrap_or_else(|| panic!("{at}: x-epistle-scope"))
			.iter()
			.map(|scope| scope.as_str().expect("scope").to_string())
			.collect();
		let open = operation["security"].as_array().is_some_and(Vec::is_empty);
		assert_eq!(
			open,
			scopes.is_empty(),
			"{at}: security: [] and an empty scope list go together"
		);
		if open {
			continue;
		}
		let http = Method::from_bytes(method.to_ascii_uppercase().as_bytes()).expect("method");
		let inferred: BTreeSet<String> = crate::api::state::acceptable_scopes_for(&http, &path)
			.into_iter()
			.map(|scope| scope.as_str().to_string())
			.collect();
		assert_eq!(
			scopes, inferred,
			"{at}: the bearer middleware accepts {inferred:?}"
		);
	}
}

#[test]
fn the_scopes_agree_with_the_route_rules_table() {
	let doc = doc();
	let mut per_path: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
	for (path, _, operation) in operations(&doc) {
		let entry = per_path.entry(path).or_default();
		for scope in operation["x-epistle-scope"].as_array().expect("scopes") {
			entry.insert(scope.as_str().expect("scope").to_string());
		}
	}
	let mut checked = 0;
	for (path, scopes) in per_path {
		let Some(expected) = crate::api::route_rules_tests::scopes_of(&path) else {
			continue;
		};
		let expected: BTreeSet<String> = expected.into_iter().map(str::to_string).collect();
		assert_eq!(
			scopes, expected,
			"{path}: route_rules_tests.rs says {expected:?}"
		);
		checked += 1;
	}
	assert!(checked > 30, "only {checked} paths were compared");
}

#[test]
fn every_error_code_and_status_the_api_can_answer_is_listed() {
	let source = include_str!("../error.rs");
	let source = super::route_openapi_tests::production_part(source);
	let codes: BTreeSet<&str> = source
		.lines()
		.filter_map(|line| line.trim().strip_prefix("code: \""))
		.filter_map(|rest| rest.split('"').next())
		.collect();
	assert!(codes.len() >= 15, "{codes:?}");
	let doc = doc();
	let described = doc["components"]["schemas"]["ApiError"]["properties"]["error"]["properties"]["code"]
		["description"]
		.as_str()
		.expect("ApiError.code description");
	for code in &codes {
		assert!(
			described.contains(&format!("`{code}`")),
			"ApiError.code does not list `{code}`"
		);
	}
	let numbers: BTreeMap<&str, &str> = BTreeMap::from([
		("BAD_REQUEST", "400"),
		("UNAUTHORIZED", "401"),
		("FORBIDDEN", "403"),
		("NOT_FOUND", "404"),
		("CONFLICT", "409"),
		("PAYLOAD_TOO_LARGE", "413"),
		("UNPROCESSABLE_ENTITY", "422"),
		("TOO_MANY_REQUESTS", "429"),
		("INTERNAL_SERVER_ERROR", "500"),
		("SERVICE_UNAVAILABLE", "503"),
		("INSUFFICIENT_STORAGE", "507"),
	]);
	let mut listed = BTreeSet::new();
	for (_, _, operation) in operations(&doc) {
		listed.extend(
			operation["responses"]
				.as_object()
				.expect("responses")
				.keys()
				.cloned(),
		);
	}
	for (_, rest) in source
		.match_indices("StatusCode::")
		.map(|(at, _)| ((), &source[at + 12..]))
	{
		let name: String = rest
			.chars()
			.take_while(|c| c.is_ascii_uppercase() || *c == '_')
			.collect();
		let number = numbers.get(name.as_str()).unwrap_or_else(|| {
			panic!("error.rs uses StatusCode::{name}; add it to this table and document it")
		});
		assert!(
			listed.contains(*number),
			"no operation documents {number} ({name})"
		);
	}
}

#[test]
fn the_json_the_server_sends_is_the_yaml() {
	let served = super::document().expect("the embedded description reads");
	let served: Value = serde_json::from_str(served).expect("it is JSON");
	assert_eq!(served, doc());
}

fn to_json(yaml: &yaml_rust2::Yaml) -> Value {
	use yaml_rust2::Yaml;
	match yaml {
		Yaml::Real(text) => json!(text.parse::<f64>().expect("a float")),
		Yaml::Integer(number) => json!(number),
		Yaml::String(text) => Value::String(text.clone()),
		Yaml::Boolean(flag) => Value::Bool(*flag),
		Yaml::Null => Value::Null,
		Yaml::Array(items) => Value::Array(items.iter().map(to_json).collect()),
		Yaml::Hash(map) => Value::Object(
			map.iter()
				.map(|(key, value)| {
					let key = match key {
						Yaml::String(text) => text.clone(),
						Yaml::Integer(number) => number.to_string(),
						other => panic!("a key that is not a string: {other:?}"),
					};
					(key, to_json(value))
				})
				.collect(),
		),
		other => panic!("a YAML node the subset does not use: {other:?}"),
	}
}

#[test]
fn an_independent_yaml_parser_reads_the_file_the_same_way() {
	let documents = yaml_rust2::YamlLoader::load_from_str(super::SOURCE).expect("valid YAML");
	assert_eq!(documents.len(), 1);
	assert_eq!(to_json(&documents[0]), doc());
}

#[tokio::test]
async fn the_route_answers_the_document_to_a_reader_and_refuses_everyone_else() {
	use crate::api::tests::{TOKEN, request, test_state};
	let dir = tempfile::tempdir().expect("tempdir");
	let app = crate::api::router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/api/v1/openapi.json", Some(TOKEN.as_str())).await;
	assert_eq!(status, axum::http::StatusCode::OK);
	assert_eq!(body, doc());
	let (status, _) = request(&app, "GET", "/api/v1/openapi.json", None).await;
	assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
	let (status, _) = request(&app, "GET", "/api/v1/openapi.json", Some("not-the-token")).await;
	assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}
