//! `epistle check <area> --json` against `GET /api/v1/health/{area}` on the
//! same configuration file: the route answers what the command prints.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::super::*;

const TOKEN: &str = "health-parity-token";

fn router(path: &std::path::Path, config: &Config) -> axum::Router {
	let accounts = Arc::new(
		crate::directory_store::AccountStore::open(
			&config.data_dir,
			config.domains.clone(),
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	let state = crate::api::ApiState::new(
		&crate::api::api_keys::sha256_hash(TOKEN),
		config.data_dir.clone(),
		config.domains.clone(),
		accounts.clone(),
		crate::storage::FsSpool::open(&config.data_dir).expect("spool"),
	)
	.with_directory(accounts.handle())
	.with_config_path(path.to_path_buf())
	.with_health_areas(vec![CheckArea::Config, CheckArea::Antispam]);
	crate::api::router(state.with_live_domains(crate::editable::LiveConfig::new(config.clone())))
}

async fn route(app: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
	let request = Request::builder()
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
		.body(Body::empty())
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, serde_json::from_slice(&bytes).expect("JSON"))
}

async fn command(path: &std::path::Path, area: CheckArea) -> serde_json::Value {
	let path = path.to_path_buf();
	// The command starts its own runtime, so it runs off this one.
	tokio::task::spawn_blocking(move || {
		let mut out = Vec::new();
		let _ = run_check(&path, area, true, &mut out);
		serde_json::from_slice(&out).expect("the command prints JSON")
	})
	.await
	.expect("the command ran")
}

#[tokio::test]
async fn each_route_answers_what_the_command_prints() {
	let dir = tempfile::tempdir().expect("directory");
	let path = super::base::valid(dir.path());
	let config = Config::load(&path).expect("config");
	let app = router(&path, &config);
	for area in [CheckArea::Config, CheckArea::Antispam] {
		let (status, body) = route(&app, &format!("/api/v1/health/{}", area.name())).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		assert_eq!(body, command(&path, area).await, "{}", area.name());
	}
	let (status, all) = route(&app, "/api/v1/health").await;
	assert_eq!(status, StatusCode::OK, "{all}");
	let mut joined = serde_json::Map::new();
	for area in [CheckArea::Antispam, CheckArea::Config] {
		joined.extend(
			command(&path, area)
				.await
				.as_object()
				.expect("object")
				.clone(),
		);
	}
	assert_eq!(all, serde_json::Value::Object(joined));
}
