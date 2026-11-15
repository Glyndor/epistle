//! `POST /api/v1/domains`: the same keys, secrets and commit as the CLI.

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;

use super::change::{self, Changed};
use crate::api::audit::DomainEvent;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::api::{Principal, error::ApiError};
use crate::domain::state::edit::{
	self,
	add::{Signing, prepare},
};
use crate::domain::state::{DomainsFile, StoredRole};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddDomain {
	domain: String,
	#[serde(default)]
	role: StoredRole,
	#[serde(default)]
	shared_dkim_key: bool,
}

pub async fn add(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Json(request): Json<AddDomain>,
) -> Result<(StatusCode, Json<Changed>), ApiError> {
	let principal = Principal::for_token(&state, &auth);
	crate::api::v1::scope::require_unconfined(&principal, "Hosting a domain")?;
	let domain = change::canonical("domain", &request.domain)?;
	let config = change::config(&state)?;
	let name = request.domain.clone();
	let done = tokio::task::spawn_blocking(move || {
		// Preparation must see writes that the watcher has not observed yet.
		let path = crate::domain::state::path(&config.data_dir);
		let file = DomainsFile::read(&path).map_err(|e| edit::EditError::Io(e.to_string()))?;
		let current = file.as_ref().map_or_else(
			|| {
				let seed = <DomainsFile as crate::editable::StateFile>::seed(&config);
				config.with_domains_file(&seed)
			},
			|file| config.with_domains_file(file),
		);
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map_or(0, |elapsed| elapsed.as_secs());
		let signing = if request.shared_dkim_key {
			Signing::SharedKey
		} else {
			Signing::OwnKey
		};
		let prepared = prepare(&current, &name, request.role, (signing, false), now)?;
		let result = edit::commit(&current, &prepared.change);
		if result.is_err() {
			// A failed rename/directory sync may still have installed the file.
			// Keep any key the on-disk state names; an unreadable file keeps all.
			if let Ok(file) = DomainsFile::read(&path) {
				let used: Vec<_> = file
					.into_iter()
					.flat_map(|f| f.domains)
					.filter_map(|d| d.dkim)
					.collect();
				let unused: Vec<_> = prepared
					.created
					.iter()
					.filter(|path| {
						!used.iter().any(|key| {
							key.key_file == **path || key.rsa_key_file.as_ref() == Some(*path)
						})
					})
					.cloned()
					.collect();
				crate::dkim::domain_keys::remove(&unused);
			}
		}
		result
	})
	.await
	.map_err(|_| ApiError::internal())?
	.map_err(change::refusal)?;
	change::audit(&done, DomainEvent::Added, &domain, ip);
	Ok((StatusCode::CREATED, Json(Changed::of(&done, domain))))
}
