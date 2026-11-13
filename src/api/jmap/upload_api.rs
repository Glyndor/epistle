//! The JMAP blob upload endpoint.

use super::*;

/// `POST /jmap/upload/{accountId}` (RFC 8620 §6.1): store an uploaded blob and
/// return its id, type and size. Blobs live in the account's partition,
/// `<data_dir>/blobs/accounts/<account>/`.
pub async fn upload(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(account): Path<String>,
	request: axum::extract::Request,
) -> impl IntoResponse {
	let principal = Principal::for_token(&state, &auth);
	// `Write` scope: a read-only key must not be able to fill the quota or
	// the blob store with arbitrary bytes.
	if state
		.require_scope_for_principal(&principal, Scope::Write)
		.is_err()
	{
		return jmap_error(StatusCode::UNAUTHORIZED, "forbidden", "missing write scope");
	}
	let Some(view) = state.accounts().into_iter().find(|a| a.name == account) else {
		return jmap_error(StatusCode::NOT_FOUND, "notFound", "account not found");
	};
	if !principal.admits_account(&view.name, &view.addresses) {
		return jmap_error(StatusCode::NOT_FOUND, "notFound", "account not found");
	}
	let Some(_slot) = CallerSlot::take(
		&state,
		&principal,
		Work::Upload,
		limits::MAX_CONCURRENT_UPLOAD,
	) else {
		let problem =
			limits::too_many_concurrent("maxConcurrentUpload", limits::MAX_CONCURRENT_UPLOAD);
		return (StatusCode::TOO_MANY_REQUESTS, Json(problem)).into_response();
	};
	let headers = request.headers().clone();
	// The route caps the body at the advertised maxSizeUpload; anything
	// larger is answered with the spec's limit error (RFC 8620 §6.1) rather
	// than a transport-level 413.
	let body = match axum::body::Bytes::from_request(request, &()).await {
		Ok(body) => body,
		Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
			let problem = limits::upload_too_large();
			return (StatusCode::PAYLOAD_TOO_LARGE, Json(problem)).into_response();
		}
		Err(rejection) => return rejection.into_response(),
	};
	// Enforce the account's storage quota before persisting (RFC 8620 §6.1:
	// upload may be refused once a limit is reached). A configured limit is the
	// hard cap; 0 means unlimited. Fail closed — reject when the blob would push
	// usage over the limit. We answer with the JMAP limit error rather than a
	// bare 413: the type is `urn:ietf:params:jmap:error:limit` (the only limit
	// error core defines) and `limit: "storage"` names the resource that was
	// hit, distinguishing an over-quota rejection from the per-request
	// `maxSizeUpload` one above. The HTTP status is 507 Insufficient Storage,
	// the closest standard code for "would exceed the account's storage".
	//
	// The check reserves the bytes it admits instead of locking the account
	// over the write: the reservation counts against the next check of the
	// same account, so two uploads at the same moment cannot both pass it.
	// It is released when the upload ends, stored the blob or not, and
	// nothing is held while the blob is written — the backend may be remote
	// and slow, and a lock across it would hold up every delivery to the
	// account.
	let size = body.len() as u64;
	let reservation = match state.quota_for_account(&account) {
		Some(limit) => {
			// Reserve, then read the usage, in that order: see `reserve`.
			let reservation = crate::smtp::quota::reserve(state.data_dir(), &account, size);
			let usage = blobs::account_usage_bytes(state.data_dir(), &account, state.crypto());
			if usage.saturating_add(reservation.reserved()) > limit {
				return (
					StatusCode::INSUFFICIENT_STORAGE,
					Json(json!({
						"type": "urn:ietf:params:jmap:error:limit",
						"limit": "storage",
						"status": 507,
						"detail": "upload would exceed the account storage quota",
					})),
				)
					.into_response();
			}
			Some(reservation)
		}
		None => None,
	};
	// Per-tenant aggregate storage cap (RFC 8620 §6.1; the same JMAP limit
	// type as the per-account quota above). Sits on top of the per-account
	// limit; either can fail and the rejection looks the same to the client.
	// Empty `tenant_limits` is the identity, no extra work.
	let account_addresses: Vec<String> = state
		.accounts()
		.into_iter()
		.find(|view| view.name == account)
		.map(|view| view.addresses)
		.unwrap_or_default();
	if let Err(message) = state.tenant_limits().check_aggregate_quota(
		state.store(),
		state.data_dir(),
		state.crypto(),
		&account_addresses,
		size,
	) {
		return (
			StatusCode::INSUFFICIENT_STORAGE,
			Json(json!({
				"type": "urn:ietf:params:jmap:error:limit",
				"limit": "tenant_storage",
				"status": 507,
				"detail": message,
			})),
		)
			.into_response();
	}
	// The blob's media type is the request Content-Type, echoed back and
	// persisted so downloads serve it (RFC 8620 §6.1).
	let content_type = headers
		.get(header::CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.filter(|value| !value.is_empty())
		.unwrap_or(DEFAULT_BLOB_TYPE)
		.to_string();
	// Minted as a `Uuid` and kept as one: the string form is only for the
	// response body, so nothing downstream can be handed a path fragment.
	let blob_id = uuid::Uuid::now_v7();
	// Encrypt the blob payload at rest like stored mail; the `.type` and
	// `.owner` sidecars stay plaintext metadata.
	let stored = match state.crypto().encode_for_account(&account, &body) {
		Ok(stored) => stored,
		Err(_) => {
			return jmap_error(
				StatusCode::INTERNAL_SERVER_ERROR,
				"serverFail",
				"cannot store blob",
			);
		}
	};
	// The blob goes into the account's partition. An account whose name is
	// not one plain path component cannot have one, so the upload fails
	// rather than landing anywhere shared.
	let backend = state.blob_backend();
	let Some(partition) = crate::storage::BlobAccount::new(&account) else {
		return jmap_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			"serverFail",
			"cannot store blob",
		);
	};
	if backend.put(&partition, blob_id, "", &stored).await.is_err()
		|| backend
			.put(&partition, blob_id, ".type", content_type.as_bytes())
			.await
			.is_err()
		|| blobs::write_blob_owner(backend, blob_id, &partition)
			.await
			.is_err()
	{
		return jmap_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			"serverFail",
			"cannot store blob",
		);
	}
	// The blob is stored: the bytes it took are the account's now, and the
	// reservation is no longer needed.
	drop(reservation);
	(
		StatusCode::OK,
		Json(json!({
			"accountId": account,
			"blobId": blob_id,
			"type": content_type,
			"size": body.len(),
		})),
	)
		.into_response()
}
