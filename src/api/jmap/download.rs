//! JMAP blob downloads scoped to the owning message or upload account.

use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;

use super::{ApiState, DEFAULT_BLOB_TYPE, blobs, jmap_error, objects};

/// `GET /jmap/download/{accountId}/{blobId}/{name}` (RFC 8620 §6.2): return the
/// transfer-decoded bytes of a MIME leaf, a stored message or an uploaded blob.
pub async fn download(
	State(state): State<ApiState>,
	Path((account, blob_id, _name)): Path<(String, String, String)>,
) -> impl IntoResponse {
	if !state.accounts().iter().any(|a| a.name == account) {
		return jmap_error(StatusCode::NOT_FOUND, "notFound", "account not found");
	}
	let (message_id, part_id) = blob_id
		.split_once('.')
		.map_or((blob_id.as_str(), None), |(message, part)| {
			(message, Some(part))
		});
	let stored_message =
		objects::find_email_raw(state.data_dir(), &account, message_id, state.crypto()).and_then(
			|bytes| match part_id {
				Some(part_id) => objects::mime::part_blob(&bytes, part_id),
				None => Some((DEFAULT_BLOB_TYPE.to_owned(), bytes)),
			},
		);
	let blob = if stored_message.is_some() {
		stored_message
	} else if let Some(bytes) =
		blobs::read_blob(state.blob_backend(), &account, &blob_id, state.crypto()).await
	{
		let content_type = blobs::read_blob_type(state.blob_backend(), &blob_id)
			.await
			.unwrap_or_else(|| DEFAULT_BLOB_TYPE.to_owned());
		Some((content_type, bytes))
	} else {
		None
	};
	match blob {
		Some((content_type, bytes)) => {
			([(header::CONTENT_TYPE, content_type)], bytes).into_response()
		}
		None => jmap_error(StatusCode::NOT_FOUND, "notFound", "blob not found"),
	}
}
