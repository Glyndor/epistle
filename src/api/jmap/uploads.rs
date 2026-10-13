//! Uploaded blobs an `Email/set` create refers to, read before the request
//! is dispatched.
//!
//! Method dispatch is synchronous and the blob backend (the filesystem or
//! S3) is not, so the blob ids an `Email/set` create names in `textBody`,
//! `htmlBody`, `attachments` or `bodyStructure` are read here first, for the
//! accounts the principal may write to, within a byte budget.

use std::collections::HashMap;

use serde_json::Value;

use super::{MethodCall, Request, blobs};
use crate::api::Principal;
use crate::api::api_keys::Scope;
use crate::api::state::ApiState;

/// Most bytes read ahead for one request: no message over the size limit
/// can be built anyway, so more would only be held in memory to be refused.
const BUDGET: usize = crate::smtp::session::MAX_MESSAGE_SIZE;

/// Most blob ids read ahead for one request.
const MAX_BLOBS: usize = 256;

/// Deepest `bodyStructure` searched for blob ids.
const MAX_DEPTH: usize = 16;

/// One uploaded blob: its recorded media type and its octets.
pub(crate) struct Upload {
	pub(crate) content_type: Option<String>,
	pub(crate) data: Vec<u8>,
}

/// What a blob id resolved to before dispatch.
pub(crate) enum Found<'a> {
	Blob(&'a Upload),
	/// It exists, but reading it would have passed the byte budget.
	OverBudget,
	Missing,
}

/// Blobs read ahead, by account and blob id.
#[derive(Default)]
pub struct Uploads {
	blobs: HashMap<(String, String), Upload>,
	over_budget: Vec<(String, String)>,
}

impl Uploads {
	/// Read every uploaded blob the `Email/set` creates in `request` name.
	pub async fn prefetch(state: &ApiState, principal: &Principal, request: &Request) -> Self {
		let mut uploads = Uploads::default();
		if state
			.require_scope_for_principal(principal, Scope::Write)
			.is_err()
		{
			return uploads;
		}
		let mut budget = BUDGET;
		let mut seen = 0usize;
		for MethodCall(name, args, _) in &request.method_calls {
			if name != "Email/set" {
				continue;
			}
			let Some(account) = args.get("accountId").and_then(Value::as_str) else {
				continue;
			};
			let admitted = state.accounts().into_iter().any(|view| {
				view.name == account && principal.admits_account(&view.name, &view.addresses)
			});
			let Some(create) = args.get("create").and_then(Value::as_object) else {
				continue;
			};
			if !admitted {
				continue;
			}
			let mut ids = Vec::new();
			for spec in create.values() {
				for list in ["textBody", "htmlBody", "attachments"] {
					for part in spec
						.get(list)
						.and_then(Value::as_array)
						.into_iter()
						.flatten()
					{
						blob_ids(part, 0, &mut ids);
					}
				}
				if let Some(structure) = spec.get("bodyStructure") {
					blob_ids(structure, 0, &mut ids);
				}
			}
			for id in ids {
				let key = (account.to_string(), id.to_string());
				if uploads.blobs.contains_key(&key) || seen >= MAX_BLOBS {
					continue;
				}
				seen += 1;
				let backend = state.blob_backend();
				let Some(data) = blobs::read_blob(backend, account, id, state.crypto()).await
				else {
					continue;
				};
				if data.len() > budget {
					uploads.over_budget.push(key);
					continue;
				}
				budget -= data.len();
				let content_type = blobs::read_blob_type(backend, account, id).await;
				uploads.blobs.insert(key, Upload { content_type, data });
			}
		}
		uploads
	}

	/// The uploaded blob `blob_id` of `account`, if it was read ahead.
	pub(crate) fn find(&self, account: &str, blob_id: &str) -> Found<'_> {
		let key = (account.to_string(), blob_id.to_string());
		if let Some(upload) = self.blobs.get(&key) {
			return Found::Blob(upload);
		}
		if self.over_budget.contains(&key) {
			return Found::OverBudget;
		}
		Found::Missing
	}
}

/// The `blobId` of `part` and of its `subParts`, depth first.
fn blob_ids<'a>(part: &'a Value, depth: usize, out: &mut Vec<&'a str>) {
	if depth > MAX_DEPTH {
		return;
	}
	if let Some(id) = part.get("blobId").and_then(Value::as_str) {
		out.push(id);
	}
	for sub in part
		.get("subParts")
		.and_then(Value::as_array)
		.into_iter()
		.flatten()
	{
		blob_ids(sub, depth + 1, out);
	}
}
