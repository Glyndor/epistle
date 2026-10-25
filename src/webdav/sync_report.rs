//! The RFC 6578 `sync-collection` REPORT on a calendar or addressbook.
//!
//! With an empty `DAV:sync-token` the answer lists every member; with a
//! token from [`super::sync`] it lists the members changed since, a changed
//! one with a `200` propstat and a removed one with a bare `404` status
//! (RFC 6578 §3.5). The new token is the last child of the multistatus.
//! Each live member carries `DAV:getetag`, plus its `calendar-data` or
//! `address-data` when the request's `DAV:prop` asks for it, so a client
//! that only wants etags does not download every object.
//!
//! An unknown, foreign or expired token is `403` with `DAV:valid-sync-token`
//! (§3.2), which tells the client to start over with an empty token.
//! `sync-level` `infinite` is refused with `DAV:sync-traversal-supported`:
//! calendars and addressbooks hold no child collections, so level 1 is the
//! whole collection.

use std::path::Path;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use percent_encoding::percent_decode_str;

use super::caldav_filter_xml::{elements, first_open, unescape};
use super::reply::{Added, Reply};
use super::report_bounds::{MAX_REPORT_BYTES, MAX_SYNC_MEMBERS, Refusal, read_capped};
use super::sync::{self, Change};
use super::{carddav, href, propfind};

/// Whether a REPORT body is a `sync-collection` request.
pub fn is_sync_collection(body: &str) -> bool {
	first_open(body, "sync-collection").is_some()
}

/// `403` with a `DAV:error` holding the precondition element `name`.
pub fn precondition_failed(name: &str) -> Response {
	(
		StatusCode::FORBIDDEN,
		[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
		format!(
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
			<D:error xmlns:D=\"DAV:\">\n  <D:{name}/>\n</D:error>\n"
		),
	)
		.into_response()
}

/// Answer a `sync-collection` REPORT on `collection`, a calendar when
/// `calendar` is true and an addressbook otherwise. `root` is the account's
/// DAV root, used to build member hrefs the same way the other reports do.
pub async fn report(root: &Path, collection: &Path, calendar: bool, body: &str) -> Response {
	report_within(
		root,
		collection,
		calendar,
		body,
		(MAX_REPORT_BYTES, MAX_SYNC_MEMBERS),
	)
	.await
}

/// [`report`] with its two bounds given: the bytes of the reply and the
/// members a first sync lists.
///
/// A reply that runs out of room never drops a member quietly. An
/// incremental sync stops there with `507` on the collection and the token of
/// the last change it delivered, so the client resumes from it. A first sync
/// has no position to resume from, so it is refused as a whole.
async fn report_within(
	root: &Path,
	collection: &Path,
	calendar: bool,
	body: &str,
	(limit, max_members): (u64, usize),
) -> Response {
	match level(body) {
		Some(true) => {}
		Some(false) => return precondition_failed("sync-traversal-supported"),
		None => return StatusCode::BAD_REQUEST.into_response(),
	}
	let Some(log) = sync::load(collection).await else {
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	};
	let first = requested_token(body).is_none();
	let mut delivered = requested_token(body).and_then(|token| log.position_of(&token));
	let changes = match requested_token(body) {
		None => match members(collection, calendar, max_members).await {
			Ok(members) => members,
			Err(refusal) => return refusal.response(),
		},
		Some(token) => match log.position_of(&token) {
			Some(position) => log.changed_since(position),
			None => return precondition_failed("valid-sync-token"),
		},
	};
	let data = first_open(
		body,
		if calendar {
			"calendar-data"
		} else {
			"address-data"
		},
	)
	.is_some();
	let Some(base) = href::resource(root, collection) else {
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	};
	let mut reply = Reply::new(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
		<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\" \
		xmlns:CAL=\"urn:ietf:params:xml:ns:caldav\">\n",
		limit,
	);
	for change in &changes {
		let member_href = format!("{}/{}", base.trim_end_matches('/'), change.name);
		match live_member(collection, change, calendar).await {
			Some((etag, disk, len)) if data => {
				let qname = if calendar {
					"CAL:calendar-data"
				} else {
					"C:address-data"
				};
				// A member that does not fit is answered `507` with its
				// href: the client fetches it on its own with a multiget.
				match read_capped(&disk, len.min(reply.remaining())).await {
					Some(bytes) => {
						if reply.member(&member_href, &etag, Some((qname, &bytes))) == Added::NoRoom
						{
							reply.too_large(&member_href);
						}
					}
					None => reply.too_large(&member_href),
				}
			}
			Some((etag, _, _)) => {
				if reply.member(&member_href, &etag, None) == Added::NoRoom {
					if first {
						return Refusal::TooManyMembers.response();
					}
					reply.truncated(&base);
					return finish_at(reply, &log, delivered);
				}
			}
			None => {
				let mut gone = String::from("\t<D:response>\n\t\t<D:href>");
				propfind::escape_into(&mut gone, &member_href);
				gone.push_str(
					"</D:href>\n\t\t<D:status>HTTP/1.1 404 Not Found</D:status>\n\t</D:response>\n",
				);
				reply.raw(&gone);
			}
		}
		delivered = Some(change.sequence);
	}
	finish_at(reply, &log, None)
}

/// Close the reply with the token of the last change delivered, or the
/// current token when it holds them all.
fn finish_at(reply: Reply, log: &sync::Log, delivered: Option<u64>) -> Response {
	let token = delivered.map_or_else(|| log.token(), |sequence| log.token_at(sequence));
	let mut tail = String::from("\t<D:sync-token>");
	propfind::escape_into(&mut tail, &token);
	tail.push_str("</D:sync-token>\n");
	reply.finish(&tail)
}

/// `Some(true)` for level 1 (or no level), `Some(false)` for infinite,
/// `None` for anything else.
fn level(body: &str) -> Option<bool> {
	let levels = elements(body, "sync-level")?;
	match levels.first().map(|level| level.inner.trim()) {
		None | Some("1") => Some(true),
		Some("infinite") | Some("infinity") => Some(false),
		Some(_) => None,
	}
}

/// The token named by the request, `None` for a first sync (no
/// `sync-token` element, or an empty one).
fn requested_token(body: &str) -> Option<String> {
	let tokens = elements(body, "sync-token")?;
	let token = unescape(tokens.first()?.inner.trim());
	(!token.is_empty()).then_some(token)
}

/// Every current member of `collection` as a change, sorted by name, or
/// [`Refusal::TooManyMembers`] when there are more than a first sync lists.
/// Names are percent-encoded segments, the form the change log stores.
async fn members(collection: &Path, calendar: bool, max: usize) -> Result<Vec<Change>, Refusal> {
	let mut out = Vec::new();
	let Ok(mut dir) = tokio::fs::read_dir(collection).await else {
		return Ok(out);
	};
	while let Ok(Some(child)) = dir.next_entry().await {
		let Some(name) = child.file_name().to_str().map(str::to_string) else {
			continue;
		};
		if is_member_name(&name, calendar) {
			if out.len() == max {
				return Err(Refusal::TooManyMembers);
			}
			out.push(Change {
				sequence: 0,
				name: href::segment(&name),
				deleted: false,
			});
		}
	}
	out.sort_by(|a, b| a.name.cmp(&b.name));
	Ok(out)
}

/// Whether a file name is the kind of member the collection holds.
pub fn is_member_name(name: &str, calendar: bool) -> bool {
	let lower = name.to_ascii_lowercase();
	!sync::is_internal(name) && lower.ends_with(if calendar { ".ics" } else { ".vcf" })
}

/// The etag, path and length of a change whose member still exists as a
/// regular file (not a symlink) of the collection's kind, or `None` when it
/// is gone and the client should drop it.
async fn live_member(
	collection: &Path,
	change: &Change,
	calendar: bool,
) -> Option<(String, std::path::PathBuf, u64)> {
	if change.deleted {
		return None;
	}
	let name = percent_decode_str(&change.name).decode_utf8().ok()?;
	if name.contains('/') || !is_member_name(&name, calendar) {
		return None;
	}
	let disk = collection.join(name.as_ref());
	let meta = tokio::fs::symlink_metadata(&disk).await.ok()?;
	if !meta.is_file() {
		return None;
	}
	Some((carddav::etag(&meta), disk, meta.len()))
}

#[cfg(test)]
#[path = "sync_bounds_tests.rs"]
mod bounds_tests;
