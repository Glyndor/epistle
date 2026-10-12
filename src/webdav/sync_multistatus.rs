//! `sync-collection` REPORT response builder (RFC 6578 §3.3).
//!
//! Given a collection's current state and the list of changes since a
//! named token, build the `207 Multi-Status` body the client receives.
//! Lives in its own file because the multistatus is the longest piece
//! of the sync module and the rest of it is the on-disk change log.

use std::path::Path;

use super::carddav;
use super::propfind;
use super::sync::{Change, State, is_kind};

/// Build the `207 Multi-Status` body for the `sync-collection` answer. The
/// current `sync-token` is always in the response (as a property on the
/// collection's own response), the changed resources are listed as
/// `<D:response>` elements with `<D:status>HTTP/1.1 200 OK</D:status>` (or
/// `404` for a deleted entry), and the `multistatus` carries the token so
/// even a client that only reads the body has it. `collection_href` is the
/// collection's href as the client sees it; child resource hrefs are
/// `<collection_href><name>`.
pub async fn build(
	collection: &Path,
	state: &State,
	changes: &[Change],
	is_calendar: bool,
	is_addressbook: bool,
	collection_href: &str,
) -> String {
	let mut body = String::from(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
		<D:multistatus xmlns:D=\"DAV:\" \
		xmlns:C=\"urn:ietf:params:xml:ns:carddav\" \
		xmlns:CAL=\"urn:ietf:params:xml:ns:caldav\" \
		xmlns:CS=\"http://calendarserver.org/ns/\">\n",
	);
	// The collection itself: its token (always present) and `getctag`.
	body.push_str(&format!(
		"\t<D:response>\n\t\t<D:href>{href}</D:href>\n\
		\t\t<D:propstat>\n\t\t\t<D:prop>\n\
		\t\t\t\t<D:sync-token>{token}</D:sync-token>\n\
		\t\t\t\t<CS:getctag>{token}</CS:getctag>\n\
		\t\t\t</D:prop>\n\t\t\t<D:status>HTTP/1.1 200 OK</D:status>\n\
		\t</D:propstat>\n\t</D:response>\n",
		href = collection_href,
		token = state.token,
	));
	if changes.is_empty() {
		// No changes since the named token: emit the empty result.
		body.push_str("</D:multistatus>\n");
		return body;
	}
	// An entry for each change: 200 with `getetag` (and `address-data` /
	// `calendar-data` for the live ones), or 404 for deletes.
	for change in changes {
		let status = if change.deleted {
			"HTTP/1.1 404 Not Found"
		} else {
			"HTTP/1.1 200 OK"
		};
		// `collection_href` is always passed with a trailing slash, so
		// the child href is the literal concatenation. We still defend
		// against a stray empty path (an absolute href by itself).
		let child_href = if change.href.starts_with('/') {
			change.href.clone()
		} else {
			format!("{collection_href}{}", change.href)
		};
		let mut response = format!(
			"\t<D:response>\n\t\t<D:href>{href}</D:href>\n\
			\t\t<D:propstat>\n\t\t\t<D:prop>\n",
			href = child_href,
		);
		if !change.deleted {
			let resource = collection.join(&change.href);
			if let Ok(meta) = tokio::fs::metadata(&resource).await
				&& meta.is_file()
				&& is_kind(&change.href, is_calendar, is_addressbook)
			{
				response.push_str(&format!(
					"\t\t\t\t<D:getetag>{etag}</D:getetag>\n",
					etag = carddav::etag(&meta)
				));
				if let Ok(bytes) = tokio::fs::read(&resource).await {
					let element = if is_calendar {
						"calendar-data"
					} else {
						"address-data"
					};
					let prefix = if is_calendar { "CAL" } else { "C" };
					let text = String::from_utf8_lossy(&bytes);
					response.push_str(&format!(
						"\t\t\t\t<{prefix}:{element}>{body}</{prefix}:{element}>\n",
						body = propfind::escape(&text)
					));
				}
			} else {
				// The change log claims the resource is live but the
				// file is gone (concurrent delete, race). Return 404 so
				// the client drops the resource, matching what a
				// freshly-emptied collection would do.
				response.push_str(
					"\t\t\t</D:prop>\n\t\t\t<D:status>HTTP/1.1 404 Not Found</D:status>\n\
					\t\t</D:propstat>\n\t</D:response>\n",
				);
				body.push_str(&response);
				continue;
			}
		}
		response.push_str(&format!(
			"\t\t\t</D:prop>\n\t\t\t<D:status>{status}</D:status>\n\
			\t\t</D:propstat>\n\t</D:response>\n"
		));
		body.push_str(&response);
	}
	body.push_str("</D:multistatus>\n");
	body
}

/// Walk the collection and return one change-log-shaped entry per current
/// member: `(sequence=state.sequence, href, deleted=false)`. The sequence
/// here is a fiction — the request gets the full state — but the shape
/// matches what `build` consumes.
pub async fn enumerate_current(
	collection: &Path,
	is_calendar: bool,
	is_addressbook: bool,
) -> Vec<Change> {
	let state = super::sync::current(collection).await;
	let Ok(mut dir) = tokio::fs::read_dir(collection).await else {
		return Vec::new();
	};
	let mut out = Vec::new();
	while let Ok(Some(child)) = dir.next_entry().await {
		let Ok(kind) = child.file_type().await else {
			continue;
		};
		if !crate::util::fs_walk::allowed(&child.path(), kind) {
			continue;
		}
		if kind.is_dir() {
			continue;
		}
		let Ok(sym) = std::fs::symlink_metadata(child.path()) else {
			continue;
		};
		if sym.file_type().is_symlink() {
			continue;
		}
		let name = child.file_name();
		let name = name.to_string_lossy();
		if !is_kind(&name, is_calendar, is_addressbook) {
			continue;
		}
		out.push(Change {
			sequence: state.sequence,
			href: name.into_owned(),
			deleted: false,
		});
	}
	out.sort_by(|a, b| a.href.cmp(&b.href));
	out
}
