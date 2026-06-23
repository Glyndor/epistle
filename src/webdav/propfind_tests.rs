use super::*;
use std::time::Duration;

fn file_entry() -> Entry {
	Entry {
		href: "/notes.txt".to_string(),
		is_collection: false,
		is_addressbook: false,
		length: 42,
		modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777)),
		display_name: "notes.txt".to_string(),
		content_type: "application/octet-stream",
		etag: String::new(),
	}
}

fn dir_entry() -> Entry {
	Entry {
		href: "/docs/".to_string(),
		is_collection: true,
		is_addressbook: false,
		length: 0,
		modified: None,
		display_name: "docs".to_string(),
		content_type: "application/octet-stream",
		etag: String::new(),
	}
}

#[test]
fn file_response_has_length_and_no_collection() {
	let body = multistatus(&[file_entry()]);
	assert!(body.contains("<D:multistatus xmlns:D=\"DAV:\""));
	assert!(body.contains("<D:resourcetype/>"));
	assert!(body.contains("<D:getcontentlength>42</D:getcontentlength>"));
	assert!(body.contains("<D:displayname>notes.txt</D:displayname>"));
	assert!(body.contains("<D:href>/notes.txt</D:href>"));
	assert!(body.contains("HTTP/1.1 200 OK"));
}

#[test]
fn collection_response_marks_resourcetype() {
	let body = multistatus(&[dir_entry()]);
	assert!(body.contains("<D:resourcetype><D:collection/></D:resourcetype>"));
	// Collections carry no content length.
	assert!(!body.contains("getcontentlength"));
}

#[test]
fn depth_one_lists_multiple_entries() {
	let body = multistatus(&[dir_entry(), file_entry()]);
	assert_eq!(body.matches("<D:response>").count(), 2);
}

#[test]
fn httpdate_is_imf_fixdate() {
	let time = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
	assert_eq!(httpdate(time), "Sun, 06 Nov 1994 08:49:37 GMT");
}

#[test]
fn httpdate_epoch() {
	assert_eq!(
		httpdate(SystemTime::UNIX_EPOCH),
		"Thu, 01 Jan 1970 00:00:00 GMT"
	);
}

#[test]
fn escapes_special_characters_in_name() {
	let entry = Entry {
		href: "/a&b".to_string(),
		is_collection: false,
		is_addressbook: false,
		length: 1,
		modified: None,
		display_name: "a&b<c>".to_string(),
		content_type: "application/octet-stream",
		etag: String::new(),
	};
	let body = multistatus(&[entry]);
	assert!(body.contains("a&amp;b&lt;c&gt;"));
	assert!(body.contains("<D:href>/a&amp;b</D:href>"));
}
