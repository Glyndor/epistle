use super::*;

fn entry(attributes: &[&str], delimiter: Option<u8>, name: &str) -> ListEntry {
	ListEntry {
		attributes: attributes.iter().map(|a| a.to_ascii_lowercase()).collect(),
		delimiter,
		name: name.as_bytes().to_vec(),
	}
}

#[test]
fn the_remote_delimiter_becomes_the_local_one() {
	assert_eq!(local_name(b"Work.Projects", Some(b'.'), None), {
		if crate::imap::mailbox::valid_name("Work/Projects") {
			Ok("Work/Projects".to_string())
		} else {
			Err(SkipReason::InvalidName)
		}
	});
	assert_eq!(
		local_name(b"Work", Some(b'.'), None),
		Ok("Work".to_string())
	);
}

#[test]
fn a_slash_inside_a_component_is_reported_not_mangled() {
	assert_eq!(
		local_name(b"Q1/Q2.Reports", Some(b'.'), None),
		Err(SkipReason::SeparatorInName)
	);
	assert_eq!(
		local_name(b"a/b", None, None),
		Err(SkipReason::SeparatorInName)
	);
}

#[test]
fn names_the_store_cannot_hold_are_skipped() {
	for bad in [".hidden", "a..b.", "x.", "trailing "] {
		assert!(
			local_name(bad.as_bytes(), Some(b'.'), None).is_err(),
			"{bad}"
		);
	}
	assert_eq!(
		local_name(b"\xff", Some(b'.'), None),
		Err(SkipReason::InvalidName)
	);
	assert_eq!(
		local_name(b"../x", Some(b'.'), None),
		Err(SkipReason::SeparatorInName)
	);
}

#[test]
fn the_personal_namespace_prefix_is_stripped() {
	assert_eq!(
		local_name(b"INBOX.Lists", Some(b'.'), Some(b"INBOX.")),
		Ok("Lists".to_string())
	);
	assert_eq!(
		local_name(b"Lists", Some(b'.'), Some(b"INBOX.")),
		Ok("Lists".to_string())
	);
}

#[test]
fn utf8_names_get_the_stored_spelling() {
	assert_eq!(
		local_name("Entwürfe".as_bytes(), Some(b'/'), None),
		Ok(crate::util::mutf7::encode("Entwürfe"))
	);
	assert_eq!(
		local_name(b"Entw&APw-rfe", Some(b'/'), None),
		Ok("Entw&APw-rfe".to_string())
	);
}

#[test]
fn special_use_maps_to_the_local_folders() {
	let entries = vec![
		entry(&["\\Sent"], Some(b'/'), "Sent Items"),
		entry(&["\\Drafts"], Some(b'/'), "Entwürfe"),
		entry(&["\\Trash"], Some(b'/'), "Deleted Items"),
		entry(&["\\Junk"], Some(b'/'), "Bulk"),
		entry(&["\\Spam"], Some(b'/'), "[Gmail]/Spam"),
		entry(&["\\Archive"], Some(b'/'), "Old"),
		entry(&["\\Inbox"], Some(b'/'), "Posteingang"),
		entry(&["\\All"], Some(b'/'), "[Gmail]/All Mail"),
		entry(&["\\Noselect"], Some(b'/'), "[Gmail]"),
	];
	let plans = plan(&entries, None, &Filter::default());
	let by_name = |name: &str| {
		plans
			.iter()
			.find(|p| p.display == name)
			.map(|p| p.local.clone())
			.expect(name)
	};
	assert_eq!(by_name("Sent Items"), Ok("Sent".to_string()));
	assert_eq!(by_name("Entwürfe"), Ok("Drafts".to_string()));
	assert_eq!(by_name("Deleted Items"), Ok("Trash".to_string()));
	assert_eq!(by_name("Bulk"), Ok("Junk".to_string()));
	assert_eq!(by_name("[Gmail]/Spam"), Ok("Junk".to_string()));
	assert_eq!(by_name("Old"), Ok("Archive".to_string()));
	assert_eq!(by_name("Posteingang"), Ok("INBOX".to_string()));
	assert_eq!(by_name("[Gmail]/All Mail"), Err(SkipReason::Virtual));
	assert_eq!(by_name("[Gmail]"), Err(SkipReason::NotSelectable));
}

#[test]
fn a_virtual_folder_named_exactly_is_copied() {
	let entries = vec![entry(&["\\All"], Some(b'/'), "Everything")];
	let plans = plan(&entries, None, &Filter::new(&["Everything".to_string()]));
	assert_eq!(plans[0].local, Ok("Everything".to_string()));
	let plans = plan(&entries, None, &Filter::new(&["Every*".to_string()]));
	assert_eq!(plans[0].local, Err(SkipReason::Virtual));
}

#[test]
fn inbox_comes_first() {
	let entries = vec![
		entry(&[], Some(b'/'), "Archive"),
		entry(&[], Some(b'/'), "INBOX"),
		entry(&[], Some(b'/'), "Alpha"),
	];
	let order: Vec<String> = plan(&entries, None, &Filter::default())
		.into_iter()
		.map(|p| p.display)
		.collect();
	assert_eq!(order, ["INBOX", "Alpha", "Archive"]);
}

#[test]
fn glob_and_filters() {
	assert!(glob("*", ""));
	assert!(glob("Work*", "Work/Projects"));
	assert!(glob("*Items", "Sent Items"));
	assert!(glob("a*b*c", "aXXbYYc"));
	assert!(!glob("a*b*c", "aXXbYY"));
	assert!(!glob("Work", "Workshop"));
	// The backtracking stays linear in practice: a long name against a
	// pathological pattern finishes immediately.
	let name = "a".repeat(4000);
	assert!(!glob(&format!("{}b", "*a".repeat(20)), &name));
	let filter = Filter::new(&["Work*".to_string(), "!Work/Old".to_string()]);
	assert!(filter.admits("Work/New"));
	assert!(!filter.admits("Work/Old"));
	assert!(!filter.admits("INBOX"));
	assert!(Filter::new(&["!Spam".to_string()]).admits("INBOX"));
}
