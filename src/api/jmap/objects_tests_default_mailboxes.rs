use super::*;

#[test]
fn default_mailboxes_jmap_objects_expose_matching_roles() {
	let dir = tempfile::tempdir().expect("tempdir");
	for (name, role) in [
		("Rejects", "junk"),
		("Sent", "sent"),
		("Drafts", "drafts"),
		("Trash", "trash"),
		("Archive", "archive"),
		("INBOX", "inbox"),
	] {
		let object = mailbox_object(dir.path(), "alice", name);
		assert!(
			object["role"] == role,
			"JMAP default mailbox {name} must expose role {role}"
		);
	}
}
