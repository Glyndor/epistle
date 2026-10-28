
use super::*;

#[test]
fn roles_follow_the_whole_name() {
	assert!(is_junk("Junk") && is_junk("rejects") && is_junk("SPAM"));
	assert!(is_trash("Trash") && is_trash("deleted"));
	assert!(!is_junk("Archive/Junk"), "a nested folder has no role");
	assert!(!is_junk("INBOX") && !is_trash("Junk"));
}
