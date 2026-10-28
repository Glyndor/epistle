
use super::special_use_attribute;

#[test]
fn well_known_folders_get_attributes() {
	assert_eq!(special_use_attribute("Junk"), "\\Junk");
	assert_eq!(special_use_attribute("rejects"), "\\Junk");
	assert_eq!(special_use_attribute("Drafts"), "\\Drafts");
	assert_eq!(special_use_attribute("Sent"), "\\Sent");
	assert_eq!(special_use_attribute("Trash"), "\\Trash");
	assert_eq!(special_use_attribute("Archive"), "\\Archive");
}

#[test]
fn ordinary_folder_has_no_attribute() {
	assert_eq!(special_use_attribute("INBOX"), "");
	assert_eq!(special_use_attribute("Projects"), "");
}
