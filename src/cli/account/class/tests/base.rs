use super::*;

#[test]
fn a_binding_is_set_and_cleared() {
	let dir = tempfile::tempdir().expect("tempdir");
	bind(dir.path(), "Notices", Some(MailClass::Transactional)).expect("bind");
	let set = crate::evidence::bindings::BindingSet::open(dir.path()).expect("open");
	assert_eq!(set.account("notices"), Some(MailClass::Transactional));
	bind(dir.path(), "notices", None).expect("clear");
	assert_eq!(
		crate::evidence::bindings::load(dir.path())
			.expect("load")
			.accounts
			.len(),
		0
	);
}
