use super::*;

#[test]
fn a_notice_is_given_once_an_hour_for_each_account_and_cause() {
	let given = Mutex::new(None);
	let start = Instant::now();
	assert!(due_at("alice", "trim", start, &given));
	assert!(!due_at(
		"alice",
		"trim",
		start + Duration::from_secs(60),
		&given
	));
	assert!(due_at("bob", "trim", start, &given));
	assert!(due_at("alice", "large", start, &given));
	assert!(due_at("alice", "trim", start + QUIET, &given));
}
