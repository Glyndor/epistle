//! Subscriptions kept under an account name leave with the account.

use super::*;

fn stored(owner: &str, id: &str) -> StoredSubscription {
	StoredSubscription {
		owner: owner.to_string(),
		object: json!({ "id": id }),
	}
}

#[test]
fn a_removed_account_leaves_no_subscriptions_behind() {
	let mut store = vec![
		stored("account:dora", "a"),
		stored("account:Dora", "b"),
		stored("account:erin", "c"),
		stored("key:ops", "d"),
	];
	drop_account_subscriptions(&mut store, "dora");
	let ids: Vec<&str> = store.iter().filter_map(StoredSubscription::id).collect();
	assert_eq!(ids, vec!["c", "d"]);
}
