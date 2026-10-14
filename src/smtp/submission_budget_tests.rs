//! A [`Budget`] charges all of its limits or none, and gives a refused
//! message's units back.

use super::*;

fn limiter() -> Arc<SendLimiter> {
	Arc::new(SendLimiter::refusing_new_keys(60))
}

/// A charge the second limit refuses takes nothing from the first.
#[test]
fn a_refused_charge_takes_nothing_from_any_limit() {
	let account = limiter();
	let tenant = limiter();
	let budget = Budget {
		limits: vec![
			Limit {
				limiter: Arc::clone(&account),
				key: "alice".into(),
				per_min: 10,
			},
			Limit {
				limiter: Arc::clone(&tenant),
				key: "acme".into(),
				per_min: 2,
			},
		],
	};
	assert_eq!(budget.charge(3, 1_000).map(drop), Err(OverLimit));
	assert!(account.check_n("alice", 10, 10, 1_000), "nothing was kept");
}

/// A refunded or dropped pending charge gives the units back; an
/// accepted one keeps them.
#[test]
fn a_pending_charge_is_refunded_unless_accepted() {
	let account = limiter();
	let budget = Budget::for_account("alice", Some((&account, 2)), None, Vec::new);
	drop(PendingCharge::new(budget.charge(2, 1_000).ok()));
	assert!(budget.has_room(1_000), "the dropped charge was refunded");
	let mut kept = PendingCharge::new(budget.charge(2, 1_000).ok());
	kept.accept();
	drop(kept);
	assert!(!budget.has_room(1_000), "the accepted charge is kept");
}
