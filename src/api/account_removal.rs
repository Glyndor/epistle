//! Removing an account on a task of its own.
//!
//! [`crate::directory_store::removal::remove_account_if`] clears the
//! account's footprint in steps, and some of them wait: the ban rows and the
//! Bayesian corpus live in a database. A client that goes away drops its
//! handler at one of those waits, and the removal would stop there with the
//! satellites already gone, the account and its keys still present and no
//! audit line. The removal, the forgetting of the account's push
//! subscriptions and the line that records it run on a task that the request
//! does not own, as the ban routes do for their changes
//! (`v1::bans::detached`): the request only waits for its end.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::api::audit::{self, AuditEvent, Carried};
use crate::api::state::ApiState;
use crate::directory_store::removal::{QueuePolicy, Removed, remove_account_if};
use crate::directory_store::{DynamicAccount, StoreError};

/// Which route removes the account: SCIM writes a second line of its own.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
	Rest,
	Scim,
}

/// Remove `name`, record it, and answer with the counts. The work and its
/// audit line finish whatever happens to the caller's future.
///
/// `authorize` is the caller's own check of the account. The store asks it
/// again under the account's lock, at the write that reserves the account,
/// before anything of it is destroyed.
pub(crate) async fn remove(
	state: &ApiState,
	name: &str,
	queue: QueuePolicy,
	via: Via,
	client_ip: Option<IpAddr>,
	authorize: impl FnOnce(&DynamicAccount) -> bool + Send + 'static,
) -> Result<Removed, StoreError> {
	let state = state.clone();
	let name = name.to_string();
	let carried = Carried::capture();
	// Whether the removal got past the refusals. The store asks `authorize`
	// about the account under its lock, right before it reserves it, so an
	// error after that answer may have left the footprint half cleared; an
	// error before it left everything as it was.
	let under_way = Arc::new(AtomicBool::new(false));
	let mark = Arc::clone(&under_way);
	tokio::spawn(async move {
		let removed = remove_account_if(
			state.store(),
			state.spool(),
			state.data_dir(),
			&name,
			queue,
			state.bayes_store(),
			move |account: &DynamicAccount| {
				let allowed = authorize(account);
				if allowed {
					mark.store(true, Ordering::SeqCst);
				}
				allowed
			},
		)
		.await;
		match &removed {
			Ok(counts) => {
				crate::api::jmap::push_subscription::forget_account(&state, &name);
				carried.run(|| {
					if via == Via::Scim {
						audit::log_privilege_change(AuditEvent::AccountRemoved, &name, None);
					}
					audit::log_account_removal(&name, client_ip, counts);
				});
			}
			Err(_) if under_way.load(Ordering::SeqCst) => {
				carried.run(|| audit::log_account_removal_incomplete(&name, client_ip));
			}
			Err(_) => {}
		}
		removed
	})
	.await
	.unwrap_or_else(|_| {
		Err(StoreError::Io(std::io::Error::other(
			"the removal task ended before it finished",
		)))
	})
}
