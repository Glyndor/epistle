//! `serve` stops the ACME renewal loop on its way out, on a stop signal and
//! when a listener fails, and waits for it before it returns.

use super::*;
use crate::acme::renew::Renewal;
use std::sync::atomic::{AtomicBool, Ordering};

/// A renewal loop that takes a while to wind down once asked, and says
/// when it has.
fn renewal(wound_down: &Arc<AtomicBool>) -> Renewal {
	let wound_down = Arc::clone(wound_down);
	Renewal::spawn(|mut stop| async move {
		stop.requested().await;
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
		wound_down.store(true, Ordering::SeqCst);
	})
}

#[tokio::test]
async fn a_stop_signal_waits_for_the_renewal_loop_to_wind_down() {
	let wound_down = Arc::new(AtomicBool::new(false));
	let listener = tokio::spawn(std::future::pending::<std::io::Result<()>>());
	let drain = crate::shutdown::Drain::new();

	let result = wait::until(vec![listener], &drain, Some(renewal(&wound_down)), async {
		"SIGTERM"
	})
	.await;

	assert!(result.is_ok(), "{result:?}");
	assert!(
		wound_down.load(Ordering::SeqCst),
		"serve returned before the loop wound down"
	);
}

#[tokio::test]
async fn a_failing_listener_waits_for_the_renewal_loop_to_wind_down() {
	let wound_down = Arc::new(AtomicBool::new(false));
	let listener = tokio::spawn(async { Err(std::io::Error::other("the listener failed")) });
	let drain = crate::shutdown::Drain::new();

	let result = wait::until(
		vec![listener],
		&drain,
		Some(renewal(&wound_down)),
		std::future::pending(),
	)
	.await;

	assert_eq!(
		result.expect_err("the listener failed").to_string(),
		"the listener failed"
	);
	assert!(
		wound_down.load(Ordering::SeqCst),
		"serve returned before the loop wound down"
	);
}
