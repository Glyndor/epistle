//! Live NTS-KE and NTPv4 probes against real public servers.
//!
//! Off by default: a network probe under `cargo test` only when the
//! operator explicitly opts in. The site is read-only and the binary
//! runs no privileged operation, but a CI run that touches the public
//! NTS endpoints would create a network dependency the rest of the
//! suite does not share.
//!
//! Activation:
//! ```text
//! EPISTLE_CLOCK_LIVE=1 cargo test --test clock_external_live -- --ignored --nocapture
//! ```
//!
//! The variable is consumed once at process start; an unset or empty
//! value is treated as disabled and the tests print a notice rather
//! than touching the network. The dial timeout is 15 s per probe; the
//! probes are run serially because the run cap on real hosts is short
//! and the KE+auth round-trip already costs a few hundred milliseconds
//! on a healthy link.

use std::time::Duration;

fn enabled() -> bool {
	std::env::var("EPISTLE_CLOCK_LIVE")
		.map(|value| value == "1")
		.unwrap_or(false)
}

fn notice(test: &str) {
	eprintln!(
		"[clock_external_live] {test}: skipped (set EPISTLE_CLOCK_LIVE=1 to run, \
		 no network contact in the default cargo test path)"
	);
}

const DEADLINE: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "current_thread")]
#[ignore = "live probe; enable with EPISTLE_CLOCK_LIVE=1"]
async fn live_plain_ntp_against_time_google_com() {
	if !enabled() {
		notice("live_plain_ntp_against_time_google_com");
		return;
	}
	let source = epistle::clock::external::Source::ntp("time.google.com");
	let result = epistle::clock::external::adapter::plain_ntp(&source, DEADLINE).await;
	println!("Google plain NTP result: {result:?}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "live probe; enable with EPISTLE_CLOCK_LIVE=1"]
async fn live_plain_ntp_against_time_cloudflare_com() {
	if !enabled() {
		notice("live_plain_ntp_against_time_cloudflare_com");
		return;
	}
	let source = epistle::clock::external::Source::ntp("time.cloudflare.com");
	let result = epistle::clock::external::adapter::plain_ntp(&source, DEADLINE).await;
	println!("Cloudflare plain NTP result: {result:?}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "live probe; enable with EPISTLE_CLOCK_LIVE=1"]
async fn live_nts_ke_against_time_cloudflare_com() {
	if !enabled() {
		notice("live_nts_ke_against_time_cloudflare_com");
		return;
	}
	let source = epistle::clock::external::Source::nts("time.cloudflare.com");
	let result = epistle::clock::external::adapter::ke_then_ntp(&source, DEADLINE).await;
	println!("Cloudflare NTS-KE result: {result:?}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "live probe; enable with EPISTLE_CLOCK_LIVE=1"]
async fn live_nts_ke_against_nts_netnod_se() {
	if !enabled() {
		notice("live_nts_ke_against_nts_netnod_se");
		return;
	}
	let source = epistle::clock::external::Source::nts("nts.netnod.se");
	let result = epistle::clock::external::adapter::ke_then_ntp(&source, DEADLINE).await;
	println!("Netnod NTS-KE result: {result:?}");
}
