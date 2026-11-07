//! Exercise PUT followed by the real query dispatchers, requesting etags only.

use super::{calendar, event, isolated_with_deadline, query};
use crate::webdav::test_support::{MKCOL_ADDRESSBOOK, MKCOL_CALENDAR, send_as_alice, test_app};
use axum::http::StatusCode;
use std::time::Duration;

#[test]
fn calendar_query_reaches_the_last_of_twenty_thousand_series() {
	isolated_with_deadline(
		"reports::calendar_query_reaches_the_last_of_twenty_thousand_series",
		Duration::from_secs(60),
		|| {
			tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
				.expect("runtime")
				.block_on(async {
					let dir = tempfile::tempdir().expect("tempdir");
					let app = test_app(dir.path());
					assert_eq!(
						send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR)
							.await
							.0,
						StatusCode::CREATED
					);
					let events = event("FREQ=DAILY", "SUMMARY:decoy\r\n").repeat(19_999)
						+ &event("FREQ=DAILY", "SUMMARY:needle\r\n");
					let ics = calendar(&events);
					assert_eq!(
						send_as_alice(&app, "PUT", "/cal/hostile.ics", &[], ics.as_bytes())
							.await
							.0,
						StatusCode::CREATED
					);
					for (needle, expected) in [("needle", true), ("absent", false)] {
						let prop = format!(
							"<C:prop-filter name=\"SUMMARY\"><C:text-match>{needle}</C:text-match></C:prop-filter>"
						);
						let body = query("20260101T000000Z", "20260201T000000Z", &prop);
						let (status, response) = send_as_alice(
							&app,
							"REPORT",
							"/cal",
							&[("Depth", "1")],
							body.as_bytes(),
						)
						.await;
						assert_eq!(status, StatusCode::MULTI_STATUS, "{response}");
						assert_eq!(
							response.contains("/cal/hostile.ics"),
							expected,
							"{response}"
						);
					}
				});
		},
	);
}

#[test]
fn addressbook_query_filters_a_stored_hostile_card() {
	isolated_with_deadline(
		"reports::addressbook_query_filters_a_stored_hostile_card",
		Duration::from_secs(60),
		|| {
			tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
				.expect("runtime")
				.block_on(async {
					let dir = tempfile::tempdir().expect("tempdir");
					let app = test_app(dir.path());
					assert_eq!(
						send_as_alice(&app, "MKCOL", "/book", &[], MKCOL_ADDRESSBOOK)
							.await
							.0,
						StatusCode::CREATED
					);
					let card = super::card::hostile_card();
					assert_eq!(
						send_as_alice(&app, "PUT", "/book/hostile.vcf", &[], card.as_bytes())
							.await
							.0,
						StatusCode::CREATED
					);
					for (value, expected) in
						[("alice@example.org", true), ("ce@example.org", false)]
					{
						let body = super::card::query("EMAIL", value);
						let (status, response) = send_as_alice(
							&app,
							"REPORT",
							"/book",
							&[("Depth", "1")],
							body.as_bytes(),
						)
						.await;
						assert_eq!(status, StatusCode::MULTI_STATUS, "{response}");
						assert_eq!(
							response.contains("/book/hostile.vcf"),
							expected,
							"{response}"
						);
					}
				});
		},
	);
}
