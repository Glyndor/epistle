use super::log_filter;
use tracing_subscriber::layer::SubscriberExt;

/// Levels of the events that get through `filter`, from the DNSSEC library's
/// own target and from epistle's.
fn passed(filter: tracing_subscriber::EnvFilter) -> (Vec<tracing::Level>, Vec<tracing::Level>) {
	use crate::cli::trace::capture::{Capture, keep_callsites_live};
	keep_callsites_live();
	let capture = Capture::default();
	let events = capture.events.clone();
	let subscriber = tracing_subscriber::Registry::default()
		.with(capture)
		.with(filter);
	tracing::subscriber::with_default(subscriber, || {
		tracing::warn!(target: "hickory_net::dnssec", "response does not contain NSEC or NSEC3 records");
		tracing::error!(target: "hickory_net::dnssec", "exceeded max validation depth");
		tracing::warn!(target: "epistle::queue", "kept");
	});
	let levels = |keep_library: bool| {
		events
			.lock()
			.unwrap()
			.iter()
			.filter(|event| {
				event.fields.get("message").is_some_and(|m| m == "kept") != keep_library
			})
			.map(|event| event.level)
			.collect::<Vec<_>>()
	};
	(levels(true), levels(false))
}

#[test]
fn the_default_silences_the_dnssec_library_and_keeps_the_rest() {
	for spec in [None, Some("info,hickory_net=loud"), Some("")] {
		let (library, ours) = passed(log_filter(spec));
		assert!(
			library.is_empty(),
			"{spec:?}: library lines got through: {library:?}"
		);
		assert_eq!(ours, [tracing::Level::WARN], "{spec:?}");
	}
}

#[test]
fn the_operator_can_raise_the_library_again() {
	let (library, _) = passed(log_filter(Some("info,hickory_net::dnssec=warn")));
	assert_eq!(library, [tracing::Level::WARN, tracing::Level::ERROR]);
}
