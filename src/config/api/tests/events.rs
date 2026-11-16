use super::*;

#[test]
fn the_event_stream_limits_are_optional() {
	let api: Api = toml::from_str(r#"token_hash = "sha256:x""#).expect("parse");
	assert_eq!(api.event_streams_per_key, None);
	assert_eq!(api.event_streams_per_server, None);
	assert_eq!(api.event_stream_max_secs, None);
}

#[test]
fn the_event_stream_limits_are_read() {
	let api: Api = toml::from_str(
		"event_streams_per_key = 2\nevent_streams_per_server = 10\nevent_stream_max_secs = 600",
	)
	.expect("parse");
	assert_eq!(api.event_streams_per_key, Some(2));
	assert_eq!(api.event_streams_per_server, Some(10));
	assert_eq!(api.event_stream_max_secs, Some(600));
}

#[test]
fn an_event_stream_limit_outside_its_range_names_the_key_and_the_range() {
	for (text, key) in [
		("event_streams_per_key = 0", "event_streams_per_key"),
		("event_streams_per_key = 1025", "event_streams_per_key"),
		("event_streams_per_server = 0", "event_streams_per_server"),
		(
			"event_streams_per_server = 65537",
			"event_streams_per_server",
		),
		("event_stream_max_secs = 59", "event_stream_max_secs"),
		("event_stream_max_secs = 86401", "event_stream_max_secs"),
	] {
		let error = toml::from_str::<Api>(text).expect_err(text).to_string();
		assert!(
			error.contains(key) && error.contains("must be between"),
			"{error}"
		);
	}
}
