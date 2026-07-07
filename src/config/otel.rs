//! OpenTelemetry trace export configuration.

use serde::Deserialize;

/// OTLP trace export. Present enables exporting tracing spans to a collector.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Otel {
	/// OTLP/HTTP endpoint of the collector (e.g. `http://localhost:4318`).
	pub endpoint: String,
	/// `service.name` resource attribute reported to the collector.
	#[serde(default = "default_service_name")]
	pub service_name: String,
}

/// Default OpenTelemetry `service.name`.
fn default_service_name() -> String {
	"epistle".to_string()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_with_default_service_name() {
		let otel: Otel = toml::from_str(r#"endpoint = "http://localhost:4318""#).expect("parse");
		assert_eq!(otel.endpoint, "http://localhost:4318");
		assert_eq!(otel.service_name, "epistle");
	}

	#[test]
	fn service_name_overrides_default() {
		let otel: Otel = toml::from_str(
			r#"
endpoint = "http://collector:4318"
service_name = "epistle-mx"
"#,
		)
		.expect("parse");
		assert_eq!(otel.service_name, "epistle-mx");
	}

	#[test]
	fn rejects_missing_endpoint_and_unknown_keys() {
		assert!(toml::from_str::<Otel>(r#"service_name = "x""#).is_err());
		assert!(
			toml::from_str::<Otel>(
				r#"endpoint = "u"
extra = 1"#
			)
			.is_err()
		);
	}
}
