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
mod tests;
