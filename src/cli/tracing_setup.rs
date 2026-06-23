//! Tracing subscriber setup: an env-filtered fmt layer plus an optional
//! OpenTelemetry OTLP export layer.

use crate::config::{Config, Otel};

/// A type-erased tracing layer attached at the registry root.
type BoxedLayer = Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>;

/// Install the global tracing subscriber: an env-filtered fmt layer plus, when
/// `[otel]` is configured, an OTLP export layer. Returns the tracer provider so
/// the caller can flush it on shutdown.
pub(super) fn init_tracing(config: &Config) -> Option<opentelemetry_sdk::trace::SdkTracerProvider> {
	use tracing_subscriber::Layer as _;
	use tracing_subscriber::layer::SubscriberExt;
	use tracing_subscriber::util::SubscriberInitExt;

	let filter = tracing_subscriber::EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
	let mut layers: Vec<BoxedLayer> = vec![match config.log_format {
		crate::config::LogFormat::Json => tracing_subscriber::fmt::layer().json().boxed(),
		crate::config::LogFormat::Text => tracing_subscriber::fmt::layer().boxed(),
	}];

	let provider = match &config.otel {
		Some(otel) => match build_otel_layer(otel) {
			Ok((layer, provider)) => {
				layers.push(layer);
				Some(provider)
			}
			Err(error) => {
				eprintln!("warning: OTLP trace export disabled: {error}");
				None
			}
		},
		None => None,
	};

	// Layers attach at `Registry`; the env filter then applies to all of them.
	tracing_subscriber::registry()
		.with(layers)
		.with(filter)
		.init();
	provider
}

/// Build the OpenTelemetry export layer and its tracer provider from `[otel]`.
fn build_otel_layer(
	otel: &Otel,
) -> Result<(BoxedLayer, opentelemetry_sdk::trace::SdkTracerProvider), Box<dyn std::error::Error>> {
	use opentelemetry::trace::TracerProvider as _;
	use opentelemetry_otlp::WithExportConfig as _;
	use tracing_subscriber::Layer as _;

	let exporter = opentelemetry_otlp::SpanExporter::builder()
		.with_http()
		.with_endpoint(&otel.endpoint)
		.build()?;
	let resource = opentelemetry_sdk::Resource::builder()
		.with_service_name(otel.service_name.clone())
		.build();
	let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
		.with_batch_exporter(exporter)
		.with_resource(resource)
		.build();
	let tracer = provider.tracer("epistle");
	let layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();
	Ok((layer, provider))
}
