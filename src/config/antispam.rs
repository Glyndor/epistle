//! LLM-assisted spam screening for the uncertain band.
//!
//! Present enables a chat-completions call for inbound mail whose Bayesian
//! score lands in a configured uncertain band (the Bayesian classifier is
//! confident outside it; an LLM is only worth calling when the local model is
//! not). Fails open: any transport, timeout, parse or shape failure is logged
//! at WARN and the message is accepted, so an outage never blocks mail.

use serde::Deserialize;

/// Bayesian scores outside `[uncertain_low, uncertain_high]` skip the LLM
/// entirely — they are already trusted to one side or the other. The defaults
/// are deliberately wide: most messages either look clearly ham or clearly
/// spam, and the LLM is paid for only when the local classifier is unsure.
const DEFAULT_LOW: f64 = 0.35;
const DEFAULT_HIGH: f64 = 0.65;
/// Conservative default so a misconfigured endpoint does not silently hang
/// the delivery path.
const DEFAULT_TIMEOUT_SECS: u64 = 10;
/// Bytes of the raw message forwarded to the LLM. Small enough to keep token
/// cost bounded; large enough for typical headers plus body.
const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024;

/// LLM-assisted antispam hook configuration. Present enables the hook; the
/// configuration is keyed by an environment variable for the API secret so the
/// key never lands on disk.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Llm {
	/// OpenAI-compatible chat-completions endpoint URL.
	pub endpoint: String,
	/// Name of the environment variable that carries the API key. The value is
	/// read at server start; absent or empty is a fatal configuration error.
	pub api_key_env: String,
	/// Model identifier sent in each request body (e.g. `gpt-4o-mini`).
	pub model: String,
	/// Inclusive lower bound of the uncertain band. Scores below this skip the
	/// LLM call entirely. Defaults to `0.35`.
	#[serde(default = "default_low")]
	pub uncertain_low: f64,
	/// Inclusive upper bound of the uncertain band. Scores above this skip the
	/// LLM call entirely. Defaults to `0.65`.
	#[serde(default = "default_high")]
	pub uncertain_high: f64,
	/// Per-request HTTP timeout, in seconds. Defaults to `10`.
	#[serde(default = "default_timeout_secs")]
	pub timeout_secs: u64,
	/// Maximum bytes of the raw message forwarded to the LLM (headers plus
	/// body, truncated). Defaults to `16384` (16 KiB).
	#[serde(default = "default_max_body_bytes")]
	pub max_body_bytes: usize,
}

fn default_low() -> f64 {
	DEFAULT_LOW
}

fn default_high() -> f64 {
	DEFAULT_HIGH
}

fn default_timeout_secs() -> u64 {
	DEFAULT_TIMEOUT_SECS
}

fn default_max_body_bytes() -> usize {
	DEFAULT_MAX_BODY_BYTES
}

impl std::fmt::Debug for Llm {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Llm")
			.field("endpoint", &self.endpoint)
			.field("api_key_env", &self.api_key_env)
			.field("model", &self.model)
			.field("uncertain_low", &self.uncertain_low)
			.field("uncertain_high", &self.uncertain_high)
			.field("timeout_secs", &self.timeout_secs)
			.field("max_body_bytes", &self.max_body_bytes)
			.finish()
	}
}

impl Llm {
	/// Whether `score` falls inside the uncertain band and therefore needs the
	/// LLM to decide. A score that sits exactly on a boundary counts as
	/// uncertain (inclusive bounds) so an empty corpus (`score == 0.5`) is
	/// asked, not silently accepted.
	pub fn is_uncertain(&self, score: f64) -> bool {
		score >= self.uncertain_low && score <= self.uncertain_high
	}

	/// Read the API key from the process environment. Returns the configured
	/// `api_key_env` so the operator can tell at a glance which variable was
	/// expected when it is unset.
	pub(crate) fn read_api_key(&self) -> Result<String, super::ConfigError> {
		match std::env::var(&self.api_key_env) {
			Ok(value) if !value.is_empty() => Ok(value),
			_ => Err(super::ConfigError::MissingEnv(self.api_key_env.clone())),
		}
	}

	/// Cross-field consistency: a misconfigured band is a logic bug, not a
	/// runtime hint, so reject it at load time.
	pub(super) fn validate(&self) -> Result<(), super::ConfigError> {
		if self.uncertain_low < 0.0 || self.uncertain_low > 1.0 {
			return Err(super::ConfigError::Invalid(format!(
				"[antispam.llm] uncertain_low must be in [0.0, 1.0]: {}",
				self.uncertain_low
			)));
		}
		if self.uncertain_high < 0.0 || self.uncertain_high > 1.0 {
			return Err(super::ConfigError::Invalid(format!(
				"[antispam.llm] uncertain_high must be in [0.0, 1.0]: {}",
				self.uncertain_high
			)));
		}
		if self.uncertain_low >= self.uncertain_high {
			return Err(super::ConfigError::Invalid(format!(
				"[antispam.llm] uncertain_low ({}) must be < uncertain_high ({})",
				self.uncertain_low, self.uncertain_high
			)));
		}
		if self.timeout_secs == 0 {
			return Err(super::ConfigError::Invalid(
				"[antispam.llm] timeout_secs must be > 0".into(),
			));
		}
		if self.max_body_bytes == 0 {
			return Err(super::ConfigError::Invalid(
				"[antispam.llm] max_body_bytes must be > 0".into(),
			));
		}
		if self.endpoint.trim().is_empty() {
			return Err(super::ConfigError::Invalid(
				"[antispam.llm] endpoint must not be empty".into(),
			));
		}
		if self.api_key_env.trim().is_empty() {
			return Err(super::ConfigError::Invalid(
				"[antispam.llm] api_key_env must not be empty".into(),
			));
		}
		if self.model.trim().is_empty() {
			return Err(super::ConfigError::Invalid(
				"[antispam.llm] model must not be empty".into(),
			));
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sample() -> Llm {
		Llm {
			endpoint: "https://api.example/v1/chat/completions".to_string(),
			api_key_env: "EPISTLE_LLM_API_KEY".to_string(),
			model: "gpt-4o-mini".to_string(),
			uncertain_low: 0.35,
			uncertain_high: 0.65,
			timeout_secs: 10,
			max_body_bytes: 16384,
		}
	}

	#[test]
	fn parses_with_defaults() {
		let parsed: Llm = toml::from_str(
			r#"
endpoint = "https://api.example/v1/chat/completions"
api_key_env = "EPISTLE_LLM_API_KEY"
model = "gpt-4o-mini"
"#,
		)
		.expect("parse");
		assert_eq!(parsed.uncertain_low, 0.35);
		assert_eq!(parsed.uncertain_high, 0.65);
		assert_eq!(parsed.timeout_secs, 10);
		assert_eq!(parsed.max_body_bytes, 16384);
	}

	#[test]
	fn parses_with_overrides() {
		let parsed: Llm = toml::from_str(
			r#"
endpoint = "https://api.example/v1/chat/completions"
api_key_env = "X"
model = "m"
uncertain_low = 0.2
uncertain_high = 0.8
timeout_secs = 5
max_body_bytes = 1024
"#,
		)
		.expect("parse");
		assert_eq!(parsed.uncertain_low, 0.2);
		assert_eq!(parsed.uncertain_high, 0.8);
		assert_eq!(parsed.timeout_secs, 5);
		assert_eq!(parsed.max_body_bytes, 1024);
	}

	#[test]
	fn rejects_unknown_keys() {
		assert!(
			toml::from_str::<Llm>(
				r#"
endpoint = "https://x/y"
api_key_env = "X"
model = "m"
surprise = true
"#,
			)
			.is_err()
		);
	}

	#[test]
	fn band_is_inclusive() {
		let llm = sample();
		assert!(llm.is_uncertain(0.35));
		assert!(llm.is_uncertain(0.65));
		assert!(llm.is_uncertain(0.5));
		assert!(!llm.is_uncertain(0.349));
		assert!(!llm.is_uncertain(0.651));
	}

	#[test]
	fn validate_rejects_inverted_band() {
		let mut llm = sample();
		llm.uncertain_low = 0.7;
		llm.uncertain_high = 0.3;
		let error = llm.validate().expect_err("inverted band must fail");
		assert!(format!("{error}").contains("uncertain_low"), "{error}");
	}

	#[test]
	fn validate_rejects_zero_timeout() {
		let mut llm = sample();
		llm.timeout_secs = 0;
		let error = llm.validate().expect_err("zero timeout must fail");
		assert!(format!("{error}").contains("timeout_secs"), "{error}");
	}

	#[test]
	fn validate_rejects_out_of_range_score() {
		let mut llm = sample();
		llm.uncertain_low = 1.5;
		let error = llm.validate().expect_err("out-of-range low must fail");
		assert!(format!("{error}").contains("uncertain_low"), "{error}");

		let mut llm = sample();
		llm.uncertain_high = -0.1;
		let error = llm.validate().expect_err("out-of-range high must fail");
		assert!(format!("{error}").contains("uncertain_high"), "{error}");
	}

	#[test]
	fn validate_rejects_zero_body() {
		let mut llm = sample();
		llm.max_body_bytes = 0;
		let error = llm.validate().expect_err("zero body must fail");
		assert!(format!("{error}").contains("max_body_bytes"), "{error}");
	}

	#[test]
	fn validate_rejects_empty_strings() {
		let mut llm = sample();
		llm.endpoint = "".into();
		let error = llm.validate().expect_err("empty endpoint must fail");
		assert!(format!("{error}").contains("endpoint"), "{error}");

		let mut llm = sample();
		llm.api_key_env = "   ".into();
		let error = llm.validate().expect_err("blank env name must fail");
		assert!(format!("{error}").contains("api_key_env"), "{error}");

		let mut llm = sample();
		llm.model = "".into();
		let error = llm.validate().expect_err("empty model must fail");
		assert!(format!("{error}").contains("model"), "{error}");
	}

	#[test]
	fn debug_redacts_nothing_but_omits_key_value() {
		// The API key is read from the environment, not stored on the struct;
		// the only secret-ish field visible in Debug is `api_key_env` (the
		// variable *name*), and that is exactly what the operator configured.
		let llm = sample();
		let rendered = format!("{llm:?}");
		assert!(rendered.contains("EPISTLE_LLM_API_KEY"));
		assert!(!rendered.contains("sk-"), "{rendered}");
	}
}
