//! Alert rules: periodic metric comparisons that fire webhooks or email.

use serde::Deserialize;

use crate::metrics::metric_names;

/// One alert rule. Repeated `[[alerts]]` blocks in the config declare
/// independent rules; an empty list (the default) disables the engine.
///
/// Each rule samples its `metric` counter every `window_secs` and evaluates
/// the per-window delta against `op threshold`. A fire posts a webhook event
/// (when `webhook = true`) and/or queues an email through the outbound spool
/// (one copy per address in `email`). A rule that has fired cannot fire again
/// until `cooldown_secs` have elapsed **and** the condition has stopped
/// holding at least once — without the second half, a sustained "high queue"
/// alert would page every window.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alert {
	/// Stable identifier for the rule (used in the webhook payload, the
	/// email subject, the spool filename, and the engine's logs).
	pub name: String,
	/// Counter name exposed by `Metrics::snapshot` (e.g. `bounced`). Validated
	/// against [`crate::metrics::metric_names`] at load time; an unknown name
	/// is rejected with the list of valid names in the error message.
	pub metric: String,
	/// Comparison applied to the per-window delta of `metric`.
	pub op: AlertOp,
	/// Right-hand side of `op`.
	pub threshold: u64,
	/// Sample interval in seconds. Each tick evaluates the delta of `metric`
	/// over this window.
	pub window_secs: u64,
	/// Post a [`crate::webhook::WebhookEvent::MetricAlert`] when the rule
	/// fires. Requires `[webhook]` to be configured (the webhook poster is
	/// shared with every other event the server emits).
	#[serde(default)]
	pub webhook: bool,
	/// Send an email to each address when the rule fires. Delivered through
	/// the outbound queue, exactly like any other outgoing message, so a
	/// stuck remote MTA defers rather the failure than losing the alert.
	#[serde(default)]
	pub email: Vec<String>,
	/// Minimum seconds between consecutive fires of the same rule, **and** the
	/// condition must have stopped holding at least once between them.
	pub cooldown_secs: u64,
}

/// Comparison operator applied to the windowed delta. The TOML syntax is the
/// operator itself (`>=`, `>`, `<=`, `<`, `==`); each variant carries the
/// corresponding rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum AlertOp {
	/// `delta >= threshold`
	#[serde(rename = ">=")]
	Ge,
	/// `delta > threshold`
	#[serde(rename = ">")]
	Gt,
	/// `delta <= threshold`
	#[serde(rename = "<=")]
	Le,
	/// `delta < threshold`
	#[serde(rename = "<")]
	Lt,
	/// `delta == threshold`
	#[serde(rename = "==")]
	Eq,
}

impl Alert {
	/// Validate one rule. Returns the reason the rule must be rejected, or
	/// `Ok(())` when every field is internally consistent.
	///
	/// The `metric` is checked against the canonical name list returned by
	/// [`crate::metrics::metric_names`]; the error message lists the valid
	/// names so operators do not have to read source.
	pub(super) fn validate(&self) -> Result<(), String> {
		if self.name.trim().is_empty() {
			return Err("[[alerts]] name must not be empty".into());
		}
		if self.name.len() > 128 {
			return Err(format!(
				"[[alerts]] name \"{}\" is longer than 128 characters",
				self.name
			));
		}
		let known = metric_names();
		if !known.iter().any(|name| *name == self.metric) {
			return Err(format!(
				"[[alerts]] metric \"{}\" is not a known counter; valid names: {}",
				self.metric,
				known.join(", ")
			));
		}
		if self.window_secs == 0 {
			return Err(format!(
				"[[alerts]] \"{}\" window_secs must be greater than zero",
				self.name
			));
		}
		if self.cooldown_secs == 0 {
			return Err(format!(
				"[[alerts]] \"{}\" cooldown_secs must be greater than zero",
				self.name
			));
		}
		if !self.webhook && self.email.is_empty() {
			return Err(format!(
				"[[alerts]] \"{}\" has neither webhook = true nor any email recipient",
				self.name
			));
		}
		for address in &self.email {
			if !looks_like_address(address) {
				return Err(format!(
					"[[alerts]] \"{}\" email \"{}\" is not a syntactically valid address",
					self.name, address
				));
			}
		}
		Ok(())
	}
}

/// Cheap syntactic check: one `@`, non-empty local and domain parts, and no
/// CR/LF that could inject headers into the alert email's `To:` field. The
/// deliverability of the address is the recipient's problem, not ours.
fn looks_like_address(value: &str) -> bool {
	if value.contains(['\r', '\n']) || value.len() > 320 {
		return false;
	}
	let Some((local, domain)) = value.split_once('@') else {
		return false;
	};
	!local.is_empty()
		&& !domain.is_empty()
		&& !domain.starts_with('.')
		&& !domain.ends_with('.')
		&& domain.contains('.')
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_minimal_rule() {
		let alert: Alert = toml::from_str(
			r#"
name = "bounce-storm"
metric = "bounced"
op = ">="
threshold = 50
window_secs = 300
cooldown_secs = 900
"#,
		)
		.expect("parse alert");
		assert_eq!(alert.name, "bounce-storm");
		assert_eq!(alert.metric, "bounced");
		assert_eq!(alert.op, AlertOp::Ge);
		assert_eq!(alert.threshold, 50);
		assert_eq!(alert.window_secs, 300);
		assert_eq!(alert.cooldown_secs, 900);
		assert!(!alert.webhook);
		assert!(alert.email.is_empty());
	}

	#[test]
	fn parses_all_operators() {
		#[derive(Deserialize)]
		struct Wrap {
			op: AlertOp,
		}
		for (text, want) in [
			(r#"op = ">=""#, AlertOp::Ge),
			(r#"op = ">""#, AlertOp::Gt),
			(r#"op = "<=""#, AlertOp::Le),
			(r#"op = "<""#, AlertOp::Lt),
			(r#"op = "==""#, AlertOp::Eq),
		] {
			let parsed: Wrap = toml::from_str(text).expect("parse op");
			assert_eq!(parsed.op, want, "{text}");
		}
	}

	#[test]
	fn unknown_metric_lists_valid_names() {
		let alert = Alert {
			name: "broken".into(),
			metric: "not_a_counter".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 60,
			cooldown_secs: 60,
			webhook: true,
			email: Vec::new(),
		};
		let error = alert.validate().expect_err("unknown metric rejected");
		assert!(error.contains("not_a_counter"), "{error}");
		assert!(error.contains("bounced"), "{error}");
	}

	#[test]
	fn zero_window_is_rejected() {
		let alert = Alert {
			name: "broken".into(),
			metric: "bounced".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 0,
			cooldown_secs: 60,
			webhook: true,
			email: Vec::new(),
		};
		assert!(alert.validate().is_err());
	}

	#[test]
	fn zero_cooldown_is_rejected() {
		let alert = Alert {
			name: "broken".into(),
			metric: "bounced".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 60,
			cooldown_secs: 0,
			webhook: true,
			email: Vec::new(),
		};
		assert!(alert.validate().is_err());
	}

	#[test]
	fn silent_alert_is_rejected() {
		let alert = Alert {
			name: "broken".into(),
			metric: "bounced".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 60,
			cooldown_secs: 60,
			webhook: false,
			email: Vec::new(),
		};
		assert!(alert.validate().is_err());
	}

	#[test]
	fn malformed_email_is_rejected() {
		let alert = Alert {
			name: "broken".into(),
			metric: "bounced".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 60,
			cooldown_secs: 60,
			webhook: false,
			email: vec!["no-at-sign".into()],
		};
		assert!(alert.validate().is_err());

		let crlf = Alert {
			email: vec!["a@b\r\nCc: x".into()],
			..alert.clone()
		};
		assert!(crlf.validate().is_err());
	}

	#[test]
	fn unknown_keys_are_rejected() {
		let parsed: Result<Alert, _> = toml::from_str(
			r#"
name = "x"
metric = "bounced"
op = ">="
threshold = 1
window_secs = 60
cooldown_secs = 60
webhook = true
surprise = 1
"#,
		);
		assert!(parsed.is_err());
	}
}
