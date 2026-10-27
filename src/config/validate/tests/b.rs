//! Configuration validation tests: secret, ACME, alias and listener errors.

use super::*;

fn invalid(toml: &str) -> bool {
	let parsed: Result<Config, _> = toml::from_str(toml);
	match parsed {
		Ok(config) => config.validate().is_err(),
		Err(_) => true,
	}
}

const BASE: &str =
	"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\"]\n";

#[test]
fn validates_api_token_hash_format() {
	// A well-formed `sha256:<64-hex>` token hash (what `mail token-hash`
	// emits) is accepted.
	let hex = "a".repeat(64);
	assert!(!invalid(&format!(
		"{BASE}\n[api]\ntoken_hash = \"sha256:{hex}\"\n"
	)));
	// A malformed sha256 (wrong length / non-hex) is rejected.
	assert!(invalid(&format!(
		"{BASE}\n[api]\ntoken_hash = \"sha256:deadbeef\"\n"
	)));
	assert!(invalid(&format!(
		"{BASE}\n[api]\ntoken_hash = \"sha256:{}\"\n",
		"z".repeat(64)
	)));
	// A plaintext / unrecognized hash is rejected.
	assert!(invalid(&format!(
		"{BASE}\n[api]\ntoken_hash = \"plaintext\"\n"
	)));
}

#[test]
fn the_identification_switches_are_read_from_the_file() {
	let file = format!(
		"{BASE}{}",
		"default_feedback_id = false\n\
		 default_list_unsubscribe = false\n\
		 bulk_recipients = 5\n\
		 default_list_id = false\n\
		 system_auto_submitted = false\n\
		 x_epistle_header = true\n\
		 organization_header = false\n\
		 [domain_organization]\n\"example.org\" = \"Example Org\"\n"
	);
	let config: Config = toml::from_str(&file).expect("parse");
	config.validate().expect("valid");
	let policy = crate::smtp::identification::Policy::from_config(&config);
	assert!(!policy.feedback_id);
	assert!(!policy.bulk_unsubscribe);
	assert_eq!(policy.bulk_recipients, 5);
	assert!(!policy.list_id);
	assert!(!policy.system_auto_submitted);
	assert!(policy.x_epistle);
	assert!(!policy.organization);
	assert_eq!(
		policy
			.domain_organization
			.get("example.org")
			.map(String::as_str),
		Some("Example Org")
	);
}

#[test]
fn without_the_keys_the_bulk_threshold_is_twenty_recipients() {
	let config: Config = toml::from_str(BASE).expect("parse");
	config.validate().expect("valid");
	assert_eq!(
		crate::smtp::identification::Policy::from_config(&config).bulk_recipients,
		20,
		"a handful of recipients is correspondence, not bulk mail"
	);
}

#[test]
fn a_bulk_threshold_of_zero_is_refused() {
	// Zero would make every transactional submission with a recipient bulk,
	// and a notice to one person is correspondence.
	assert!(invalid(&format!("{BASE}\nbulk_recipients = 0\n")));
	assert!(!invalid(&format!("{BASE}\nbulk_recipients = 1\n")));
}

#[test]
fn a_domain_organization_value_has_to_be_a_header_safe_ascii_name() {
	// A key that is not a DNS name, an empty value, and a value carrying a
	// line break are all refused: the value reaches an `Organization`
	// field of a message that leaves the server.
	assert!(invalid(&format!(
		"{BASE}\n[domain_organization]\n\"not a domain\" = \"X\"\n"
	)));
	assert!(invalid(&format!(
		"{BASE}\n[domain_organization]\n\"example.org\" = \"  \"\n"
	)));
	assert!(invalid(&format!(
		"{BASE}\n[domain_organization]\n\"example.org\" = \"Example\r\nBcc: victim@example.net\"\n"
	)));
	assert!(invalid(&format!(
		"{BASE}\n[domain_organization]\n\"example.org\" = \"Example\u{7f}\"\n"
	)));
	// A plain name is accepted.
	assert!(!invalid(&format!(
		"{BASE}\n[domain_organization]\n\"example.org\" = \"Example Org\"\n"
	)));
}

#[test]
fn rejects_non_argon2id_account_password() {
	// account password_hash must be argon2id.
	assert!(invalid(&format!(
		"{BASE}\n[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"plaintext\"\n"
	)));
}

#[test]
fn rejects_bad_acme_sections() {
	// Non-https directory URL.
	assert!(invalid(&format!(
		"{BASE}\n[acme]\ndirectory_url = \"http://acme.example/dir\"\ndomains = [\"example.org\"]\n"
	)));
	// No domains.
	assert!(invalid(&format!(
		"{BASE}\n[acme]\ndirectory_url = \"https://acme.example/dir\"\ndomains = []\n"
	)));
	// Domain not configured.
	assert!(invalid(&format!(
		"{BASE}\n[acme]\ndirectory_url = \"https://acme.example/dir\"\ndomains = [\"other.example\"]\n"
	)));
}

#[test]
fn rejects_bad_domain_aliases() {
	// Alias targets an unconfigured domain.
	assert!(invalid(&format!(
		"{BASE}\n[domain_aliases]\n\"alias.example\" = \"missing.example\"\n"
	)));
	// Alias that equals its target.
	assert!(invalid(&format!(
		"{BASE}\n[domain_aliases]\n\"example.org\" = \"example.org\"\n"
	)));
}

#[test]
fn rejects_listeners_missing_required_sections() {
	// submissions (implicit TLS) without [tls].
	assert!(invalid(&format!(
		"{BASE}\n[[listeners]]\nkind = \"submissions\"\n"
	)));
	// imaps without [tls].
	assert!(invalid(&format!(
		"{BASE}\n[[listeners]]\nkind = \"imaps\"\n"
	)));
	// api listener without [api].
	assert!(invalid(&format!("{BASE}\n[[listeners]]\nkind = \"api\"\n")));
}

#[test]
fn webhook_url_must_be_https_or_loopback() {
	use super::*;
	fn ok(toml: &str) -> bool {
		toml::from_str::<Config>(toml).is_ok_and(|c| c.validate().is_ok())
	}
	// Plaintext http to a remote host is rejected (leaks metadata).
	assert!(invalid(&format!(
		"{BASE}\n[webhook]\nurl = \"http://hooks.example/x\"\n"
	)));
	// https is accepted.
	assert!(ok(&format!(
		"{BASE}\n[webhook]\nurl = \"https://hooks.example/x\"\n"
	)));
	// A private destination needs the operator to say so.
	assert!(invalid(&format!(
		"{BASE}\n[webhook]\nurl = \"http://127.0.0.1:9000/x\"\n"
	)));
	assert!(invalid(&format!(
		"{BASE}\n[webhook]\nurl = \"http://localhost/x\"\n"
	)));
	// Loopback http is allowed with the option (never leaves the host).
	assert!(ok(&format!(
		"{BASE}\n[webhook]\nurl = \"http://127.0.0.1:9000/x\"\nallow_private_webhooks = true\n"
	)));
	assert!(ok(&format!(
		"{BASE}\n[webhook]\nurl = \"http://localhost/x\"\nallow_private_webhooks = true\n"
	)));
}

/// Plaintext listener kinds (Submission, WebDav, Api, Autoconfig, Metrics)
/// accepted without `[tls]` so the "front me with a TLS proxy" deployment
/// keeps working. The loopback default is the passive defense; binding
/// externally emits a `tracing::warn!` (still accepted, still parses) until
/// the next release makes rejection opt-in, then fail-closed.
mod plaintext_listener_tls_warning {
	use std::collections::HashMap;
	use std::sync::{Arc, Mutex};

	use tracing::Level;
	use tracing::field::{Field, Visit};
	use tracing_subscriber::layer::{Context, SubscriberExt};
	use tracing_subscriber::{Layer, Registry};

	use super::{BASE, Config, ConfigError};

	#[derive(Clone, Debug)]
	struct CapturedEvent {
		level: Level,
		fields: HashMap<String, String>,
	}

	#[derive(Default)]
	struct Capture {
		events: Arc<Mutex<Vec<CapturedEvent>>>,
	}

	impl<S: tracing::Subscriber> Layer<S> for Capture {
		fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
			let mut fields = HashMap::new();
			event.record(&mut FieldVisitor {
				fields: &mut fields,
			});
			self.events.lock().unwrap().push(CapturedEvent {
				level: *event.metadata().level(),
				fields,
			});
		}
	}

	struct FieldVisitor<'a> {
		fields: &'a mut HashMap<String, String>,
	}

	impl Visit for FieldVisitor<'_> {
		fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
			self.fields
				.insert(field.name().to_string(), format!("{value:?}"));
		}
		fn record_str(&mut self, field: &Field, value: &str) {
			self.fields
				.insert(field.name().to_string(), value.to_string());
		}
		fn record_i64(&mut self, field: &Field, value: i64) {
			self.fields
				.insert(field.name().to_string(), value.to_string());
		}
		fn record_u64(&mut self, field: &Field, value: u64) {
			self.fields
				.insert(field.name().to_string(), value.to_string());
		}
		fn record_bool(&mut self, field: &Field, value: bool) {
			self.fields
				.insert(field.name().to_string(), value.to_string());
		}
	}

	/// Run `f` with a thread-local subscriber that captures every emitted
	/// tracing event, then return the captured set.
	fn run_with_capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
		crate::cli::trace::capture::keep_callsites_live();
		let cap = Capture::default();
		let events = cap.events.clone();
		let subscriber = Registry::default().with(cap);
		tracing::subscriber::with_default(subscriber, f);
		std::mem::take(&mut *events.lock().unwrap())
	}

	fn parse(toml: &str) -> Result<Config, ConfigError> {
		let config: Config =
			toml::from_str(toml).map_err(|e| ConfigError::Invalid(e.to_string()))?;
		config.validate()?;
		Ok(config)
	}

	#[test]
	fn warns_on_submission_bound_externally_without_tls() {
		let events = run_with_capture(|| {
			let result = parse(&format!(
				"{BASE}[[listeners]]\nkind = \"submission\"\naddr = \"0.0.0.0\"\n"
			));
			assert!(result.is_ok(), "submission without [tls] still parses");
		});
		let warn = events
			.iter()
			.find(|e| e.level == Level::WARN)
			.expect("expected a warning for externally-bound plaintext submission");
		let msg = warn.fields.get("message").expect("message field").as_str();
		assert!(
			msg.contains("no-TLS"),
			"warning message must mention no-TLS: {msg}"
		);
		// The `listener` field is recorded via `Debug` (the enum has no
		// `Display`); the variant name is enough to identify what to fix.
		let listener = warn
			.fields
			.get("listener")
			.expect("listener field")
			.as_str();
		assert!(
			listener.eq_ignore_ascii_case("submission"),
			"warning must identify the listener kind: {listener}"
		);
	}

	#[test]
	fn no_warning_on_submission_bound_loopback_without_tls() {
		let events = run_with_capture(|| {
			let result = parse(&format!("{BASE}[[listeners]]\nkind = \"submission\"\n"));
			assert!(result.is_ok());
		});
		assert!(
			!events.iter().any(|e| e.level == Level::WARN),
			"loopback submission is the passive defense: {events:?}"
		);
	}

	#[test]
	fn no_warning_on_webdav_bound_loopback_without_tls() {
		let events = run_with_capture(|| {
			let result = parse(&format!("{BASE}[[listeners]]\nkind = \"web-dav\"\n"));
			assert!(result.is_ok(), "web-dav loopback must validate");
		});
		assert!(
			!events.iter().any(|e| e.level == Level::WARN),
			"loopback webdav is the passive defense: {events:?}"
		);
	}

	#[test]
	fn rejects_pop3s_without_tls() {
		// Pop3s is implicit TLS by protocol definition: the only way to speak
		// it is INSIDE a TLS session. The validate now fails closed here
		// instead of letting serve() crash at bind time.
		let result = parse(&format!("{BASE}[[listeners]]\nkind = \"pop3s\"\n"));
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn accepts_pop3s_with_tls() {
		let result = parse(&format!(
			"{BASE}[[listeners]]\nkind = \"pop3s\"\n\n[tls]\ncert_file = \"/etc/mail/cert.pem\"\nkey_file = \"/etc/mail/key.pem\"\n"
		));
		assert!(result.is_ok());
	}
}

/// The HTTPS autoconfig listener terminates TLS itself, so it cannot start
/// without a certificate.
#[test]
fn autoconfigs_listener_requires_tls() {
	let toml = format!("{BASE}\n[[listeners]]\nkind = \"autoconfigs\"\n");
	let error = match toml::from_str::<Config>(&toml) {
		Ok(config) => config.validate().err().map(|error| error.to_string()),
		Err(error) => Some(error.to_string()),
	};
	let error = error.unwrap_or_default();
	assert!(
		error.contains("is \"autoconfigs\" (HTTPS) but no [tls] section is configured"),
		"{error}"
	);
}
