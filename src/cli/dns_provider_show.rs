//! `dns provider show`: the configured provider without any credential.

use std::io::Write;

use serde_json::{Map, Value, json};

use crate::cli::resource;
use crate::config::{Config, Dns};

/// Settings that name a place a secret lives, shown as written.
fn describe(dns: &Dns) -> Vec<(&'static str, String)> {
	let path = |p: &Option<std::path::PathBuf>| p.as_ref().map(|p| p.display().to_string());
	let text = |v: &Option<String>| v.clone();
	let present = |v: &Option<String>| v.as_ref().map(|_| "set".to_string());
	[
		("provider", Some(dns.provider.clone())),
		("zone", Some(dns.zone.clone())),
		("token", present(&dns.token)),
		("token_env", text(&dns.token_env)),
		("token_file", path(&dns.token_file)),
		("access_key", text(&dns.access_key)),
		("secret_key", present(&dns.secret_key)),
		("secret_key_env", text(&dns.secret_key_env)),
		("hosted_zone_id", text(&dns.hosted_zone_id)),
		("account_id", text(&dns.account_id)),
		("endpoint", text(&dns.endpoint)),
		("consumer_key", present(&dns.consumer_key)),
		("consumer_key_env", text(&dns.consumer_key_env)),
		("key_name", text(&dns.key_name)),
		("algorithm", text(&dns.algorithm)),
		("credentials_file", path(&dns.credentials_file)),
	]
	.into_iter()
	.filter_map(|(key, value)| value.map(|value| (key, value)))
	.collect()
}

pub(super) fn run(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let Some(dns) = &config.dns else {
		if json {
			return resource::json(out, &Value::Null);
		}
		return writeln!(out, "provider\tunset").map_err(|error| error.to_string());
	};
	let rows = describe(dns);
	if json {
		let map: Map<String, Value> = rows
			.into_iter()
			.map(|(k, v)| (k.into(), json!(v)))
			.collect();
		return resource::json(out, &map);
	}
	for (key, value) in rows {
		writeln!(out, "{key}\t{value}").map_err(|error| error.to_string())?;
	}
	Ok(())
}
