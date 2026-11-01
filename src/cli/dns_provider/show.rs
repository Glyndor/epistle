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
		("client_ip", text(&dns.client_ip)),
	]
	.into_iter()
	.filter_map(|(key, value)| value.map(|value| (key, value)))
	.collect()
}

pub(super) fn run(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let rows = |dns: &Dns| -> Map<String, Value> {
		describe(dns)
			.into_iter()
			.map(|(k, v)| (k.into(), json!(v)))
			.collect()
	};
	match config.dns.len() {
		0 => {
			if json {
				return resource::json(out, &Value::Null);
			}
			writeln!(out, "provider\tunset").map_err(|error| error.to_string())
		}
		1 if !config.dns.scoped() => {
			let dns = config.dns.first().ok_or("no provider")?;
			if json {
				return resource::json(out, &rows(dns));
			}
			print_rows(dns, out)
		}
		// Several entries: a list in JSON, and one block per entry in text,
		// each starting with its `provider` and `zone` rows.
		_ => {
			if json {
				let list: Vec<_> = config.dns.iter().map(rows).collect();
				return resource::json(out, &list);
			}
			for (index, dns) in config.dns.iter().enumerate() {
				if index > 0 {
					writeln!(out).map_err(|error| error.to_string())?;
				}
				print_rows(dns, out)?;
			}
			Ok(())
		}
	}
}

fn print_rows(dns: &Dns, out: &mut impl Write) -> Result<(), String> {
	for (key, value) in describe(dns) {
		writeln!(out, "{key}\t{value}").map_err(|error| error.to_string())?;
	}
	Ok(())
}
