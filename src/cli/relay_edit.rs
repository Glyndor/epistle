//! Validation and `[[transport]]` edits behind `relay add` and `relay remove`.

use toml_edit::Value;

use super::{Target, find};
use crate::cli::config_edit::ConfigDocument;
use crate::config::{Config, TransportKind};

/// Everything `relay add` was asked to write.
pub(super) struct Request {
	pub target: Target,
	pub host: String,
	pub port: Option<u16>,
	pub starttls: bool,
	pub username: Option<String>,
	pub password: Option<String>,
	pub password_stdin: bool,
	pub socks_proxy: Option<String>,
}

fn is_relay(table: &dyn toml_edit::TableLike) -> bool {
	table.get("kind").and_then(|kind| kind.as_str()) == Some("relay")
}

fn check_host(host: &str) -> Result<(), String> {
	let valid = !host.is_empty()
		&& host.len() <= 253
		&& host
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':'));
	if valid {
		Ok(())
	} else {
		Err(format!(
			"--host \"{host}\" is not a host name or address (letters, digits, '-', '.', '_' and ':')"
		))
	}
}

fn check_proxy(proxy: &str) -> Result<(), String> {
	let valid = proxy.rsplit_once(':').is_some_and(|(host, port)| {
		check_host(host).is_ok() && port.parse::<u16>().is_ok_and(|port| port != 0)
	});
	if valid {
		Ok(())
	} else {
		Err(format!("--socks-proxy \"{proxy}\" must be HOST:PORT"))
	}
}

fn check_target(target: &Target) -> Result<Target, String> {
	let mut target = target.clone();
	if let Some(account) = &target.account
		&& (account.is_empty() || account.contains(|c: char| c.is_whitespace() || c == '@'))
	{
		return Err(format!(
			"--account \"{account}\" is not a local account name"
		));
	}
	if let Some(domain) = &target.domain {
		crate::config::validate_dns_name("--domain", domain).map_err(|error| error.to_string())?;
		target.domain = Some(domain.trim().to_ascii_lowercase());
	}
	Ok(target)
}

pub(super) fn add(
	document: &mut ConfigDocument,
	config: &Config,
	request: Request,
) -> Result<(), String> {
	let target = check_target(&request.target)?;
	check_host(&request.host)?;
	if let Some(proxy) = &request.socks_proxy {
		check_proxy(proxy)?;
	}
	if request.port == Some(0) {
		return Err("--port must be between 1 and 65535".into());
	}
	if request.password_stdin && request.username.is_none() {
		return Err("--password-stdin needs --username".into());
	}
	if let Some(other) = config
		.transport
		.iter()
		.find(|rule| rule.kind != TransportKind::Relay && target.matches(rule))
	{
		return Err(format!(
			"{} already has a {:?} transport rule; remove it from the configuration first",
			capitalize(&target.describe()),
			other.kind
		));
	}
	let existing = find(config, &target).ok();
	let auth = match request.username.as_deref() {
		None => None,
		Some(user) if user.is_empty() || user.chars().any(char::is_control) => {
			return Err("--username must not be empty or contain control characters".into());
		}
		Some(_) if !request.starttls => {
			return Err(
				"--username requires --starttls: credentials are never sent in plaintext".into(),
			);
		}
		Some(user) => {
			let password = request
				.password
				.clone()
				.or_else(|| existing.and_then(|rule| rule.password.clone()))
				.ok_or("--username needs --password-stdin: pipe the password in as one line")?;
			Some((user.to_string(), password))
		}
	};
	let port = request
		.port
		.unwrap_or(if request.starttls { 587 } else { 25 });
	let string = |value: &str| Some(Value::from(value));
	let fields = [
		("account", target.account.as_deref().and_then(string)),
		("domain", target.domain.as_deref().and_then(string)),
		("kind", string("relay")),
		("host", string(&request.host)),
		("port", Some(Value::from(i64::from(port)))),
		("starttls", request.starttls.then(|| Value::from(true))),
		("username", auth.as_ref().and_then(|(user, _)| string(user))),
		("password", auth.as_ref().and_then(|(_, pass)| string(pass))),
		(
			"socks_proxy",
			request.socks_proxy.as_deref().and_then(string),
		),
	];
	document.upsert_where(
		"transport",
		&|table| target.matches_table(table) && is_relay(table),
		&fields,
	)
}

pub(super) fn remove(
	document: &mut ConfigDocument,
	config: &Config,
	target: &Target,
) -> Result<(), String> {
	let target = check_target(target)?;
	find(config, &target)?;
	document.remove_where("transport", &|table| {
		target.matches_table(table) && is_relay(table)
	})?;
	Ok(())
}

fn capitalize(text: &str) -> String {
	let mut chars = text.chars();
	chars
		.next()
		.map(|first| first.to_uppercase().chain(chars).collect())
		.unwrap_or_default()
}
