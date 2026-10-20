//! Per-provider rules for `dns provider set`, mirroring what `Dns::build` needs.

use clap::Args;
use toml_edit::Value;

use crate::cli::config_edit::FieldChange;

/// Provider settings. Which ones apply depends on the provider; secrets are
/// referenced by environment variable or file, never given inline.
#[derive(Debug, Clone, Default, Args)]
pub struct ProviderArgs {
	/// Move the current or supplied token into secrets/dns_provider_token.
	#[arg(long)]
	pub store_token: bool,
	/// The DNS zone the credentials are scoped to.
	#[arg(long)]
	pub zone: Option<String>,
	/// Environment variable holding the API token.
	#[arg(long, value_name = "VAR")]
	pub token_env: Option<String>,
	/// 0600 file holding the API token.
	#[arg(long, value_name = "FILE")]
	pub token_file: Option<String>,
	/// API key id (Route 53, GoDaddy, Porkbun, OVH, Spaceship).
	#[arg(long)]
	pub access_key: Option<String>,
	/// Environment variable holding the secret key.
	#[arg(long, value_name = "VAR")]
	pub secret_key_env: Option<String>,
	/// Route 53 hosted zone id.
	#[arg(long)]
	pub hosted_zone_id: Option<String>,
	/// DNSimple account id.
	#[arg(long)]
	pub account_id: Option<String>,
	/// OVH region (ovh-eu, ovh-ca, ovh-us) or RFC 2136 nameserver HOST:PORT.
	#[arg(long)]
	pub endpoint: Option<String>,
	/// OVH: environment variable holding the consumer key.
	#[arg(long, value_name = "VAR")]
	pub consumer_key_env: Option<String>,
	/// RFC 2136: TSIG key name.
	#[arg(long)]
	pub key_name: Option<String>,
	/// RFC 2136: TSIG algorithm (hmac-sha256, hmac-sha384, hmac-sha512).
	#[arg(long)]
	pub algorithm: Option<String>,
	/// Google Cloud: service-account JSON file.
	#[arg(long, value_name = "FILE")]
	pub credentials_file: Option<String>,
	/// Namecheap: the IPv4 address on the account's API whitelist.
	#[arg(long, value_name = "IPV4")]
	pub client_ip: Option<String>,
}

/// One setting the user can pass, with the TOML key it becomes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Setting {
	Token,
	AccessKey,
	SecretKeyEnv,
	HostedZoneId,
	AccountId,
	Endpoint,
	ConsumerKeyEnv,
	KeyName,
	Algorithm,
	CredentialsFile,
	ClientIp,
}

use Setting::*;

/// Required and optional settings per provider, taken from `Dns::build`.
fn rules(provider: &str) -> Option<(&'static [Setting], &'static [Setting])> {
	Some(match provider {
		"cloudflare" | "bunny" | "desec" | "digitalocean" => (&[Token], &[]),
		"namecheap" => (&[Token, ClientIp], &[]),
		"dnsimple" => (&[Token, AccountId], &[]),
		"spaceship" | "godaddy" | "porkbun" => (&[AccessKey, SecretKeyEnv], &[]),
		"gcloud" => (&[Token, CredentialsFile], &[]),
		"ovh" => (&[AccessKey, SecretKeyEnv, ConsumerKeyEnv], &[Endpoint]),
		"route53" => (&[AccessKey, SecretKeyEnv, HostedZoneId], &[]),
		"rfc2136" => (&[Token, KeyName, Endpoint], &[Algorithm]),
		"manual" => (&[], &[]),
		_ => return None,
	})
}

impl Setting {
	fn flag(self) -> &'static str {
		match self {
			Token => "--token-env or --token-file",
			AccessKey => "--access-key",
			SecretKeyEnv => "--secret-key-env",
			HostedZoneId => "--hosted-zone-id",
			AccountId => "--account-id",
			Endpoint => "--endpoint",
			ConsumerKeyEnv => "--consumer-key-env",
			KeyName => "--key-name",
			Algorithm => "--algorithm",
			CredentialsFile => "--credentials-file",
			ClientIp => "--client-ip",
		}
	}

	fn given(self, args: &ProviderArgs) -> bool {
		match self {
			Token => args.token_env.is_some() || args.token_file.is_some(),
			AccessKey => args.access_key.is_some(),
			SecretKeyEnv => args.secret_key_env.is_some(),
			HostedZoneId => args.hosted_zone_id.is_some(),
			AccountId => args.account_id.is_some(),
			Endpoint => args.endpoint.is_some(),
			ConsumerKeyEnv => args.consumer_key_env.is_some(),
			KeyName => args.key_name.is_some(),
			Algorithm => args.algorithm.is_some(),
			CredentialsFile => args.credentials_file.is_some(),
			ClientIp => args.client_ip.is_some(),
		}
	}
}

const ALL: [Setting; 11] = [
	Token,
	AccessKey,
	SecretKeyEnv,
	HostedZoneId,
	AccountId,
	Endpoint,
	ConsumerKeyEnv,
	KeyName,
	Algorithm,
	CredentialsFile,
	ClientIp,
];

fn check_env(flag: &str, name: &str) -> Result<(), String> {
	let mut chars = name.chars();
	let valid = chars
		.next()
		.is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
		&& chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
	if valid {
		Ok(())
	} else {
		Err(format!(
			"{flag} \"{name}\" is not an environment variable name"
		))
	}
}

fn check_path(flag: &str, path: &str) -> Result<(), String> {
	if path.starts_with('/') && !path.chars().any(char::is_control) {
		Ok(())
	} else {
		Err(format!("{flag} must be an absolute path"))
	}
}

fn check_value(flag: &str, value: &str) -> Result<(), String> {
	if value.trim().is_empty() || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
		Err(format!("{flag} must not be empty or contain whitespace"))
	} else {
		Ok(())
	}
}

fn check_endpoint(provider: &str, endpoint: &str) -> Result<(), String> {
	let valid = match provider {
		"ovh" => {
			matches!(endpoint, "ovh-eu" | "ovh-ca" | "ovh-us") || endpoint.starts_with("https://")
		}
		_ => endpoint.rsplit_once(':').is_some_and(|(host, port)| {
			!host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0)
		}),
	};
	if valid && check_value("--endpoint", endpoint).is_ok() {
		Ok(())
	} else if provider == "ovh" {
		Err("--endpoint must be ovh-eu, ovh-ca, ovh-us or an https:// URL".into())
	} else {
		Err("--endpoint must be the nameserver HOST:PORT".into())
	}
}

/// Validate the request and build the complete set of `[dns]` fields, with
/// every key the provider does not use cleared.
pub(super) fn fields(
	provider: &str,
	args: &ProviderArgs,
) -> Result<Vec<FieldChange<'static>>, String> {
	let provider = provider.trim().to_ascii_lowercase();
	let Some((required, optional)) = rules(&provider) else {
		return Err(format!(
			"provider \"{provider}\" is not a supported provider; supported: {}",
			crate::config::SUPPORTED_PROVIDERS.join(", ")
		));
	};
	let zone = args.zone.as_deref().ok_or("--zone is required")?;
	let zone = crate::cli::resource::dns_name("--zone", zone)?;
	for setting in required {
		if !setting.given(args) {
			return Err(format!("{provider} needs {}", setting.flag()));
		}
	}
	for setting in ALL {
		if setting.given(args) && !required.contains(&setting) && !optional.contains(&setting) {
			return Err(format!("{} is not used by {provider}", setting.flag()));
		}
	}
	if args.token_env.is_some() && args.token_file.is_some() {
		return Err("choose one of --token-env and --token-file".into());
	}
	let text = |value: &Option<String>| value.as_deref().map(Value::from);
	if let Some(name) = &args.token_env {
		check_env("--token-env", name)?;
	}
	if let Some(name) = &args.secret_key_env {
		check_env("--secret-key-env", name)?;
	}
	if let Some(name) = &args.consumer_key_env {
		check_env("--consumer-key-env", name)?;
	}
	for (flag, path) in [
		("--token-file", &args.token_file),
		("--credentials-file", &args.credentials_file),
	] {
		if let Some(path) = path {
			check_path(flag, path)?;
		}
	}
	for (flag, value) in [
		("--access-key", &args.access_key),
		("--hosted-zone-id", &args.hosted_zone_id),
		("--account-id", &args.account_id),
		("--key-name", &args.key_name),
	] {
		if let Some(value) = value {
			check_value(flag, value)?;
		}
	}
	if let Some(endpoint) = &args.endpoint {
		check_endpoint(&provider, endpoint)?;
	}
	if let Some(ip) = &args.client_ip
		&& ip.parse::<std::net::Ipv4Addr>().is_err()
	{
		return Err("--client-ip must be an IPv4 address".into());
	}
	if let Some(algorithm) = &args.algorithm
		&& !matches!(
			algorithm.as_str(),
			"hmac-sha256" | "hmac-sha384" | "hmac-sha512"
		) {
		return Err("--algorithm must be hmac-sha256, hmac-sha384 or hmac-sha512".into());
	}
	Ok(vec![
		("provider", Some(Value::from(provider.as_str()))),
		("zone", Some(Value::from(zone))),
		("token", None),
		("token_file", text(&args.token_file)),
		("token_env", text(&args.token_env)),
		("access_key", text(&args.access_key)),
		("secret_key", None),
		("secret_key_env", text(&args.secret_key_env)),
		("hosted_zone_id", text(&args.hosted_zone_id)),
		("account_id", text(&args.account_id)),
		("endpoint", text(&args.endpoint)),
		("consumer_key", None),
		("consumer_key_env", text(&args.consumer_key_env)),
		("key_name", text(&args.key_name)),
		("algorithm", text(&args.algorithm)),
		("credentials_file", text(&args.credentials_file)),
		("client_ip", text(&args.client_ip)),
	])
}
