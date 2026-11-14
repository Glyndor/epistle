//! Command variants for discovery.

macro_rules! discovery_commands {
	($next:ident $(, $rest:ident)*; $($variants:tt)*) => {
		$next! { $($rest),*;
			$($variants)*
			/// Check published DNS records against what epistle expects.
			///
			/// Check published DNS records against what epistle expects and report
			/// drift (read-only; queries DNS, changes nothing).
			VerifyDns {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Print the DNS records this deployment should publish.
			///
			/// Print the DNS records this deployment should publish (SPF, DKIM, DMARC,
			/// MTA-STS, MX and a DANE TLSA record when a certificate is present).
			DnsRecords {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Print an Apple `.mobileconfig` profile for an account.
			///
			/// Print an Apple `.mobileconfig` profile for an account (for the user to
			/// install on iOS/macOS to auto-configure Mail).
			Mobileconfig {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// The account name.
				#[arg(long, value_name = "NAME")]
				account: String,
			},
			/// Print the RFC 6186 SRV records to publish in DNS.
			SrvRecords {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Print the Thunderbird autoconfig XML for a domain.
			///
			/// Print the Thunderbird autoconfig XML for a domain (host it at
			/// `autoconfig.<domain>/mail/config-v1.1.xml`).
			Autoconfig {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// The domain (defaults to the first configured domain).
				#[arg(long, value_name = "DOMAIN")]
				domain: Option<String>,
			},
			/// Print the Microsoft Autodiscover v1 XML for a domain.
			///
			/// Print the Microsoft Autodiscover v1 XML for a domain (host it at
			/// `autodiscover.<domain>/autodiscover/autodiscover.xml`).
			Autodiscover {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// The domain (defaults to the first configured domain).
				#[arg(long, value_name = "DOMAIN")]
				domain: Option<String>,
			},
		}
	};
}

pub(super) use discovery_commands;
