//! Command variants for keys.

macro_rules! keys_commands {
	($next:ident $(, $rest:ident)*; $($variants:tt)*) => {
		$next! { $($rest),*;
			$($variants)*
			/// Generate a DKIM key and print the DNS record value.
			DkimKeygen {
				/// Where to write the private key (PKCS#8 PEM).
				#[arg(long, value_name = "FILE")]
				out: PathBuf,
				/// Generate an RSA key instead of the default ed25519 key. The TXT
				/// record then uses `k=rsa` and is split across 255-octet strings
				/// per RFC 1035 §3.3.14.
				#[arg(long)]
				rsa: bool,
				/// RSA modulus size in bits, only meaningful with `--rsa`. Accepts
				/// 2048 (default) or 4096.
				#[arg(long, value_name = "BITS", default_value_t = 2048)]
				bits: u32,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Generate an at-rest message-encryption key and print it.
			///
			/// Generate a base64 32-byte at-rest message-encryption key and print it to
			/// stdout. Store it off the data disk (an env var or a key file), then
			/// point `[storage]` at it; never written into data_dir.
			StorageKeygen {
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Generate the ES256 key pair for the built-in OAuth server.
			///
			/// Generate an ES256 key pair for the built-in OAuth authorization server
			/// and write it to a file only the owner can read: the base64 PKCS#8
			/// private key for `[oauth] signing_key` and the matching base64 public
			/// point for `[oauth] public_key`. The private key is never printed.
			OauthKeygen {
				/// Where to write the key pair (mode 0600; an existing file is refused).
				#[arg(long, value_name = "FILE")]
				out: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
		}
	};
}

pub(super) use keys_commands;
