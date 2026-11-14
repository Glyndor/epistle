use super::RecordKind;

/// Free-text description that epistle attaches to every record it creates or
/// updates, for providers whose record API has a per-record description field
/// (Cloudflare `comment`, Bunny `Comment`, Porkbun `notes`). It reads
/// `Epistle v<version>` with the version of the running binary, and every
/// create and every update rewrites it, so a record touched again by a newer
/// release shows the newer version. It is a label for whoever reads the
/// provider's panel, not an ownership key: record matching still uses only
/// type, name and, for TXT, the value. Providers without such a field never
/// receive it. Kept in this one function so the text is easy to extend; it
/// stays well under the tightest documented limit (100 characters on the
/// Cloudflare free plan).
pub fn record_description() -> String {
	format!("Epistle v{}", env!("CARGO_PKG_VERSION"))
}

/// A DNS record to publish or remove.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DnsRecord {
	/// Fully-qualified record name (e.g. `_dmarc.example.org`).
	pub name: String,
	/// Record type.
	pub kind: RecordKind,
	/// Record value in presentation form for its kind (raw IPv4/IPv6 for
	/// A/AAAA, target host for MX, etc.). For TXT it is the logical text,
	/// unquoted and unsplit; a value already in quoted presentation form is
	/// accepted and read back through [`crate::dns::txt::txt_logical`].
	/// Each provider encodes it for its own API and every `list` returns
	/// the logical text again.
	pub value: String,
	/// Time-to-live in seconds. Providers translate to their own semantics.
	pub ttl: u32,
	/// Whether the record is proxied through the provider's edge (Cloudflare's
	/// "orange cloud"). Providers that do not proxy (every other one
	/// epistle publishes through) ignore it on write and leave it `None`
	/// on read. Cloudflare populates it from the API's `proxied` field on
	/// `list` and always writes `proxied: false` for mail-related names,
	/// because traffic for SMTP / IMAP / POP3 / submission cannot reach
	/// epistle through the proxy.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub proxied: Option<bool>,
}

impl DnsRecord {
	/// A record with `proxied: None` (the default for every non-Cloudflare
	/// provider). The convenience constructor exists so call sites that
	/// build a record by hand do not have to spell the field out; tests
	/// already build `DnsRecord` literally.
	pub fn new(
		name: impl Into<String>,
		kind: RecordKind,
		value: impl Into<String>,
		ttl: u32,
	) -> Self {
		Self {
			name: name.into(),
			kind,
			value: value.into(),
			ttl,
			proxied: None,
		}
	}
}
