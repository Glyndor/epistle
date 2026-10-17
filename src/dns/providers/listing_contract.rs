//! What every provider's `list` must do with a record type epistle does not
//! publish. A zone lists an NS (the delegation of a subdomain), a CAA, an
//! HTTPS, an SVCB and types epistle has never heard of; a listing that
//! turns any of them into a TXT hides a delegation from `epistle dns
//! lockdown` and lets a later write act on the wrong record set. Each
//! provider's tests build this zone in its own wire format and hand the
//! listing to [`assert_kinds_kept`].

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, UNKNOWN_KIND};

/// What a listing past the record cap fails with.
pub(crate) const CAP_MESSAGE: &str =
	"the example.org zone is larger than a listing reads (1000 pages, 100000 records)";

/// The NS target of the delegated subdomain `sub.example.org`.
pub(crate) const NS_TARGET: &str = "ns1.delegated.example.";
/// An MX value in presentation form, with the root dot of a hostname trimmed.
pub(crate) const MX_VALUE: &str = "10 mail.example.org";
/// The same MX as a provider that keeps the root dot lists it.
pub(crate) const MX_DOTTED: &str = "10 mail.example.org.";
/// A CAA value in presentation form.
pub(crate) const CAA_VALUE: &str = "0 issue \"letsencrypt.org\"";
/// An HTTPS value in presentation form.
pub(crate) const HTTPS_VALUE: &str = "1 . alpn=\"h2\"";
/// An SVCB value in presentation form.
pub(crate) const SVCB_VALUE: &str = "1 svc.example.net. port=8443";
/// A NAPTR value: a type no provider module knows.
pub(crate) const NAPTR_VALUE: &str = "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.org.";
/// What a record whose type token is [`HOSTILE_TYPE`] carries.
pub(crate) const OPAQUE_VALUE: &str = "opaque";
/// A type token with a terminal escape, a CR LF and a trailing letter, as
/// a hostile or broken API could return it.
pub(crate) const HOSTILE_TYPE: &str = "NAPTR\u{1b}[2J\r\nX";

/// One row the listing is compared on: owner, kind and value.
type Row = (String, String, String);

fn row(name: &str, kind: &RecordKind, value: &str) -> Row {
	(name.to_string(), format!("{kind:?}"), value.to_string())
}

fn rows(records: &[DnsRecord]) -> Vec<Row> {
	let mut rows: Vec<Row> = records
		.iter()
		.map(|r| row(&r.name, &r.kind, &r.value))
		.collect();
	rows.sort();
	rows
}

/// How a provider's wire format bends the shared zone.
pub(crate) struct Shape {
	/// Whether the provider keeps the root dot of a hostname value.
	pub(crate) trailing_dot: bool,
	/// The `Other` token the unknown type comes back as: `NAPTR` for a
	/// provider that returns type names, `TYPE99` for one that numbers them.
	pub(crate) unknown_as: &'static str,
	/// Whether the zone also holds a record whose type token is
	/// [`HOSTILE_TYPE`] (a provider that numbers its types cannot).
	pub(crate) hostile_row: bool,
	/// The MX as the provider lists it: [`MX_VALUE`], or [`MX_DOTTED`] when it
	/// keeps the root dot of the exchange.
	pub(crate) mx: &'static str,
}

impl Shape {
	/// A provider that returns type names and keeps the root dot.
	pub(crate) const NAMED: Shape = Shape {
		trailing_dot: true,
		unknown_as: "NAPTR",
		hostile_row: true,
		mx: MX_VALUE,
	};
}

/// Assert that `listed` is exactly the records of the shared zone with
/// their own kinds and values: the NS at `sub.example.org`, and at the apex an
/// MX with its preference, a CAA with its flags and tag, an
/// HTTPS, an SVCB, a NAPTR and, when `shape` says so, one whose type token
/// is [`HOSTILE_TYPE`], which must come back as `Other(UNKNOWN)`.
#[track_caller]
pub(crate) fn assert_kinds_kept(listed: &[DnsRecord], shape: &Shape) {
	let dot = |value: &str| {
		if shape.trailing_dot {
			value.to_string()
		} else {
			value.trim_end_matches('.').to_string()
		}
	};
	let mut want = vec![
		row("sub.example.org", &RecordKind::Ns, &dot(NS_TARGET)),
		row("example.org", &RecordKind::Caa, CAA_VALUE),
		row("example.org", &RecordKind::Mx, shape.mx),
		row("example.org", &RecordKind::Https, HTTPS_VALUE),
		row("example.org", &RecordKind::Svcb, SVCB_VALUE),
		row(
			"example.org",
			&RecordKind::Other(shape.unknown_as.to_string()),
			&dot(NAPTR_VALUE),
		),
	];
	if shape.hostile_row {
		want.push(row(
			"example.org",
			&RecordKind::Other(UNKNOWN_KIND.to_string()),
			OPAQUE_VALUE,
		));
	}
	want.sort();
	assert_eq!(rows(listed), want, "the listing changed a record's kind");
}

/// Assert that `provider` refuses to publish or remove a record of a type
/// it only lists. A listing that shows an NS must not make it writable: the
/// answer is `Unsupported`, before the provider asks its API anything.
pub(crate) async fn assert_listed_kinds_are_not_written(provider: &dyn DnsProvider) {
	for kind in [
		RecordKind::Ns,
		RecordKind::Https,
		RecordKind::Svcb,
		RecordKind::Other("NAPTR".to_string()),
	] {
		let record = DnsRecord::new("www.example.org", kind.clone(), "x", 3600);
		assert_eq!(
			provider.upsert("example.org", record.clone()).await,
			Err(ProviderError::Unsupported),
			"upsert of {kind:?}"
		);
		assert_eq!(
			provider.delete("example.org", record).await,
			Err(ProviderError::Unsupported),
			"delete of {kind:?}"
		);
	}
}
