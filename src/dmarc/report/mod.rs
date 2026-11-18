//! DMARC aggregate report generation (RFC 7489 §7).

use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;

mod email;
pub use email::build_email;

/// One per-message DMARC delivery record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeliveryRecord {
	/// Unix timestamp (seconds) of acceptance.
	pub timestamp: u64,
	/// Sending client IP address.
	pub source_ip: String,
	/// RFC5321.MailFrom domain (envelope from), empty if null sender.
	pub envelope_from: String,
	/// RFC5322.From domain.
	pub header_from: String,
	/// SPF result keyword.
	pub spf: String,
	/// DKIM result keyword; empty string means no DKIM signatures.
	pub dkim: String,
	/// Authenticated identifier domain from the passing DKIM signature, if any.
	pub dkim_domain: String,
	/// DMARC result keyword.
	pub dmarc: String,
	/// Disposition actually applied (none/quarantine/reject).
	pub disposition: String,
	/// Domain whose DMARC record was consulted.
	pub policy_domain: String,
	/// The `p=` value of the record that was evaluated: `none`,
	/// `quarantine` or `reject`. Empty when no record applied.
	pub published_policy: String,
	/// The `sp=` value of that record, or its `p=` value when it carries
	/// no `sp=`. Empty when no record applied, and in records written
	/// before the field existed.
	#[serde(default)]
	pub published_subdomain_policy: String,
	/// The `pct=` value of that record; 100 when no record applied.
	pub pct: u8,
}

/// Build a gzip-compressed aggregate XML report (RFC 7489 Appendix C).
/// `records` is the full set of delivery records for `domain` during the period.
pub fn build_xml(
	org_name: &str,
	org_email: &str,
	report_id: &str,
	period_start: u64,
	period_end: u64,
	domain: &str,
	records: &[DeliveryRecord],
) -> Vec<u8> {
	let xml = generate_xml(
		org_name,
		org_email,
		report_id,
		period_start,
		period_end,
		domain,
		records,
	);
	let mut enc = GzEncoder::new(Vec::new(), Compression::default());
	enc.write_all(xml.as_bytes())
		.expect("in-memory gzip cannot fail");
	enc.finish().expect("in-memory gzip cannot fail")
}

fn generate_xml(
	org_name: &str,
	org_email: &str,
	report_id: &str,
	period_start: u64,
	period_end: u64,
	domain: &str,
	records: &[DeliveryRecord],
) -> String {
	use std::collections::HashMap;

	let mut out = String::with_capacity(2048);
	out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n");
	out.push_str("<feedback>\n");

	// Report metadata.
	out.push_str("  <report_metadata>\n");
	out.push_str(&format!(
		"    <org_name>{}</org_name>\n",
		xml_escape(org_name)
	));
	out.push_str(&format!("    <email>{}</email>\n", xml_escape(org_email)));
	out.push_str(&format!(
		"    <report_id>{}</report_id>\n",
		xml_escape(report_id)
	));
	out.push_str("    <date_range>\n");
	out.push_str(&format!("      <begin>{period_start}</begin>\n"));
	out.push_str(&format!("      <end>{period_end}</end>\n"));
	out.push_str("    </date_range>\n");
	out.push_str("  </report_metadata>\n");

	// Published policy, as the evaluated record stated it. The first
	// record that carries one is quoted: a message no record applied to
	// says nothing about a published policy. When no message of the
	// period had one, RFC 7489's defaults stand (`p=none`, `pct=100`).
	let (policy, subdomain_policy, pct) = records
		.iter()
		.find(|record| !record.published_policy.is_empty())
		.map(|record| {
			let policy = record.published_policy.as_str();
			let subdomain_policy = match record.published_subdomain_policy.as_str() {
				"" => policy,
				subdomain_policy => subdomain_policy,
			};
			(policy, subdomain_policy, record.pct)
		})
		.unwrap_or(("none", "none", 100));
	out.push_str("  <policy_published>\n");
	out.push_str(&format!("    <domain>{}</domain>\n", xml_escape(domain)));
	out.push_str(&format!("    <p>{}</p>\n", xml_escape(policy)));
	out.push_str(&format!("    <sp>{}</sp>\n", xml_escape(subdomain_policy)));
	out.push_str(&format!("    <pct>{pct}</pct>\n"));
	out.push_str("  </policy_published>\n");

	// Aggregate: group by (source_ip, disposition, spf, dkim).
	type RowKey = (String, String, String, String);
	let mut rows: HashMap<RowKey, (u64, &DeliveryRecord)> = HashMap::new();
	for rec in records {
		let key = (
			rec.source_ip.clone(),
			rec.disposition.clone(),
			rec.spf.clone(),
			rec.dkim.clone(),
		);
		let entry = rows.entry(key).or_insert((0, rec));
		entry.0 += 1;
	}

	let mut sorted_rows: Vec<_> = rows.into_iter().collect();
	sorted_rows.sort_by_key(|(k, _)| k.clone());

	for ((source_ip, disposition, spf, dkim), (count, rec)) in &sorted_rows {
		out.push_str("  <record>\n");
		out.push_str("    <row>\n");
		out.push_str(&format!(
			"      <source_ip>{}</source_ip>\n",
			xml_escape(source_ip)
		));
		out.push_str(&format!("      <count>{count}</count>\n"));
		out.push_str("      <policy_evaluated>\n");
		out.push_str(&format!(
			"        <disposition>{}</disposition>\n",
			xml_escape(disposition)
		));
		out.push_str(&format!("        <dkim>{}</dkim>\n", xml_escape(dkim)));
		out.push_str(&format!("        <spf>{}</spf>\n", xml_escape(spf)));
		out.push_str("      </policy_evaluated>\n");
		out.push_str("    </row>\n");
		out.push_str("    <identifiers>\n");
		out.push_str(&format!(
			"      <header_from>{}</header_from>\n",
			xml_escape(&rec.header_from)
		));
		if !rec.envelope_from.is_empty() {
			out.push_str(&format!(
				"      <envelope_from>{}</envelope_from>\n",
				xml_escape(&rec.envelope_from)
			));
		}
		out.push_str("    </identifiers>\n");
		out.push_str("    <auth_results>\n");
		if !rec.dkim_domain.is_empty() {
			out.push_str("      <dkim>\n");
			out.push_str(&format!(
				"        <domain>{}</domain>\n",
				xml_escape(&rec.dkim_domain)
			));
			out.push_str(&format!("        <result>{dkim}</result>\n"));
			out.push_str("      </dkim>\n");
		}
		out.push_str("      <spf>\n");
		let spf_domain = if rec.envelope_from.is_empty() {
			domain
		} else {
			&rec.envelope_from
		};
		out.push_str(&format!(
			"        <domain>{}</domain>\n",
			xml_escape(spf_domain)
		));
		out.push_str(&format!("        <result>{spf}</result>\n"));
		out.push_str("      </spf>\n");
		out.push_str("    </auth_results>\n");
		out.push_str("  </record>\n");
	}

	out.push_str("</feedback>\n");
	out
}

/// Escape `&`, `<`, `>`, `"`, `'` for XML text/attribute content.
fn xml_escape(s: &str) -> String {
	s.chars()
		.flat_map(|c| match c {
			'&' => "&amp;".chars().collect::<Vec<_>>(),
			'<' => "&lt;".chars().collect(),
			'>' => "&gt;".chars().collect(),
			'"' => "&quot;".chars().collect(),
			'\'' => "&apos;".chars().collect(),
			c => vec![c],
		})
		.collect()
}

#[cfg(test)]
mod tests;
