//! Documentation tests for `docs/configuration.md`. The ports
//! document has to enumerate the TCP ports a public install has
//! to open and call out port 80 as the ACME HTTP-01 responder.
//! This file pins what the document has to keep saying.
//!
//! Sister to the other `apply_*_tests*.rs` files because this one
//! does not own a code surface; the document lives next to the
//! crate, not in it. The test asserts the text by substring so a
//! future edit that drops a port or that turns "certificate
//! issuance" into "Let's Encrypt only" goes red here.

/// The documentation must call out each required port in a single
/// paragraph that lists the operator-facing firewall rules. The
/// phrases here are the unique substrings the doc has to carry
/// next to each port number so a future editor cannot
/// accidentally drop a number without dropping the prose.
const REQUIRED_PORT_PHRASES: &[&str] = &[
	"25",  // SMTP inbound
	"80",  // ACME HTTP-01 challenge responder
	"143", // IMAP STARTTLS
	"465", // IMAP implicit TLS (submissions)
	"587", // Submission STARTTLS
	"993", // IMAP implicit TLS (imaps)
];

/// A public-install firewall section the operator can read
/// without scrolling past the listener reference table. The
/// section has to start with a marker the table-of-contents
/// generator can pick up, and the marker has to be unique to
/// the firewall block so a future edit that moves the section
/// elsewhere does not silently lose the heading.
const FIREWALL_SECTION_HEADING: &str = "### Public-install firewall";

#[test]
fn configuration_md_has_a_public_install_firewall_section() {
	let body =
		std::fs::read_to_string("docs/configuration.md").expect("read docs/configuration.md");
	assert!(
		body.contains(FIREWALL_SECTION_HEADING),
		"docs/configuration.md must have a `### Public-install firewall` section that \
		 enumerates the TCP ports the operator has to open; missing the heading"
	);
}

#[test]
fn configuration_md_firewall_section_lists_every_required_port() {
	let body =
		std::fs::read_to_string("docs/configuration.md").expect("read docs/configuration.md");
	// Find the firewall section. If the heading is missing the
	// earlier test already failed; this test asserts the body of
	// the section, not the heading.
	let heading_pos = body
		.find(FIREWALL_SECTION_HEADING)
		.expect("firewall section heading present (earlier test pins this)");
	let section = &body[heading_pos..];
	// The section ends at the next `## ` or `### ` heading, which
	// the doc generator emits at every level. Take the prefix up
	// to the next marker so a port that lives on a later page does
	// not accidentally satisfy this assertion.
	let section_end = section
		.find("\n## ")
		.or_else(|| section.find("\n### "))
		.unwrap_or(section.len());
	let section = &section[..section_end];
	for port in REQUIRED_PORT_PHRASES {
		assert!(
			section.contains(port),
			"the firewall section must mention port {port:?}; missing in {section:?}"
		);
	}
}

#[test]
fn configuration_md_firewall_section_explains_port_80_is_for_certificate_issuance() {
	let body =
		std::fs::read_to_string("docs/configuration.md").expect("read docs/configuration.md");
	let heading_pos = body
		.find(FIREWALL_SECTION_HEADING)
		.expect("firewall section heading present");
	let section_end = body[heading_pos..]
		.find("\n## ")
		.or_else(|| body[heading_pos..].find("\n### "))
		.unwrap_or(body.len() - heading_pos);
	let section = &body[heading_pos..heading_pos + section_end];
	// The doc has to name the HTTP-01 challenge so an operator
	// understands why port 80 must be open to the public
	// internet, and that an HTTP challenge from the CA is what
	// the responder serves. A document that only said "for ACME"
	// would leave the operator guessing.
	assert!(
		section.contains("HTTP-01"),
		"the firewall section must explain port 80 serves the HTTP-01 challenge; section: {section:?}"
	);
	assert!(
		section.contains("certificate") || section.contains("Certificate"),
		"the firewall section must mention certificate issuance so the operator knows what \
		 port 80 is for; section: {section:?}"
	);
}
