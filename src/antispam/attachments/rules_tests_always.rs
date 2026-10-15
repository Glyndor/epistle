//! The always-dangerous list: extensions that run, install or open
//! something on a double click, which no `allow_extensions` entry may
//! cover.

use super::*;

/// Script hosts, installers, control panel and console snap-ins, registry
/// and shell files, ClickOnce and web shortcuts, and compiled help.
pub(super) const ADDED: &[&str] = &[
	"jse",
	"vbe",
	"wsf",
	"wsh",
	"cpl",
	"scf",
	"msc",
	"msp",
	"mst",
	"reg",
	"ps1xml",
	"psc1",
	"appref-ms",
	"gadget",
	"application",
	"hta",
	"url",
	"website",
	"chm",
];

fn judged(name: &str, extensions: &Extensions) -> Vec<Reason> {
	judge(
		&Facts {
			filenames: &[name.to_string()],
			declared_types: &["application/octet-stream".to_string()],
			real_type: RealType::Unknown,
			listing: None,
			ole: None,
		},
		extensions,
	)
}

#[test]
fn every_always_dangerous_extension_is_dangerous_to_begin_with() {
	let missing: Vec<&str> = ALWAYS_DANGEROUS
		.iter()
		.copied()
		.filter(|ext| !DANGEROUS_EXTENSIONS.contains(ext))
		.collect();
	assert_eq!(missing, Vec::<&str>::new());
}

#[test]
fn an_allowance_never_covers_an_always_dangerous_extension() {
	let slipped: Vec<&str> = ADDED
		.iter()
		.copied()
		.filter(|ext| {
			let allow = Extensions::new(&[], &[ext.to_string()]);
			!judged(&format!("file.{ext}"), &allow).contains(&Reason::DangerousExtension)
		})
		.collect();
	assert_eq!(slipped, Vec::<&str>::new());
}

#[test]
fn the_list_has_no_duplicates() {
	let mut sorted = ALWAYS_DANGEROUS.to_vec();
	sorted.sort_unstable();
	sorted.dedup();
	assert_eq!(sorted.len(), ALWAYS_DANGEROUS.len());
}
