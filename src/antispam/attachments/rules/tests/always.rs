//! The always-dangerous list: extensions that run, install or open
//! something on a double click, which no `allow_extensions` entry may
//! cover.

use super::*;

/// Script hosts, installers, control panel and console snap-ins, registry
/// and shell files, ClickOnce and web shortcuts, and compiled help.
pub(in super::super) const ADDED: &[&str] = &[
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

/// One extension: dangerous with no configuration, in any case, and still
/// dangerous when the operator tries to allow it.
fn assert_always_dangerous(ext: &str) {
	assert!(ALWAYS_DANGEROUS.contains(&ext), "{ext} is not in the list");
	for name in [
		format!("file.{ext}"),
		format!("FILE.{}", ext.to_uppercase()),
	] {
		assert!(
			judged(&name, &Extensions::default()).contains(&Reason::DangerousExtension),
			"{name} passed with no allowance"
		);
		let allow = Extensions::new(&[], &[ext.to_string()]);
		assert!(
			judged(&name, &allow).contains(&Reason::DangerousExtension),
			"{name} passed with an allowance"
		);
	}
}

/// One test per extension, so a failure names the extension.
macro_rules! one_test_per_extension {
	($($test:ident => $ext:literal),+ $(,)?) => {
		$(
			#[test]
			fn $test() {
				assert_always_dangerous($ext);
			}
		)+

		const TESTED: &[&str] = &[$($ext),+];
	};
}

one_test_per_extension! {
	exe_is_always_dangerous => "exe",
	scr_is_always_dangerous => "scr",
	com_is_always_dangerous => "com",
	pif_is_always_dangerous => "pif",
	cpl_is_always_dangerous => "cpl",
	bat_is_always_dangerous => "bat",
	cmd_is_always_dangerous => "cmd",
	js_is_always_dangerous => "js",
	jse_is_always_dangerous => "jse",
	vbs_is_always_dangerous => "vbs",
	vbe_is_always_dangerous => "vbe",
	wsf_is_always_dangerous => "wsf",
	wsh_is_always_dangerous => "wsh",
	ps1_is_always_dangerous => "ps1",
	ps1xml_is_always_dangerous => "ps1xml",
	psc1_is_always_dangerous => "psc1",
	jar_is_always_dangerous => "jar",
	hta_is_always_dangerous => "hta",
	chm_is_always_dangerous => "chm",
	msi_is_always_dangerous => "msi",
	msp_is_always_dangerous => "msp",
	mst_is_always_dangerous => "mst",
	msc_is_always_dangerous => "msc",
	reg_is_always_dangerous => "reg",
	lnk_is_always_dangerous => "lnk",
	scf_is_always_dangerous => "scf",
	url_is_always_dangerous => "url",
	website_is_always_dangerous => "website",
	appref_ms_is_always_dangerous => "appref-ms",
	application_is_always_dangerous => "application",
	gadget_is_always_dangerous => "gadget",
	iso_is_always_dangerous => "iso",
}

#[test]
fn every_extension_in_the_list_has_its_own_test() {
	let mut listed = ALWAYS_DANGEROUS.to_vec();
	listed.sort_unstable();
	let mut tested = TESTED.to_vec();
	tested.sort_unstable();
	assert_eq!(listed, tested);
}
