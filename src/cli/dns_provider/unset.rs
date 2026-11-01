//! `dns provider unset --zone`: remove one zone's entry and keep the rest.

use toml_edit::TableLike;

use crate::cli::config_edit::ConfigDocument;

/// Remove the `[dns]` entry for `zone`. Refuses when there is none, so a typo
/// never reports a removal that did not happen.
pub(super) fn zone(document: &mut ConfigDocument, zone: &str) -> Result<(), String> {
	let zone = crate::cli::resource::dns_name("--zone", zone)?;
	let removed = if document.is_table("dns") {
		// A lone `[dns]` table is the entry of its own zone.
		let owns = document.config()?.dns.for_zone(&zone).is_some();
		if owns {
			document.remove_table(&["dns"])?;
		}
		usize::from(owns)
	} else {
		document.remove_where("dns", &|table: &dyn TableLike| {
			super::write::is_zone(table, &zone)
		})?
	};
	if removed == 0 {
		return Err(format!("no [dns] entry for zone {zone}"));
	}
	Ok(())
}
