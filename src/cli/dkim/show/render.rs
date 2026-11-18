//! Printing the view as text or JSON.

use std::process::ExitCode;

use super::DkimView;

/// Print the view as text or JSON.
pub(in crate::cli::dkim) fn render(
	view: &DkimView,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let result = if json {
		serde_json::to_writer_pretty(&mut *out, view)
			.map_err(std::io::Error::other)
			.and_then(|()| writeln!(out))
	} else {
		render_text(view, out)
	};
	if result.is_ok() {
		ExitCode::SUCCESS
	} else {
		ExitCode::FAILURE
	}
}

/// `ed` alone, or `ed and rsa` when an RSA selector goes with it.
fn pair(ed: &str, rsa: Option<&str>) -> String {
	match rsa {
		Some(rsa) => format!("{ed} and {rsa}"),
		None => ed.to_string(),
	}
}

/// An instant as RFC 3339 UTC, or `-` when there is none.
fn when(epoch: Option<u64>) -> String {
	epoch.map_or_else(|| "-".to_string(), crate::clock::rfc3339_or_epoch)
}

fn render_text(view: &DkimView, out: &mut impl std::io::Write) -> std::io::Result<()> {
	writeln!(out, "selector: {} ({})", view.selector, view.algorithm)?;
	writeln!(
		out,
		"key file: {} (from {})",
		view.key_file.display(),
		view.source
	)?;
	writeln!(out, "rotated at: {}", when(view.rotated_at))?;
	if !view.automatic_rotation {
		writeln!(out, "next rotation: never ([dns] is not configured)")?;
	} else if view.next_rotation_due.is_none() {
		writeln!(out, "next rotation: at the server's next hourly tick")?;
	} else {
		writeln!(out, "next rotation: {}", when(view.next_rotation_due))?;
	}
	if let Some(rsa) = &view.rsa_selector {
		writeln!(
			out,
			"rsa selector: {rsa} (from {})",
			view.rsa_source.unwrap_or("config")
		)?;
	}
	if let Some(previous) = &view.previous {
		writeln!(
			out,
			"previous: {} (retires at {})",
			pair(&previous.selector, previous.rsa_selector.as_deref()),
			crate::clock::rfc3339_or_epoch(previous.retire_at)
		)?;
	}
	if let Some(next) = &view.in_progress {
		let to = pair(&next.selector, next.rsa_selector.as_deref());
		let since = crate::clock::rfc3339_or_epoch(next.started_at);
		match &next.withdrawing {
			Some(reason) => writeln!(out, "rotation to {to} is being withdrawn: {reason}")?,
			None if next.rsa_selector.is_some() => writeln!(
				out,
				"rotation to {to} in progress since {since}; {} sign until DNS shows the new keys",
				pair(&view.selector, view.rsa_selector.as_deref())
			)?,
			None => writeln!(
				out,
				"rotation to {to} in progress since {since}; {} signs until DNS shows the new key",
				view.selector
			)?,
		}
	}
	if let Some(at) = view.rotation_requested_at {
		writeln!(
			out,
			"rotation requested at {}, waiting for the server",
			crate::clock::rfc3339_or_epoch(at)
		)?;
	}
	if let Some(error) = &view.last_request_error {
		writeln!(out, "last rotation error: {error}")?;
	}
	for entry in &view.overrides {
		let rsa = entry
			.rsa_selector
			.as_deref()
			.map(|rsa| format!(" and rsa {rsa}"))
			.unwrap_or_default();
		writeln!(
			out,
			"override {}: {}{} ({})",
			entry.domain,
			entry.selector,
			rsa,
			entry.key_file.display()
		)?;
	}
	for key in &view.keys {
		let who = if key.shared_with.is_empty() {
			"its own key".to_string()
		} else {
			format!("shared with {}", key.shared_with.join(", "))
		};
		writeln!(
			out,
			"key {}: {} ({who})",
			key.domain,
			pair(&key.selector, key.rsa_selector.as_deref())
		)?;
	}
	if !view.stale_records.is_empty() {
		writeln!(
			out,
			"split incomplete: the shared key is still published at {}; `epistle dkim split --finish` retires it",
			view.stale_records.join(", ")
		)?;
	}
	if !view.stale_unchecked.is_empty() {
		writeln!(
			out,
			"split: could not check whether the shared key is still published ({})",
			view.stale_unchecked.join("; ")
		)?;
	}
	for record in &view.records {
		writeln!(out, "{} {}", record.status, record.name)?;
	}
	Ok(())
}
