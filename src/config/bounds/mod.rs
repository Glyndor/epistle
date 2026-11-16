//! The range check the settings with a floor share.

/// `Ok` when `value` is absent or lies within `low..=high`; otherwise the
/// message the loader prints, naming the setting by `path`, for example
/// `[bans] threshold`.
pub(super) fn check<T: PartialOrd + std::fmt::Display>(
	path: &str,
	value: Option<T>,
	(low, high): (T, T),
) -> Result<(), String> {
	match value {
		Some(value) if value < low || value > high => {
			Err(format!("{path} ({value}) must be between {low} and {high}"))
		}
		_ => Ok(()),
	}
}
