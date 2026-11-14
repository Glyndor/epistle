use super::InputError;

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_ID_BYTES: usize = 255;

pub(crate) const MAX_QUERY_LIMIT: usize = super::super::limits::MAX_OBJECTS_IN_GET;

pub(super) struct Page {
	position: i64,
	anchor: Option<String>,
	anchor_offset: i64,
	limit: usize,
	server_adjusted_limit: bool,
	calculate_total: Option<bool>,
}

impl Page {
	pub(super) fn parse(args: &serde_json::Value) -> Result<Self, InputError> {
		let position = optional_integer(args, "position")?.unwrap_or(0);
		let anchor_offset = optional_integer(args, "anchorOffset")?.unwrap_or(0);
		let requested_limit = optional_unsigned_integer(args, "limit")?;
		let limit = requested_limit.map_or(MAX_QUERY_LIMIT, |value| {
			usize::try_from(value)
				.unwrap_or(MAX_QUERY_LIMIT)
				.min(MAX_QUERY_LIMIT)
		});
		let server_adjusted_limit =
			requested_limit.is_none_or(|value| value > MAX_QUERY_LIMIT as u64);
		let anchor = match args.get("anchor") {
			None | Some(serde_json::Value::Null) => None,
			Some(serde_json::Value::String(value)) => Some(valid_id(value)?),
			Some(_) => return Err(InputError::invalid("anchor must be an id")),
		};
		let calculate_total = match args.get("calculateTotal") {
			None => None,
			Some(serde_json::Value::Bool(value)) => Some(*value),
			Some(_) => return Err(InputError::invalid("calculateTotal must be a boolean")),
		};
		match args.get("collapseThreads") {
			None | Some(serde_json::Value::Bool(_)) => {}
			Some(_) => return Err(InputError::invalid("collapseThreads must be a boolean")),
		}
		Ok(Self {
			position,
			anchor,
			anchor_offset,
			limit,
			server_adjusted_limit,
			calculate_total,
		})
	}

	pub(super) fn position(&self) -> i64 {
		self.position
	}

	pub(super) fn anchor(&self) -> Option<&str> {
		self.anchor.as_deref()
	}

	pub(super) fn anchor_offset(&self) -> i64 {
		self.anchor_offset
	}

	pub(super) fn limit(&self) -> usize {
		self.limit
	}

	pub(super) fn server_adjusted_limit(&self) -> bool {
		self.server_adjusted_limit
	}

	pub(super) fn include_total(&self) -> bool {
		self.calculate_total != Some(false)
	}
}

fn optional_integer(args: &serde_json::Value, key: &str) -> Result<Option<i64>, InputError> {
	let value = match args.get(key) {
		None => return Ok(None),
		Some(value) => value,
	};
	let number = value
		.as_i64()
		.ok_or_else(|| InputError::invalid(format!("{key} must be an integer")))?;
	if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&number) {
		return Err(InputError::invalid(format!(
			"{key} is outside the JMAP Int range"
		)));
	}
	Ok(Some(number))
}

fn optional_unsigned_integer(
	args: &serde_json::Value,
	key: &str,
) -> Result<Option<u64>, InputError> {
	let value = match args.get(key) {
		None | Some(serde_json::Value::Null) => return Ok(None),
		Some(value) => value,
	};
	let number = value
		.as_u64()
		.ok_or_else(|| InputError::invalid(format!("{key} must be an unsigned integer")))?;
	if number > MAX_SAFE_INTEGER as u64 {
		return Err(InputError::invalid(format!(
			"{key} is outside the JMAP Int range"
		)));
	}
	Ok(Some(number))
}

fn valid_id(value: &str) -> Result<String, InputError> {
	if value.is_empty()
		|| value.len() > MAX_ID_BYTES
		|| !value
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
	{
		return Err(InputError::invalid("anchor must be a valid id"));
	}
	Ok(value.to_string())
}
