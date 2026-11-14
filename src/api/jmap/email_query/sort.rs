use super::InputError;

const MAX_COMPARATORS: usize = 4;

#[derive(Default)]
pub(super) struct Sort {
	ascending: bool,
	explicit: bool,
}

impl Sort {
	pub(super) fn parse(value: Option<&serde_json::Value>) -> Result<Self, InputError> {
		let items = match value {
			None | Some(serde_json::Value::Null) => return Ok(Self::default()),
			Some(serde_json::Value::Array(items)) => items,
			Some(_) => return Err(InputError::invalid("sort must be an array")),
		};
		if items.is_empty() {
			return Ok(Self::default());
		}
		if items.len() > MAX_COMPARATORS {
			return Err(InputError::invalid("sort has too many comparators"));
		}
		let mut ascending = true;
		let mut found = false;
		for item in items {
			let object = item
				.as_object()
				.ok_or_else(|| InputError::invalid("sort comparator must be an object"))?;
			let property = object
				.get("property")
				.and_then(serde_json::Value::as_str)
				.ok_or_else(|| InputError::invalid("sort comparator property must be a string"))?;
			if property != "receivedAt" {
				return Err(InputError::unsupported_sort());
			}
			if object
				.keys()
				.any(|key| key != "property" && key != "isAscending" && key != "collation")
			{
				return Err(InputError::invalid(
					"sort comparator has unknown properties",
				));
			}
			if object
				.get("collation")
				.is_some_and(|value| !value.is_string())
			{
				return Err(InputError::invalid("collation must be a string"));
			}
			let item_ascending = match object.get("isAscending") {
				None => true,
				Some(serde_json::Value::Bool(value)) => *value,
				Some(_) => return Err(InputError::invalid("isAscending must be a boolean")),
			};
			if !found {
				ascending = item_ascending;
				found = true;
			}
		}
		Ok(Self {
			ascending,
			explicit: true,
		})
	}

	pub(super) fn ascending(&self) -> bool {
		self.ascending
	}

	pub(super) fn replayable(&self) -> bool {
		!self.explicit || !self.ascending
	}
}
