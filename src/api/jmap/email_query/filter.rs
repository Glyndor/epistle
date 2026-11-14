use super::InputError;
use super::content::{Content, TextQuery};

const MAX_FILTER_DEPTH: usize = 8;
const MAX_FILTER_NODES: usize = 64;
const MAX_FILTER_TEXT_BYTES: usize = 1_024;
const MAX_TEXT_TERMS_TOTAL: usize = 32;
const MAX_KEYWORD_BYTES: usize = 64;
const MAX_MAILBOX_BYTES: usize = 255;

pub(super) struct Filter {
	root: Node,
}

enum Node {
	All(Vec<Condition>),
	And(Vec<Node>),
	Or(Vec<Node>),
	Not(Box<Node>),
}

enum Condition {
	InMailbox(String),
	Text(TextQuery),
	From(TextQuery),
	To(TextQuery),
	Subject(TextQuery),
	Before(u64),
	After(u64),
	HasKeyword(String),
	NotKeyword(String),
}

pub(super) enum ReplayScope {
	All,
	Mailbox(String),
}

struct Parser {
	nodes: usize,
	text_terms: usize,
}

impl Filter {
	pub(super) fn parse(value: Option<&serde_json::Value>) -> Result<Self, InputError> {
		let mut parser = Parser {
			nodes: 0,
			text_terms: 0,
		};
		let root = match value {
			None | Some(serde_json::Value::Null) => Node::All(Vec::new()),
			Some(serde_json::Value::Object(object)) => parser.parse_object(object, 0)?,
			Some(_) => return Err(InputError::invalid("filter must be an object")),
		};
		Ok(Self { root })
	}

	pub(super) fn needs_content(&self) -> bool {
		self.root.needs_content()
	}

	pub(super) fn mailbox_scope(&self) -> Option<String> {
		self.root.mailbox_scope()
	}

	pub(super) fn replayable_scope(&self) -> Option<ReplayScope> {
		match &self.root {
			Node::All(conditions) if conditions.is_empty() => Some(ReplayScope::All),
			Node::And(children) if children.is_empty() => Some(ReplayScope::All),
			Node::All(conditions) if conditions.len() == 1 => match &conditions[0] {
				Condition::InMailbox(mailbox) => Some(ReplayScope::Mailbox(mailbox.clone())),
				_ => None,
			},
			_ => None,
		}
	}

	pub(super) fn matches(
		&self,
		mailbox: &str,
		message: &crate::imap::mailbox::MessageRef,
		content: Option<&Content>,
	) -> bool {
		self.root.matches(mailbox, message, content)
	}
}

impl Parser {
	fn parse_object(
		&mut self,
		object: &serde_json::Map<String, serde_json::Value>,
		depth: usize,
	) -> Result<Node, InputError> {
		if depth > MAX_FILTER_DEPTH {
			return Err(InputError::invalid("filter operator nesting is too deep"));
		}
		self.add_node()?;
		if object.contains_key("operator") {
			self.parse_operator(object, depth)
		} else {
			let mut conditions = Vec::with_capacity(object.len());
			for (property, value) in object {
				self.add_node()?;
				conditions.push(self.parse_condition(property, value)?);
			}
			Ok(Node::All(conditions))
		}
	}

	fn parse_operator(
		&mut self,
		object: &serde_json::Map<String, serde_json::Value>,
		depth: usize,
	) -> Result<Node, InputError> {
		if object
			.keys()
			.any(|key| key != "operator" && key != "conditions")
		{
			return Err(InputError::invalid(
				"filter operator has unknown properties",
			));
		}
		let operator = object
			.get("operator")
			.and_then(serde_json::Value::as_str)
			.ok_or_else(|| InputError::invalid("filter operator must be a string"))?;
		let conditions = object
			.get("conditions")
			.and_then(serde_json::Value::as_array)
			.ok_or_else(|| InputError::invalid("filter operator conditions must be an array"))?;
		if conditions.len() > MAX_FILTER_NODES {
			return Err(InputError::invalid("filter has too many conditions"));
		}
		let mut children = Vec::with_capacity(conditions.len());
		for condition in conditions {
			let object = condition
				.as_object()
				.ok_or_else(|| InputError::invalid("filter condition must be an object"))?;
			children.push(self.parse_object(object, depth + 1)?);
		}
		match operator {
			"AND" => Ok(Node::And(children)),
			"OR" => Ok(Node::Or(children)),
			"NOT" => Ok(Node::And(
				children
					.into_iter()
					.map(|child| Node::Not(Box::new(child)))
					.collect(),
			)),
			_ => Err(InputError::invalid(
				"filter operator must be AND, OR or NOT",
			)),
		}
	}

	fn parse_condition(
		&mut self,
		property: &str,
		value: &serde_json::Value,
	) -> Result<Condition, InputError> {
		let condition = parse_condition(property, value)?;
		self.text_terms = self.text_terms.saturating_add(condition.text_term_count());
		if self.text_terms > MAX_TEXT_TERMS_TOTAL {
			return Err(InputError::invalid("filter has too many search terms"));
		}
		Ok(condition)
	}

	fn add_node(&mut self) -> Result<(), InputError> {
		self.nodes += 1;
		if self.nodes > MAX_FILTER_NODES {
			return Err(InputError::invalid("filter has too many conditions"));
		}
		Ok(())
	}
}

fn parse_condition(property: &str, value: &serde_json::Value) -> Result<Condition, InputError> {
	match property {
		"inMailbox" => {
			let mailbox = bounded_string(value, MAX_MAILBOX_BYTES, "inMailbox")?;
			if crate::util::path_component::MailboxName::new(&mailbox).is_err() {
				return Err(InputError::invalid("invalid inMailbox"));
			}
			let mailbox = if mailbox.eq_ignore_ascii_case("INBOX") {
				"INBOX".to_string()
			} else {
				mailbox
			};
			Ok(Condition::InMailbox(mailbox))
		}
		"text" => Ok(Condition::Text(parse_text(value, "text")?)),
		"from" => Ok(Condition::From(parse_text(value, "from")?)),
		"to" => Ok(Condition::To(parse_text(value, "to")?)),
		"subject" => Ok(Condition::Subject(parse_text(value, "subject")?)),
		"before" => Ok(Condition::Before(parse_date(value, "before")?)),
		"after" => Ok(Condition::After(parse_date(value, "after")?)),
		"hasKeyword" => {
			let keyword = bounded_string(value, MAX_KEYWORD_BYTES, "hasKeyword")?;
			Ok(Condition::HasKeyword(keyword))
		}
		"notKeyword" => {
			let keyword = bounded_string(value, MAX_KEYWORD_BYTES, "notKeyword")?;
			Ok(Condition::NotKeyword(keyword))
		}
		_ => Err(InputError::unsupported_filter()),
	}
}

fn parse_text(value: &serde_json::Value, property: &str) -> Result<TextQuery, InputError> {
	let text = value
		.as_str()
		.ok_or_else(|| InputError::invalid(format!("{property} must be a string")))?;
	if text.len() > MAX_FILTER_TEXT_BYTES {
		return Err(InputError::invalid(format!("{property} text is too long")));
	}
	TextQuery::parse(text).map_err(|_| InputError::invalid(format!("invalid {property} text")))
}

fn bounded_string(
	value: &serde_json::Value,
	maximum: usize,
	property: &str,
) -> Result<String, InputError> {
	let text = value
		.as_str()
		.ok_or_else(|| InputError::invalid(format!("{property} must be a string")))?;
	if text.is_empty() || text.len() > maximum || text.chars().any(char::is_control) {
		return Err(InputError::invalid(format!("invalid {property}")));
	}
	Ok(text.to_string())
}

fn parse_date(value: &serde_json::Value, property: &str) -> Result<u64, InputError> {
	let text = value
		.as_str()
		.ok_or_else(|| InputError::invalid(format!("{property} must be a UTCDate")))?;
	crate::storage::vacation_store::utc_date_to_unix_secs(Some(text))
		.ok_or_else(|| InputError::invalid(format!("{property} must be a UTCDate")))
}

impl Node {
	fn needs_content(&self) -> bool {
		match self {
			Node::All(conditions) => conditions.iter().any(Condition::needs_content),
			Node::And(children) | Node::Or(children) => children.iter().any(Node::needs_content),
			Node::Not(child) => child.needs_content(),
		}
	}

	fn mailbox_scope(&self) -> Option<String> {
		match self {
			Node::All(conditions) => {
				let mut scopes = conditions.iter().filter_map(|condition| match condition {
					Condition::InMailbox(mailbox) => Some(mailbox),
					_ => None,
				});
				let scope = scopes.next()?.clone();
				if scopes.next().is_some() {
					None
				} else {
					Some(scope)
				}
			}
			Node::And(children) => {
				let mut scope = None;
				for child in children {
					let Some(child_scope) = child.mailbox_scope() else {
						continue;
					};
					if let Some(expected) = &scope
						&& expected != &child_scope
					{
						return None;
					}
					scope = Some(child_scope);
				}
				scope
			}
			Node::Or(_) | Node::Not(_) => None,
		}
	}

	fn matches(
		&self,
		mailbox: &str,
		message: &crate::imap::mailbox::MessageRef,
		content: Option<&Content>,
	) -> bool {
		match self {
			Node::All(conditions) => conditions
				.iter()
				.all(|condition| condition.matches(mailbox, message, content)),
			Node::And(children) => children
				.iter()
				.all(|child| child.matches(mailbox, message, content)),
			Node::Or(children) => children
				.iter()
				.any(|child| child.matches(mailbox, message, content)),
			Node::Not(child) => !child.matches(mailbox, message, content),
		}
	}
}

impl Condition {
	fn text_term_count(&self) -> usize {
		match self {
			Condition::Text(query)
			| Condition::From(query)
			| Condition::To(query)
			| Condition::Subject(query) => query.term_count(),
			_ => 0,
		}
	}

	fn needs_content(&self) -> bool {
		matches!(
			self,
			Condition::Text(_) | Condition::From(_) | Condition::To(_) | Condition::Subject(_)
		)
	}

	fn matches(
		&self,
		mailbox: &str,
		message: &crate::imap::mailbox::MessageRef,
		content: Option<&Content>,
	) -> bool {
		match self {
			Condition::InMailbox(expected) => mailbox == expected,
			Condition::Text(query) => content.is_some_and(|content| query.matches(content.all())),
			Condition::From(query) => content.is_some_and(|content| query.matches(content.from())),
			Condition::To(query) => content.is_some_and(|content| query.matches(content.to())),
			Condition::Subject(query) => {
				content.is_some_and(|content| query.matches(content.subject()))
			}
			Condition::Before(bound) => received_seconds(message) < *bound,
			Condition::After(bound) => received_seconds(message) >= *bound,
			Condition::HasKeyword(keyword) => has_keyword(message, keyword),
			Condition::NotKeyword(keyword) => !has_keyword(message, keyword),
		}
	}
}

fn received_seconds(message: &crate::imap::mailbox::MessageRef) -> u64 {
	message
		.internal_date
		.duration_since(std::time::UNIX_EPOCH)
		.map(|duration| duration.as_secs())
		.unwrap_or(0)
}

fn has_keyword(message: &crate::imap::mailbox::MessageRef, expected: &str) -> bool {
	use crate::imap::mailbox::Flag;
	message.flags.iter().any(|flag| {
		let keyword = match flag {
			Flag::Seen => Some("$seen"),
			Flag::Answered => Some("$answered"),
			Flag::Flagged => Some("$flagged"),
			Flag::Draft => Some("$draft"),
			Flag::Deleted => None,
			Flag::Keyword(keyword) => Some(keyword.as_str()),
		};
		keyword.is_some_and(|keyword| keyword.eq_ignore_ascii_case(expected))
	})
}
