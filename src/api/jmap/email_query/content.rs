use mail_parser::MessageParser;

const MAX_TEXT_QUERY_BYTES: usize = 1_024;
const MAX_TEXT_TERMS: usize = 16;

pub(super) struct Content {
	from: String,
	to: String,
	subject: String,
	all: String,
}

impl Content {
	pub(super) fn from_raw(raw: &[u8]) -> Self {
		let from = normalized_header(raw, "from");
		let to = normalized_header(raw, "to");
		let cc = normalized_header(raw, "cc");
		let bcc = normalized_header(raw, "bcc");
		let subject = normalized_header(raw, "subject");
		let mut body = String::new();
		if let Some(message) = MessageParser::default().parse(raw) {
			for part in message.text_bodies() {
				body.push_str(&part);
				body.push('\n');
			}
		}
		let body = normalize_whitespace(&body).to_lowercase();
		let all = [
			from.as_str(),
			to.as_str(),
			cc.as_str(),
			bcc.as_str(),
			subject.as_str(),
			body.as_str(),
		]
		.join("\n");
		Self {
			from,
			to,
			subject,
			all,
		}
	}

	pub(super) fn from(&self) -> &str {
		&self.from
	}

	pub(super) fn to(&self) -> &str {
		&self.to
	}

	pub(super) fn subject(&self) -> &str {
		&self.subject
	}

	pub(super) fn all(&self) -> &str {
		&self.all
	}
}

fn normalized_header(raw: &[u8], name: &str) -> String {
	let values = header_values(raw, name);
	normalize_whitespace(&values.join(" ")).to_lowercase()
}

fn header_values(raw: &[u8], name: &str) -> Vec<String> {
	let (header, _) = crate::util::header_block::split_at_blank_line(raw);
	let text = String::from_utf8_lossy(header);
	let mut values: Vec<String> = Vec::new();
	let mut current: Option<usize> = None;
	for line in text.lines() {
		if line.is_empty() {
			break;
		}
		if line.starts_with([' ', '\t']) {
			if let Some(index) = current {
				values[index].push(' ');
				values[index].push_str(line.trim());
			}
			continue;
		}
		current = None;
		if let Some((key, value)) = line.split_once(':')
			&& key.trim().eq_ignore_ascii_case(name)
		{
			values.push(value.trim().to_string());
			current = Some(values.len() - 1);
		}
	}
	values
		.into_iter()
		.map(|value| crate::util::encoded_word::decode(&value))
		.collect()
}

fn normalize_whitespace(value: &str) -> String {
	let mut output = String::with_capacity(value.len());
	let mut separated = false;
	for word in value.split_whitespace() {
		if separated {
			output.push(' ');
		}
		output.push_str(word);
		separated = true;
	}
	output
}

#[derive(Clone)]
pub(super) struct TextQuery {
	terms: Vec<Term>,
}

#[derive(Clone)]
enum Term {
	Token(String),
	Phrase(String),
}

impl TextQuery {
	pub(super) fn parse(value: &str) -> Result<Self, ()> {
		if value.is_empty() || value.len() > MAX_TEXT_QUERY_BYTES {
			return Err(());
		}
		let mut terms = Vec::new();
		let mut current = String::new();
		let mut quote = None;
		let mut escaped = false;
		for character in value.chars() {
			if escaped {
				current.push(character);
				escaped = false;
				continue;
			}
			if character == '\\' {
				escaped = true;
				continue;
			}
			if matches!(character, '\'' | '"') {
				if quote == Some(character) {
					push_phrase(&mut terms, &current)?;
					current.clear();
					quote = None;
				} else if quote.is_none() && current.is_empty() {
					push_token(&mut terms, &current);
					quote = Some(character);
				} else {
					current.push(character);
				}
				continue;
			}
			if quote.is_none() && character.is_whitespace() {
				push_token(&mut terms, &current);
				current.clear();
				continue;
			}
			current.push(character);
		}
		if escaped || quote.is_some() {
			return Err(());
		}
		push_token(&mut terms, &current);
		if terms.is_empty() || terms.len() > MAX_TEXT_TERMS {
			return Err(());
		}
		Ok(Self { terms })
	}

	pub(super) fn term_count(&self) -> usize {
		self.terms.len()
	}

	pub(super) fn matches(&self, haystack: &str) -> bool {
		self.terms.iter().all(|term| match term {
			Term::Token(token) => haystack.contains(token),
			Term::Phrase(phrase) => haystack.contains(phrase),
		})
	}
}

fn push_token(terms: &mut Vec<Term>, value: &str) {
	if value.is_empty() {
		return;
	}
	terms.push(Term::Token(value.to_lowercase()));
}

fn push_phrase(terms: &mut Vec<Term>, value: &str) -> Result<(), ()> {
	let phrase = normalize_whitespace(value);
	if phrase.is_empty() {
		return Err(());
	}
	terms.push(Term::Phrase(phrase.to_lowercase()));
	Ok(())
}
