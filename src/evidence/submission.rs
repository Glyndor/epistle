//! What every submission path (SMTP after AUTH, `POST /api/v1/send`, JMAP
//! `EmailSubmission/set`) does with the class before the message is handed
//! on: decide it, strip the client's header, and apply the marketing rules.

use std::path::Path;

use super::MailClass;
use super::class::{ClassSources, resolve};
use super::marketing::{self, MarketingRefusal};
use crate::smtp::session::AcceptedMessage;

/// A submission ready to hand on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
	/// The class granted.
	pub class: MailClass,
	/// Recipients dropped because they are on a suppression list (marketing
	/// only), in the order they were given.
	pub suppressed: Vec<String>,
}

/// Decide the class of `message` from `sources`, remove the client's class
/// header, and for `marketing` refuse a message without a one-click
/// unsubscribe, mark it `Precedence: bulk`, and drop the recipients on the
/// global suppression list or on the sender's under `data_dir`.
pub fn prepare(
	message: &mut AcceptedMessage,
	sources: ClassSources,
	data_dir: Option<&Path>,
) -> Result<Prepared, MarketingRefusal> {
	let class = resolve(sources, &mut message.data);
	let mut suppressed = Vec::new();
	if class == MailClass::Marketing {
		marketing::check(&message.data)?;
		marketing::mark_bulk(&mut message.data);
		if let Some(list) = data_dir.and_then(|dir| crate::queue::SuppressionList::open(dir).ok()) {
			let sender = message.reverse_path.clone();
			message.recipients.retain(|recipient| {
				let blocked =
					list.is_suppressed(recipient) || list.is_suppressed_for(&sender, recipient);
				if blocked {
					suppressed.push(recipient.clone());
				}
				!blocked
			});
		}
	}
	Ok(Prepared { class, suppressed })
}

#[cfg(test)]
#[path = "submission_tests.rs"]
mod tests;
