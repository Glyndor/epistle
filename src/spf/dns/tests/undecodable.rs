//! A name that cannot be put on the wire is an absence, not a failure.
//!
//! The HELO name of a client is text the client chose, and the SPF check of
//! a null reverse-path looks it up as it came. RFC 7208 section 4.3 says a
//! domain that is not a well-formed name is evaluated as `none`. A name that
//! cannot be encoded never reaches a server, so a retry cannot change the
//! answer: reporting it as a temporary failure made every bounce from such a
//! host wait for a retry that never ends.

use hickory_resolver::proto::op::Message;

use super::server::{self, Reply};
use super::{DnsFailure, DnsLookup};

fn nothing(_: &Message) -> Reply {
	Reply::Answers(Vec::new())
}

#[tokio::test]
async fn a_name_with_an_underscore_in_a_label_is_looked_up_like_any_other() {
	let port = server::spawn(nothing).await;
	let dns = server::resolver(port);
	assert_eq!(dns.txt("host_name.example.com").await, Ok(Vec::new()));
}

#[tokio::test]
async fn a_label_longer_than_the_wire_allows_is_an_absence_and_not_a_failure() {
	let port = server::spawn(nothing).await;
	let dns = server::resolver(port);
	let label = "a".repeat(64);
	assert_eq!(
		dns.txt(&format!("{label}.example.com")).await,
		Ok(Vec::new())
	);
}

#[tokio::test]
async fn a_resolver_that_fails_is_still_a_temporary_failure() {
	let port = server::spawn(|_| Reply::Failed).await;
	let dns = server::resolver(port);
	assert_eq!(
		dns.txt("mail.example.com").await,
		Err(DnsFailure::Temporary)
	);
}
