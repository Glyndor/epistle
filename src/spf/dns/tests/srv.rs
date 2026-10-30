//! The SRV lookup through [`SystemDns`] against an in-process resolver.
//!
//! Three answers have to stay apart: a name that publishes no SRV record
//! and a name that does not exist are both an absence, and a resolver that
//! fails to answer is not an absence. The first two leave the list empty
//! and the last one reports a temporary failure, so a caller can tell "not
//! published" from "not known yet".

use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::rdata::SRV;
use hickory_resolver::proto::rr::{Name, RData, Record};

use super::server::{self, Reply};
use super::{DnsFailure, DnsLookup, SrvRecord};

const SERVICE: &str = "_sieve._tcp.example.org";

/// The SRV record of the queried name, with the offer the test asks for.
fn offer(name: &Name, priority: u16, weight: u16, port: u16, target: &str) -> Record {
	let target = Name::from_ascii(target).expect("target name");
	Record::from_rdata(
		name.clone(),
		300,
		RData::SRV(SRV::new(priority, weight, port, target)),
	)
}

/// A reply that publishes the offers of the queried name. Every offer is
/// the target, the priority, the weight and the port of one record.
fn publishing(offers: &[(&str, u16, u16, u16)]) -> impl Fn(&Message) -> Reply {
	move |query: &Message| {
		let Some(question) = query.queries.first() else {
			return Reply::Answers(Vec::new());
		};
		Reply::Answers(
			offers
				.iter()
				.map(|(target, priority, weight, port)| {
					offer(question.name(), *priority, *weight, *port, target)
				})
				.collect(),
		)
	}
}

/// The lookup of the SRV records of the service name, with the time it is
/// given to answer.
async fn lookup(dns: &super::SystemDns) -> Result<Vec<SrvRecord>, DnsFailure> {
	tokio::time::timeout(Duration::from_secs(20), dns.srv(SERVICE))
		.await
		.expect("the lookup finishes")
}

#[tokio::test]
async fn the_srv_records_of_a_name_carry_the_priority_the_weight_the_port_and_the_target() {
	let port = server::spawn(publishing(&[
		("mail.example.org.", 0, 1, 4190),
		("Mail.Example.ORG.", 10, 5, 8443),
	]))
	.await;
	let dns = server::resolver(port);
	assert_eq!(
		lookup(&dns).await,
		Ok(vec![
			SrvRecord {
				priority: 0,
				weight: 1,
				port: 4190,
				target: "mail.example.org".to_string(),
			},
			SrvRecord {
				priority: 10,
				weight: 5,
				port: 8443,
				target: "mail.example.org".to_string(),
			},
		]),
		"the offers of the SRV records of a name, the second one read as the \
		 resolver spelled it"
	);
}

#[tokio::test]
async fn a_service_that_is_not_available_keeps_the_root_as_its_target() {
	// RFC 2782: a target of `.` says the service is decidedly not
	// available at that name. It is not the same as a target that names
	// no host, so it does not lose its meaning.
	let port = server::spawn(publishing(&[(".", 0, 0, 0)])).await;
	let dns = server::resolver(port);
	let found = lookup(&dns).await.expect("the SRV records of the name");
	assert_eq!(
		found[0].target, ".",
		"the target of an SRV record that says the service is not available"
	);
}

#[tokio::test]
async fn a_name_that_does_not_exist_has_no_srv_records() {
	let port = server::spawn(|_| Reply::NotFound).await;
	let dns = server::resolver(port);
	assert_eq!(
		lookup(&dns).await,
		Ok(Vec::new()),
		"the SRV records of a name that does not exist"
	);
}

#[tokio::test]
async fn a_resolver_that_fails_reports_a_temporary_failure() {
	let port = server::spawn(|_| Reply::Failed).await;
	let dns = server::resolver(port);
	assert_eq!(
		lookup(&dns).await,
		Err(DnsFailure::Temporary),
		"the SRV records of a name the resolver could not answer"
	);
}

/// A resolver that answers the queries the mail evaluation needs and knows
/// nothing about SRV.
struct NoSrv;

impl DnsLookup for NoSrv {
	fn txt(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[tokio::test]
async fn a_resolver_without_srv_support_reports_a_temporary_failure() {
	// An empty list would say "the service is not published", and this
	// resolver never looked.
	assert_eq!(
		NoSrv.srv(SERVICE).await,
		Err(DnsFailure::Temporary),
		"the SRV records of a name, asked of a resolver that cannot answer"
	);
}
