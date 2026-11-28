//! The rules for making a key: what is refused to anyone, and what a key may
//! not give the key it makes.

use super::*;

mod lock;
use crate::api::api_keys::{ApiKey, Scope};

const NOW: u64 = 1_800_000_000;

/// What `key` and `read` give a key: both halves of reading.
const READER: &[Scope] = &[Scope::Key, Scope::ManageRead, Scope::MailRead];

struct Server;

impl World for Server {
	fn account_known(&self, name: &str) -> bool {
		matches!(name, "ann" | "bob" | "nowhere")
	}
	fn account_addresses(&self, name: &str) -> Vec<String> {
		match name {
			"ann" => vec!["ann@a.example".to_string()],
			"bob" => vec!["bob@a.example".to_string(), "bob@b.example".to_string()],
			_ => Vec::new(),
		}
	}
	fn hosts(&self, domain: &str) -> bool {
		matches!(domain, "a.example" | "b.example" | "c.example")
			|| (domain.starts_with('d') && domain.ends_with(".example"))
	}
}

fn request(scopes: &[&str]) -> Request {
	Request {
		label: "ci".to_string(),
		scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
		..Request::default()
	}
}

fn caller(scopes: Option<&[Scope]>, domains: Option<&[&str]>) -> Caller {
	Caller::new(
		Reach {
			scopes: scopes.map(<[Scope]>::to_vec),
			domains: domains.map(|d| d.iter().map(|d| (*d).to_string()).collect()),
			..Reach::default()
		},
		"maker".to_string(),
		"sha256:00".to_string(),
		None,
	)
}

fn refused(request: &Request, by: Option<&Caller>) -> Refusal {
	check(request, by, &Server).expect_err("refused")
}

#[test]
fn what_is_refused_to_everyone() {
	let mut bad = request(&["read"]);
	bad.label = " ".to_string();
	assert!(matches!(refused(&bad, None), Refusal::Invalid(_)));
	assert!(matches!(refused(&request(&[]), None), Refusal::Invalid(_)));
	assert!(matches!(
		refused(&request(&["reed"]), None),
		Refusal::Invalid(_)
	));
	let mut cidr = request(&["read"]);
	cidr.ip_cidr = Some("not-a-network".to_string());
	assert!(matches!(refused(&cidr, None), Refusal::Invalid(_)));
	let mut many = request(&["read"]);
	many.domains = (0..=MAX_DOMAINS).map(|n| format!("d{n}.example")).collect();
	many.max_domains = Some(MAX_DOMAINS);
	assert!(matches!(refused(&many, None), Refusal::Invalid(_)));
	let mut ghost = request(&["read"]);
	ghost.account = Some("nobody".to_string());
	assert!(matches!(refused(&ghost, None), Refusal::Invalid(_)));
}

#[test]
fn administrative_scopes_are_not_for_an_account_or_for_a_domain() {
	for scope in ["scim", "alias", "ban", "health", "key"] {
		let mut bound = request(&["read", scope]);
		bound.account = Some("ann".to_string());
		assert!(
			matches!(refused(&bound, None), Refusal::Policy(_)),
			"{scope} for an account"
		);
	}
	for scope in ["ban", "health"] {
		let mut confined = request(&[scope]);
		confined.domains = vec!["a.example".to_string()];
		assert!(
			matches!(refused(&confined, None), Refusal::Policy(_)),
			"{scope} for a domain"
		);
	}
	let mut fine = request(&["read", "key", "scim"]);
	fine.domains = vec!["a.example".to_string()];
	assert!(check(&fine, None, &Server).is_ok());
}

#[test]
fn the_operator_may_make_any_key_the_rules_allow() {
	let mut all = request(&[
		"read", "write", "send", "scim", "alias", "ban", "health", "key",
	]);
	all.expires_at = None;
	assert!(check(&all, None, &Server).is_ok());
	// Whoever asks, a domain the server does not host is refused; the command's
	// own `World` says every domain is hosted.
	let mut elsewhere = request(&["read"]);
	elsewhere.domains = vec!["not-hosted.example".to_string()];
	assert!(matches!(
		check(&elsewhere, None, &Server),
		Err(Refusal::Invalid(_))
	));
}

/// The cap of domains belongs to whoever asks: the API sets one and the
/// command does not.
#[test]
fn the_cap_of_domains_is_the_callers() {
	let mut many = request(&["read"]);
	many.domains = (0..=MAX_DOMAINS).map(|n| format!("d{n}.example")).collect();
	// The command asks for no cap, so the count of its domains is not a
	// reason to refuse the request.
	assert!(check(&many, None, &Server).is_ok());
	// The API asks for one.
	many.max_domains = Some(MAX_DOMAINS);
	let refusal = refused(&many, None);
	assert!(
		matches!(&refusal, Refusal::Invalid(text) if text.contains("at most")),
		"{refusal:?}"
	);
}

/// A key makes only a key that reaches no further than itself.
#[test]
fn a_key_cannot_make_a_key_with_more_than_it_has() {
	let maker = caller(Some(READER), None);
	assert!(check(&request(&["read"]), Some(&maker), &Server).is_ok());
	assert!(check(&request(&["key", "read"]), Some(&maker), &Server).is_ok());
	for scope in ["write", "send", "scim", "alias", "ban", "health"] {
		assert!(
			matches!(
				refused(&request(&["read", scope]), Some(&maker)),
				Refusal::Escalation(_)
			),
			"{scope}"
		);
	}
	// A key made before scopes existed holds every one of them.
	let legacy = caller(None, None);
	assert!(check(&request(&["ban", "write"]), Some(&legacy), &Server).is_ok());
}

#[test]
fn a_confined_key_makes_keys_inside_its_domains_only() {
	let maker = caller(Some(READER), Some(&["a.example"]));
	let mut inside = request(&["read"]);
	inside.domains = vec!["A.example".to_string()];
	assert!(check(&inside, Some(&maker), &Server).is_ok());
	let mut every = request(&["read"]);
	assert!(
		matches!(refused(&every, Some(&maker)), Refusal::Escalation(_)),
		"no domain is every domain"
	);
	every.domains = vec!["a.example".to_string(), "b.example".to_string()];
	assert!(matches!(
		refused(&every, Some(&maker)),
		Refusal::Escalation(_)
	));
	let mut unhosted = request(&["read"]);
	unhosted.domains = vec!["nowhere.example".to_string()];
	assert!(matches!(
		refused(&unhosted, Some(&maker)),
		Refusal::Invalid(_)
	));
	// An account bound key: the account has to be inside the domains.
	let mut ann = request(&["read"]);
	ann.account = Some("ann".to_string());
	assert!(check(&ann, Some(&maker), &Server).is_ok());
	let mut bob = request(&["read"]);
	bob.account = Some("bob".to_string());
	assert!(
		matches!(refused(&bob, Some(&maker)), Refusal::Escalation(_)),
		"bob has an address in b.example"
	);
}

#[test]
fn the_network_and_the_expiry_of_a_key_bound_the_keys_it_makes() {
	let maker = Caller::new(
		Reach {
			scopes: Some(READER.to_vec()),
			ip_cidr: Cidr::parse("10.0.0.0/16"),
			expires_at: Some(NOW + 1000),
			..Reach::default()
		},
		"maker".to_string(),
		"sha256:00".to_string(),
		None,
	);
	let mut ok = request(&["read"]);
	ok.ip_cidr = Some("10.0.4.0/24".to_string());
	ok.expires_at = Some(NOW + 500);
	assert!(check(&ok, Some(&maker), &Server).is_ok());
	let mut anywhere = ok.clone();
	anywhere.ip_cidr = None;
	assert!(matches!(
		refused(&anywhere, Some(&maker)),
		Refusal::Escalation(_)
	));
	let mut wider = ok.clone();
	wider.ip_cidr = Some("10.0.0.0/8".to_string());
	assert!(matches!(
		refused(&wider, Some(&maker)),
		Refusal::Escalation(_)
	));
	let mut elsewhere = ok.clone();
	elsewhere.ip_cidr = Some("192.0.2.0/24".to_string());
	assert!(matches!(
		refused(&elsewhere, Some(&maker)),
		Refusal::Escalation(_)
	));
	let mut family = ok.clone();
	family.ip_cidr = Some("2001:db8::/32".to_string());
	assert!(matches!(
		refused(&family, Some(&maker)),
		Refusal::Escalation(_)
	));
	let mut never = ok.clone();
	never.expires_at = None;
	assert!(matches!(
		refused(&never, Some(&maker)),
		Refusal::Escalation(_)
	));
	let mut later = ok.clone();
	later.expires_at = Some(NOW + 2000);
	assert!(matches!(
		refused(&later, Some(&maker)),
		Refusal::Escalation(_)
	));
}

#[test]
fn a_reach_from_a_key_never_reads_wider_than_the_file_says() {
	let key = ApiKey {
		label: "k".to_string(),
		hash: "sha256:00".to_string(),
		expires_at: Some(5),
		ip_cidr: Some("10.0.0.0/8".to_string()),
		scopes: vec!["read".to_string(), "from-the-future".to_string()],
		grants: Vec::new(),
		domains: vec!["A.Example".to_string()],
		account: None,
		auto_submitted: false,
	};
	let reach = Reach::of_key(&key, None);
	// A name this build cannot read is a scope the key does not hold, so the
	// whole key holds nothing.
	assert_eq!(reach.scopes, Some(Vec::new()));
	assert_eq!(reach.domains, Some(vec!["a.example".to_string()]));
	assert_eq!(reach.expires_at, Some(5));
}

/// `read` is both halves of reading, or the mail half for a key bound to one
/// account, and what a maker may give is counted on those scopes.
#[test]
fn read_means_both_halves_or_the_mail_half_for_an_account() {
	let management = caller(Some(&[Scope::Key, Scope::ManageRead]), None);
	assert!(check(&request(&["manage:read"]), Some(&management), &Server).is_ok());
	for scope in ["read", "mail:read"] {
		assert!(
			matches!(
				refused(&request(&[scope]), Some(&management)),
				Refusal::Escalation(_)
			),
			"{scope} holds mail, which the maker does not"
		);
	}
	let mail = caller(Some(&[Scope::Key, Scope::MailRead]), None);
	assert!(matches!(
		refused(&request(&["read"]), Some(&mail)),
		Refusal::Escalation(_)
	));
	let mut bound = request(&["read"]);
	bound.account = Some("ann".to_string());
	assert!(check(&bound, Some(&mail), &Server).is_ok());
	let mut bound_management = request(&["manage:read"]);
	bound_management.account = Some("ann".to_string());
	assert!(matches!(
		refused(&bound_management, None),
		Refusal::Policy(_)
	));
}

/// An account whose addresses are not known cannot be placed inside any domain,
/// so a key confined to domains does not make a key for it, nor reach one.
#[test]
fn an_account_with_no_addresses_is_outside_every_domain() {
	let confined = caller(Some(READER), Some(&["a.example"]));
	let mut unplaced = request(&["read"]);
	unplaced.account = Some("nowhere".to_string());
	assert!(matches!(
		refused(&unplaced, Some(&confined)),
		Refusal::Escalation(_)
	));
	let unconfined = caller(Some(READER), None);
	assert!(check(&unplaced, Some(&unconfined), &Server).is_ok());
	assert!(check(&unplaced, None, &Server).is_ok());
}
