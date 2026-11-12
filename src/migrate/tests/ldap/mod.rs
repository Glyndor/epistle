//! A self-referring directory must fail closed, without chasing its URL.
mod limits;
mod peer;
mod raw;

use super::DEADLINE;
use crate::directory_store::load_ldap_accounts;
use ldap3::LdapError;
use std::sync::atomic::Ordering;

fn config(url: &str) -> crate::config::Ldap {
	toml::from_str(&format!(
		r#"
url = "{url}"
bind_dn = "cn=svc"
bind_password = "{}"
base_dn = "dc=example,dc=org"
user_filter = "(uid=%s)"
account_attribute = "uid"
mail_attribute = "mail"
tls = false
"#,
		crate::test_support::fixtures::password()
	))
	.expect("LDAP config")
}

fn load(url: &str) -> Result<Vec<crate::directory_store::LdapAccount>, LdapError> {
	load_ldap_accounts(&config(url))
}

#[tokio::test]
async fn referral_loop_is_an_error_without_a_second_connection() {
	for referral in [false, true] {
		let (url, connections, _peer) = peer::start(referral).await;
		let target = url.clone();
		let (tx, rx) = tokio::sync::oneshot::channel();
		// A detached OS thread lets the outer guard fail promptly even if
		// the synchronous loader hangs. A spawn_blocking task would make
		// Tokio runtime shutdown wait indefinitely on that same defect.
		let worker = std::thread::spawn(move || {
			let _ = tx.send(load(&target));
		});
		let result = tokio::time::timeout(DEADLINE, rx)
			.await
			.expect("LDAP loader exceeded deadline")
			.expect("loader panicked");
		worker.join().expect("loader did not panic");
		if referral {
			assert!(
				matches!(&result, Err(LdapError::LdapResult { result })
                if result.rc == 10 && result.refs == vec![url.clone()]),
				"{result:?}"
			);
		} else {
			assert_eq!(result.expect("successful empty search"), vec![]);
		}
		assert_eq!(
			connections.load(Ordering::SeqCst),
			1,
			"referral must not be followed"
		);
	}
}
