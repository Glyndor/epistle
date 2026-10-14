use super::*;

#[test]
fn domains_become_lowercase_ascii() {
	assert_eq!(domain("Example.COM"), Some("example.com".to_string()));
	assert_eq!(
		domain("bücher.example"),
		Some("xn--bcher-kva.example".to_string())
	);
	assert_eq!(domain("not a domain"), None);
	assert_eq!(domain("${expr}"), None);
}

#[test]
fn addresses_keep_both_parts() {
	assert_eq!(
		address("Info@Bücher.example"),
		Some("info@xn--bcher-kva.example".to_string())
	);
	assert_eq!(address("@example.com"), None);
	assert_eq!(address("no-at-sign"), None);
	assert_eq!(address("a b@example.com"), None);
}

#[test]
fn a_key_never_prints_its_material() {
	let key = Key {
		domain: "example.com".into(),
		selector: "s1".into(),
		algorithm: Algorithm::Ed25519,
		pkcs8: Zeroizing::new(vec![0xAB; 48]),
	};
	let shown = format!("{key:?} {}", serde_json::to_string(&key).expect("json"));
	assert!(!shown.contains("171"), "{shown}");
	assert!(!shown.to_lowercase().contains("abab"), "{shown}");
	assert!(!shown.contains("pkcs8"), "{shown}");
}
