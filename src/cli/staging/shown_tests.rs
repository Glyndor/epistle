use super::*;

#[test]
fn staged_paths_read_as_the_operators() {
	let encoded = encode(&[
		("/h/.s/0/config".into(), "/etc/mox".into()),
		("/h/.s/0/config/mox.conf".into(), "/etc/mox/mox.conf".into()),
		("/h/.s/1/pw".into(), "/root/pw".into()),
	]);
	let pairs = decode(&encoded);
	assert_eq!(
		replace(
			&pairs,
			"Mox configuration in /h/.s/0/config; passwords are in /h/.s/1/pw"
		),
		"Mox configuration in /etc/mox; passwords are in /root/pw"
	);
	assert_eq!(
		replace(&pairs, "reading /h/.s/0/config/mox.conf: denied"),
		"reading /etc/mox/mox.conf: denied"
	);
	assert_eq!(replace(&[], "unchanged"), "unchanged");
}
