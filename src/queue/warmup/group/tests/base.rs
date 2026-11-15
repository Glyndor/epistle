use super::*;

#[test]
fn provider_exchangers_are_grouped_by_their_host() {
	let cases = [
		("gmail-smtp-in.l.google.com", Group::Gmail),
		("alt1.aspmx.l.google.com.", Group::Gmail),
		("ASPMX.L.GOOGLE.COM", Group::Gmail),
		("smtp.google.com", Group::Gmail),
		("aspmx2.googlemail.com", Group::Gmail),
		("hotmail-com.olc.protection.outlook.com", Group::Outlook),
		("contoso-com.mail.protection.outlook.com", Group::Outlook),
		("contoso-com.r-v1.mx.microsoft", Group::Outlook),
		("mta5.am0.yahoodns.net", Group::Yahoo),
		("mx-aol.mail.gm0.yahoodns.net", Group::Yahoo),
		("mx01.mail.icloud.com", Group::Icloud),
		("mx.example.net", Group::Other),
		("[192.0.2.1]", Group::Other),
		("", Group::Other),
	];
	let got: Vec<(&str, Group)> = cases
		.iter()
		.map(|(host, _)| (*host, Group::of_exchanger(host)))
		.collect();
	assert_eq!(got, cases.to_vec());
}

#[test]
fn a_provider_name_inside_another_domain_is_not_the_provider() {
	let cases = [
		"gmail-smtp-in.l.google.com.evil.example",
		"evilgoogle.com",
		"google.com.evil.example",
		"notoutlook.com",
		"outlook.com-mx.example",
		"mx.microsoft.evil.example",
		"yahoodns.net.example",
		"fakeicloud.com",
	];
	let got: Vec<Group> = cases.iter().map(|host| Group::of_exchanger(host)).collect();
	assert_eq!(got, vec![Group::Other; cases.len()]);
}

#[test]
fn a_unicode_lookalike_is_compared_after_idna() {
	// A Cyrillic "о" in "gооgle" is a different name once in A-labels.
	assert_eq!(
		Group::of_exchanger("mx.g\u{43e}\u{43e}gle.com"),
		Group::Other
	);
}

#[test]
fn labels_round_trip_and_unknown_names_are_refused() {
	for group in Group::ALL {
		assert_eq!(Group::parse(group.label()), Some(group));
	}
	assert_eq!(Group::parse("Gmail"), None);
	assert_eq!(Group::parse("hotmail"), None);
	assert_eq!(Group::parse(""), None);
}

#[test]
fn the_new_groups_are_read_from_their_mx_names() {
	let cases = [
		("mx00.emig.gmx.net", Group::Gmx),
		("mx01.gmx.net.", Group::Gmx),
		("mx-ha02.web.de", Group::Gmx),
		("mx00.mail.com", Group::Gmx),
		("MXS.MAIL.RU", Group::Mailru),
		("mxs.mail.ru", Group::Mailru),
		("evilgmx.net", Group::Other),
		("gmx.net.evil.example", Group::Other),
		("web.de.evil.example", Group::Other),
		("notmail.com", Group::Other),
		("mx.gmail.ru", Group::Other),
		("mail.ru.evil.example", Group::Other),
	];
	let got: Vec<(&str, Group)> = cases
		.iter()
		.map(|(host, _)| (*host, Group::of_exchanger(host)))
		.collect();
	assert_eq!(got, cases.to_vec());
}

#[test]
fn the_new_groups_have_their_own_labels() {
	assert_eq!(Group::Gmx.label(), "gmx");
	assert_eq!(Group::Mailru.label(), "mailru");
	assert_eq!(Group::parse("gmx"), Some(Group::Gmx));
	assert_eq!(Group::parse("mailru"), Some(Group::Mailru));
	assert_eq!(Group::parse("mail.ru"), None);
}

#[test]
fn the_new_groups_are_providers() {
	assert!(Group::Gmx.is_provider());
	assert!(Group::Mailru.is_provider());
	assert!(!Group::Other.is_provider());
}

#[test]
fn every_group_is_listed() {
	let labels: Vec<&str> = Group::ALL.iter().map(|group| group.label()).collect();
	assert_eq!(
		labels,
		[
			"gmail", "outlook", "yahoo", "icloud", "gmx", "mailru", "other"
		]
	);
	for group in Group::ALL {
		assert_eq!(Group::parse(group.label()), Some(group));
	}
}
