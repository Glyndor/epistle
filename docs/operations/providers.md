# Sender panels

Google and Microsoft carry most of the traffic of a mail server, and each
provider has a portal where the sender watches what the provider thinks of
the sending addresses. Enrolling in one is a step in the provider's own
page. This page says what each step is, what the portal shows, and the
limits the provider asks the sender to stay inside.

`epistle check deliverability` names the panels that are not enrolled yet.
It only warns: the list in `[deliverability] enrolled` changes no behaviour
of the server.

## Google

**Portal:** Postmaster Tools, <https://support.google.com/mail/answer/9981691>

**Enrolment**

1. Add the domain to Postmaster Tools with a Google account.
2. Publish the record Google asks for: a TXT or a CNAME at the DKIM
   domain (`d=`) or at the Return-Path domain.

The TXT record is a value Google issues, so epistle cannot invent it. Put
it in the configuration and epistle publishes it with the rest:

```toml
[dns_publish]
extra_txt = [{ name = "example.org", value = "google-site-verification=..." }]
```

`epistle dns-records` prints it, `epistle dns publish` writes it, and it
stays published while it is in the list.

**What it shows:** the spam rate of the domain, the share of the mail its
recipients report as spam.

**Limits**

| Limit | Value |
|---|---|
| Spam rate | below 0.1 %; 0.3 % is the limit of eligibility |
| Authentication | SPF or DKIM for every sender; above 5,000 messages a day both, plus DMARC (`p=none` is enough) |
| Reverse DNS | a valid PTR whose forward and reverse match, for IPv4 and IPv6 |
| Transport | TLS |
| Marketing mail | `List-Unsubscribe` and `List-Unsubscribe-Post: List-Unsubscribe=One-Click`, plus a visible link in the body |
| DKIM key | 1024 bits at least, 2048 recommended |

The replies the guidelines cite: `421 4.7.0` (the IP is not allowed),
`4.7.28` (the quota or the rate: pause at least 10 minutes and send again
from a connection), `5.7.26` (not authenticated) and `550 5.7.1` (the IP is
suspended; the page cites the IPv6 PTR and authentication rules there too).
Since November 2025 a domain that does not meet the rules gets more
temporary and permanent rejections, and a new domain follows a shorter
schedule.

The requirements are in the [email sender guidelines]
(<https://support.google.com/a/answer/81126>) and in their
[FAQ](<https://support.google.com/a/answer/14229414>).

## Microsoft

**Portals:** SNDS,
<https://substrate.office.com/ip-domain-management-snds/snds>, and the
[IP unblock portal](https://sender.office.com/).

**Enrolment**

1. Sign in to SNDS with a Microsoft account.
2. Ask for access to the sending IP addresses and authorize them. The
   access does not expire any more.
3. When an address is blocked, run the three steps of the unblock portal.

**What it shows:** the complaints. JMRP, inside SNDS, sends the reports
when a recipient marks the message as junk.

**Limits**

| Limit | Value |
|---|---|
| Authentication | above 5,000 messages a day to `outlook.com`, `hotmail.com` or `live.com`: SPF passes, DKIM passes, and DMARC is published with at least `p=none` and aligned (with SPF, with DKIM, or with both) |
| SPF | an SPF record with more than 10 DNS lookups fails |
| Sender | a valid `From` or `Reply-To` that can receive replies |
| Addresses | the invalid ones removed |
| Forwards and lists | ARC |
| DMARC reports | Outlook sends the aggregate reports (`rua`) and does not send `ruf` |

Mail that does not meet the requirements has gone to the Junk folder since
5 May 2025. The rejection that follows is `550 5.7.515 Access denied,
sending domain ... does not meet the required authentication level`; the
date the rejection starts is still to be announced.

The requirements are in the [high-volume sender post]
(<https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/strengthening-email-ecosystem-outlooks-new-requirements-for-high-volume-senders/4399730>),
published on 2 April 2025 and updated on 30 April 2025.

## Yahoo and AOL

**Portal:** Complaint Feedback Loop,
<https://senders.yahooinc.com/complaint-feedback-loop/>

**Enrolment**

1. Create the sender profile.
2. Add the domain and verify it; the verification is tied to the DKIM key.
3. Subscribe the domain: the ARF reports arrive at the subscribed mailbox.

Only mail signed with DKIM can use the loop.

**What it shows:** the complaints of the enrolled domains, as ARF reports in
the subscribed mailbox.

**Limits**

| Limit | Value |
|---|---|
| Authentication | SPF or DKIM; for bulk mail both, plus DMARC (at least `p=none`) with alignment, and `rua` is highly recommended |
| Complaints | below 0.3 % |
| DNS | forward and reverse records valid |
| Message format | RFC 5321 and RFC 5322 |
| Unsubscribe | `List-Unsubscribe` with one-click (RFC 8058; the POST is strongly recommended, `mailto` is accepted), a visible link in the body, and the unsubscribe processed within 2 days |

Recommended:

| Limit | Value |
|---|---|
| Forwards | ARC |
| DKIM key | 1024 bits or more |
| Traffic | bulk and transactional mail on separate IP addresses and different DKIM domains |
| Reverse DNS | a PTR that is meaningful, not a generic name |
| Volume | raised gradually |

The replies the sender portal lists: `421 4.7.0` and `TSS04` mean retry
later, `553` and `554` mean do not retry. A `553` or a `554` does not only
mean an invalid address: the page lists DMARC and DKIM failures, the
content and Spamhaus among its causes.

The requirements are in the [sender best practices]
(<https://senders.yahooinc.com/best-practices/>); the replies are in the
[SMTP error codes](<https://senders.yahooinc.com/smtp-error-codes/>).
Support writes to `mail-questions@yahooinc.com`.

## Apple

**Portal:** no feedback loop and no allowlist for bulk senders. Apple
weighs the reputation of the IP and the domain, the content and the
feedback of the users. The contact is an email to `icloudadmin@apple.com`
with the company, the domain, the IP, the SMTP errors and a description
that says when the sending started.

The page: <https://support.apple.com/en-us/102322>, published on 25
February 2025.

**What it shows:** nothing to read. There is no portal to open.

**Limits**

Hard, and all of them for bulk mail, or the mail is rejected:

| Limit | Value |
|---|---|
| Authentication | SPF and DKIM, and DMARC published |
| Reverse DNS | an rDNS that matches the domain |
| Forwards | ARC |
| Message format | RFC 5321 and RFC 5322 |
| Consent | opt-in only, and a working unsubscribe link |

Recommended:

| Limit | Value |
|---|---|
| Consistency | the same IP addresses and domains, bulk and transactional in separate streams, and a fixed `From` |
| Errors | the temporary and the permanent SMTP errors followed, the bounce policy applied, and a suppressed address never reactivated |
| List | the inactive addresses removed |

## GMX

**Portal:** <https://postmaster.gmx.com/en/requirements-and-recommendations>,
with the postmaster contact form of the page.

**Enrolment:** write to the postmaster form of the portal.

**What it shows:** the requirements the provider publishes, and the form to
reach it. The page gives no numbers: mass mailings may be throttled even
with a warm-up.

**Limits**

Hard:

| Limit | Value |
|---|---|
| DKIM | required, aligned at least in relaxed mode |
| Reverse DNS | a PTR to an FQDN of your own; the generic names of the provider are usually rejected |
| IP | a static address |
| Greeting | EHLO with a valid FQDN, the name of the PTR |
| Domain | a valid MX or A record |
| Headers | `Date`, `From` and `Message-ID` present; `BCC`, `CC`, `Date`, `From`, `Sender`, `Subject` and `To` at most once |
| Blocklists | the IP and the domain out of the DNS blocklists; the page suggests Spamhaus |
| Unsubscribe | `List-Unsubscribe` on every bulk mail; RFC 8058 is the ideal |
| Consent | opt-in, double opt-in ideal, and a sender that can be identified |
| Unknown addresses | many messages to unknown addresses bring a temporary block |

Recommended: SPF, DMARC and the Certified Senders Alliance (CSA).

## Not covered here

Other providers are not covered (Fastmail, Proton, Mail.ru, Yandex, Orange,
QQ, 163). This page is not the list of every provider.

## The list in the configuration

```toml
[deliverability]
enrolled = ["postmaster", "snds"]
```

Every panel the list does not name is reported by `epistle check
deliverability`, one warning each:

| Name | Panel |
|---|---|
| `postmaster` | Google Postmaster Tools |
| `snds` | Microsoft SNDS |
| `jmrp` | Microsoft JMRP |
| `yahoo-cfl` | Yahoo Complaint Feedback Loop |
| `apple` | the Apple iCloud Mail postmaster contact |

A name the list does not know is a configuration error, and the error names
the panels that exist. The list is empty by default, so every panel is
reported until the operator marks the ones that are done. The warning
never blocks: it does not change the exit code of `epistle check` and no
behaviour of the server depends on it.
