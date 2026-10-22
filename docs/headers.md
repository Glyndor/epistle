# Message headers

What epistle writes into a message, what it takes out, and what it leaves
alone, for each way a message enters or leaves the server. It describes the
code as it is today, not as it is meant to become. If you build on it, read
[Planned changes](#planned-changes) first: some of what this page says will
move.

The tests read this page. `tests/headers_documented.rs` fails when the source
writes or removes a header this page does not name, and
`tests/headers_system_mail.rs` builds each message of [System mail](#system-mail)
and fails when its header names differ from the table.
`dkim::sign::tests_headers::signed_header_table_matches_the_signer` ties the
DKIM table below to the signed names and their repetition counts in CI.

## Summary by path

| Path | Added by epistle | Removed or rewritten | Passed through unchanged |
|---|---|---|---|
| **SMTP submission** (587, 465, after AUTH) | `Received`; `Message-ID` and `Date` only when the client left them out; `DKIM-Signature` on the copy that leaves the server; `Precedence: bulk` for marketing mail; the [identification headers](#identification-headers) | `Bcc` and `Resent-Bcc`; `Epistle-Class`; any `Received` the client wrote (the server writes its own); `Authentication-Results`; every `X-Epistle-*`; any `Precedence` the client wrote, for marketing mail | Everything else, including a `Return-Path` or `Delivered-To` the client wrote |
| **REST API** (`POST /api/v1/send`) | `From`, `Subject`, `Date`, `Message-ID`, `MIME-Version`, `Content-Type` always; `To`, `Sender`, `Cc`, `Reply-To`, `In-Reply-To`, `References`, `Importance` with `X-Priority`, `List-Unsubscribe` with `List-Unsubscribe-Post`, `Auto-Submitted`, `Feedback-ID` and your `X-` headers when the request has the field; `Content-Transfer-Encoding`, `Content-Disposition`, `Content-ID` for bodies and attachments; `DKIM-Signature` on the copy that leaves the server; `Precedence: bulk` for marketing mail; the [identification headers](#identification-headers) | A custom `X-Epistle*` header, which is the one custom name a request may not send. No `Received` or `Authentication-Results` can be sent at all: a custom header has to be named `X-` | Nothing: the request names every header, and only the fields listed in the [API guide](api.md) turn into one |
| **JMAP** (`Email/set` then `EmailSubmission/set`) | The headers of the Email object (`From`, `Sender`, `To`, `Cc`, `Bcc`, `Reply-To`, `Subject`, `In-Reply-To`, `References`, `MIME-Version`, `Content-*`); `Message-ID` and `Date` when missing; `DKIM-Signature` on the copy that leaves the server; `Precedence: bulk` for marketing mail; the [identification headers](#identification-headers) | `Bcc` and `Resent-Bcc` at submission; `Epistle-Class`; any `Received` the draft carries; `Authentication-Results`; every `X-Epistle-*`; any `Precedence` the draft had, for marketing mail | Nothing the draft carries besides the above. Custom `header:` properties on `Email/set` create are ignored |
| **SMTP inbound** (25, then local delivery) | `Received`; `Received-SPF`, `Authentication-Results` and the ARC set when the sender is checked; `X-Spam-Status` and `X-Spam-Score` for a junk score; `X-Epistle-Attachment-Warning` when the attachment policy flags the message; `Return-Path` and `Delivered-To` on the stored copy; `List-Id`, `List-Post`, `List-Unsubscribe` for a list address | `Authentication-Results` with our authserv-id or an unparseable authserv-id; `Received-SPF`; `X-Spam-*`; `X-Epistle-*`; `Delivered-To`; `Return-Path`; `Epistle-Class`, before adding local fields; `TLS-Required` at delivery | Other `Authentication-Results` with a parseable foreign authserv-id, as untrusted information; `DKIM-Signature`; `ARC-*`; earlier `Received`; `Bcc`; other fields not listed as removed |
| **Forwarding** (account forward, Sieve `redirect`) | `Delivered-To` naming the forwarding address; the ARC set when an ARC key is configured | Nothing in the message; the envelope sender is rewritten with SRS when it is enabled | The original message, headers and body. No `Resent-*` and no `X-Forwarded-*` is added |
| **Lists** (an alias with a list id) | `List-Id`, `List-Post`, `List-Unsubscribe` on each delivered copy | Nothing | The original message |
| **Relay to the next MTA** (the queue worker) | Nothing | Nothing | The queued bytes, as signed at submission |
| **System mail** (bounces, replies, reports) | See [System mail](#system-mail) | Nothing | Not applicable |

**Never added, on any path:** `X-Mailer`, `X-Originating-IP`, `X-Original-To`,
`Resent-From`, `Resent-To`, `Resent-Date`, `Resent-Message-ID`, `X-Forwarded-To`,
`Disposition-Notification-To`, `Return-Receipt-To`. **Never leaves the server:**
`Bcc` and `Resent-Bcc`, from any submission path. **Not exposed:** the server
version appears in no header of a message epistle sends or stores. The one
place it shows is the `User-Agent` field of the abuse report that
`epistle report-abuse` prints.

## Every header

Each header epistle writes or removes, with when and what. Names are matched
without regard to case.

| Header | Where it comes from | Notes |
|---|---|---|
| `ARC-Authentication-Results`, `ARC-Message-Signature`, `ARC-Seal` | Inbound mail checked by SPF, and forwarded copies, when an ARC key is configured | One set per hop, written as `ARC-Seal`, `ARC-Message-Signature` and `ARC-Authentication-Results` right after `Authentication-Results`. `cv` is `none` for a message without a chain and carries the status of an inbound chain otherwise. A forward does not seal a message whose newest instance is already ours |
| `Action`, `Diagnostic-Code`, `Final-Recipient`, `Remote-MTA`, `Reporting-MTA`, `Status` | Inside the `message/delivery-status` part of a failure or delay notice | RFC 3464 fields, not top-level headers. One block per recipient |
| `Arrival-Date`, `Feedback-Type`, `Original-Mail-From`, `Reported-Domain`, `Source-IP`, `User-Agent`, `Version` | Inside the `message/feedback-report` part of an abuse report | RFC 5965 fields, not top-level headers. `User-Agent` is the mail hostname in the report epistle sends on its own, and `epistle/<version>` in the report `epistle report-abuse` prints |
| `Authentication-Results` | Inbound mail from a peer that did not log in, when a resolver is configured and the peer address is known. Never on a submission: no check of ours happens on one, so a field naming one would be a claim about a hop that did not take place, and the client's is dropped on all three paths | Authserv-id is the mail hostname. Lists `spf`, one `dkim` entry per signature (`dkim=none` without one) and `dmarc`. On unauthenticated SMTP, fields naming our hostname (case-insensitively) or with an unparseable authserv-id are removed before ours is added. Parseable foreign ids are kept below ours as untrusted information. The preamble reader accepts MIME tokens and quoted values, comments, folding and an optional numeric version |
| `Auto-Submitted` | REST `auto_submitted` field; every system message (`auto-generated`) except the vacation reply (`auto-replied (vacation)`) | The REST field accepts `no`, `auto-generated`, `auto-replied`, `auto-notified` (RFC 3834). The server writes `auto-generated` on the mail it generates itself, bounces included, whatever the original sender asked for; `system_auto_submitted` (`true`) turns that off, and with it off every generated message leaves without the field, failure notices and delay warnings among them, so nothing stops a bounce loop by that field alone and the null return path is what prevents it. A vacation reply stays `auto-replied (vacation)`: it is an answer, not a generated message |
| `Bcc`, `Resent-Bcc` | Removed at SMTP submission and at JMAP `EmailSubmission/set`; never written by the REST API | The recipients stay on the envelope. A JMAP draft keeps `Bcc`. Inbound mail keeps whatever the sender wrote |
| `Cc`, `Sender`, `Reply-To` | REST fields `cc`, `sender`, `reply_to`; JMAP Email properties | Written only when given |
| `Content-Disposition`, `Content-ID`, `Content-Transfer-Encoding`, `Content-Type`, `MIME-Version` | The MIME builder behind REST, JMAP, replies and reports | `Content-Transfer-Encoding` is `7bit`, `quoted-printable` or `base64` as the content needs. `Content-ID` only on inline parts |
| `DKIM-Signature` | The copy of a message that goes to a remote recipient, from any submission path, and vacation replies | See [DKIM](#dkim). Not on the copy stored for a local recipient, not on the Sent copy |
| `Date` | REST always; SMTP submission and JMAP when missing; every system message | RFC 5322 format in UTC with `+0000` |
| `Delivered-To` | Every stored copy, once per mailbox delivery, and forwarded copies | Names the address the copy was finally delivered to. Sender-supplied fields are removed at unauthenticated SMTP ingress. Internal delivery and forwarding retain earlier fields for forwarding-loop detection; mail returning through SMTP is still subject to the `Received` hop limit |
| `Epistle-Class` | Removed from every submission and from unauthenticated SMTP inbound mail | The class of a message is decided by the server (see the [API guide](api.md#class-and-evidence)), never by this header |
| `Feedback-ID` | REST `feedback_id` field; every submission without one (see [Identification headers](#identification-headers)) | The server's own value is `epistle:<class>:<domain>` and names no account; the client's is kept as written. `default_feedback_id` (`true`) turns the default off |
| `From` | REST (with the `from_name` or the account's display name as phrase); JMAP; system messages | On SMTP submission the client's `From` is kept as is. The send-as rule decides which addresses an account may use |
| `Importance`, `X-Priority` | REST `importance` field | `high` writes `Importance: high` and `X-Priority: 1 (Highest)`, `normal` writes `3 (Normal)`, `low` writes `5 (Lowest)` |
| `In-Reply-To`, `References` | REST fields; JMAP properties; vacation replies when the original had a `Message-ID` | |
| `List-Id`, `List-Post` | Local delivery to a list address (an alias with a list id); a submission whose envelope sender is that list address | Delivery adds them above `Received`, together with a `List-Unsubscribe`. Submission adds the same three fields, replacing whatever the client wrote for them; `default_list_id` (`true`) turns that off |
| `List-Unsubscribe`, `List-Unsubscribe-Post` | REST `list_unsubscribe` and `list_unsubscribe_post`; local delivery to a list address and a submission from one (`List-Unsubscribe` only); bulk `transactional` submissions (`List-Unsubscribe` only) | REST: at most four URLs, `mailto:` or `https://`, and `List-Unsubscribe-Post: List-Unsubscribe=One-Click` needs an `https://` URL. Marketing mail is refused without both. A list address gets a `mailto:` URL with `?subject=unsubscribe`, which is also what a bulk `transactional` submission gets when it has none; a client's `List-Unsubscribe-Post` is removed with it, since it would name an `https` URL the message no longer carries |
| `Message-ID` | REST always; SMTP submission and JMAP when missing; alert emails; DMARC and TLS-RPT reports | `<uuid-v7@domain>`. REST uses the first configured domain, not the sender's. SMTP submission uses the domain of the envelope sender (the hostname when there is none). Failure notices, vacation replies and abuse reports get none from epistle |
| `Organization` | A submission whose sending domain has an entry in `domain_organization` | The configured value of the domain, and it replaces what the client wrote. With no entry for the domain the client's own value stays. See [Identification headers](#identification-headers) |
| `Precedence` | `bulk` on marketing mail | Any `Precedence` the client wrote is removed first. Other classes are left alone |
| `Received` | SMTP, both inbound and submission | `Received: from <EHLO name> ([<peer ip>])` then `by <hostname> with <protocol>;` and the date. The protocol is `SMTP`, `ESMTP`, `ESMTPS`, `ESMTPA` or `ESMTPSA`. The client address appears even on submission, and there is no setting to leave it out. Not added by REST, JMAP, forwarding or the queue worker. On submission the client's own `Received` is dropped before this one is written, and a JMAP draft's is dropped at submission; on inbound earlier ones stay |
| `Received-SPF` | Inbound mail from a peer that did not log in | `Received-SPF: <result> (domain of <domain>) client-ip=<ip>`. Sender-supplied instances are removed before the local result is added. A failed SPF is refused at SMTP and never reaches this point |
| `Return-Path` | Every stored copy | The envelope sender, `<>` for a bounce. Any `Return-Path` the message arrived with is removed first. Not added to the copy that leaves for a remote recipient, and not to the Sent copy; a `Return-Path` a client wrote on submission goes out as written |
| `Subject` | REST always (empty when not given); JMAP; system messages | Non-ASCII text is written as RFC 2047 encoded words |
| `TLS-Report-Domain`, `TLS-Report-Submitter` | TLS-RPT report emails | RFC 8460 |
| `TLS-Required` | Read on submitted mail, removed from inbound mail | `TLS-Required: No` from a local sender makes the MTA-STS and DANE policies advisory for that message. Left in place when the message goes out |
| `To` | REST (empty `to` is allowed when `cc` or `bcc` has someone); JMAP; system messages | |
| `X-` custom headers | REST `headers` object | Up to 32, name `X-` plus letters, digits and hyphens, at most 76 characters, not `X-Priority`. Written after the other optional headers, before `MIME-Version`. The name keeps the case you gave it |
| `X-Epistle` | Nothing by default; every submission when `x_epistle_header` is on | The fixed value `1`. No version rides in it and no version field sits beside it |
| `X-Epistle-*` | Reserved for local verdicts | `X-Epistle` and every name under it with a hyphen are removed on every submission, and `X-Epistle-*` on unauthenticated SMTP ingress, before the server writes any of its own. The namespace is the name and the names under it, not a text prefix, so `X-Epistlefoo` is the sender's and survives |
| `X-Epistle-Attachment-Warning` | Inbound mail the `[attachments]` policy flags or quarantines | Comma-separated reason codes only, never text from the message. Removed first from inbound and from every submission, so only the server's own verdict is ever in it |
| `X-Mailbox` | Written by `epistle export` and read by `epistle import` in an mbox file | A marker of the mbox format, not a header of any message in transit |
| `X-Spam-Score`, `X-Spam-Status` | Inbound mail from a peer that did not log in whose Bayesian score reaches `bayes_junk_at` | `X-Spam-Status: Yes` and the probability with six decimals, above `Received`. All sender-supplied `X-Spam-*` fields are removed on unauthenticated SMTP ingress before local verdicts are added |

## Identification headers

Every submission path writes these, from the same code
(`evidence::submission::prepare`), so the same message carries the same fields
whether it went out over SMTP after AUTH, through `POST /api/v1/send` or through
JMAP `EmailSubmission/set`. They are written before the message is DKIM-signed,
so every one of them is covered by the signature. Each has a switch in the
[configuration](configuration.md#top-level-keys).

| Field | When the server writes it | Switch (default) |
|---|---|---|
| `Feedback-ID` | A submission with no `Feedback-ID` of its own. `epistle:<class>:<domain>`, where the class is the one the server granted and the domain is the one the message is sent for. No account name and no other personal data goes in it | `default_feedback_id` (`true`) |
| `List-Unsubscribe` | A `transactional` submission with more recipients than `bulk_recipients`. One `mailto:` URI naming the sender with `?subject=unsubscribe`, percent-encoded per RFC 6068 so a `?`, an `&` or a `%` in the address cannot read as a query. A submission that already has a `List-Unsubscribe` is left alone, whatever wrote it. When the server writes one and the client left none, the client's `List-Unsubscribe-Post` goes with it: RFC 8058 posts to an `https` URL, and a `mailto:` is not one | `default_list_unsubscribe` (`true`) and `bulk_recipients` (`20`) |
| `List-Id`, `List-Post`, `List-Unsubscribe` | A submission whose envelope sender is a `[[alias]]` with a `list_id`. The same block local delivery prepends, minus the `List-Unsubscribe` when the client already sent one. The two fields that say what the list is replace whatever the client wrote for them and name the alias in its canonical form; the unsubscribe the client chose is kept, one-click included, because RFC 8058 posts to it | `default_list_id` (`true`) |
| `X-Epistle` | Nothing, unless asked for: the fixed value `1`, with no version in it and no version field beside it. It says the message left an epistle server and nothing more | `x_epistle_header` (`false`) |
| `Organization` | A submission whose sending domain has an entry in `domain_organization`. That value replaces whatever the client wrote for the field; with no entry configured the client's own claim is left alone, because the server has no opinion to overrule it with | `organization_header` (`true`) |

What counts as bulk for the `mailto` unsubscribe: a `transactional` class with
more than `bulk_recipients` recipients, twenty-one with the default setting.
Marketing mail is left alone, because it already has to carry a one-click
unsubscribe the sender controls (see the `List-Unsubscribe` row above); personal
mail is correspondence between people, where an unsubscribe address would be a
stranger's mailbox offered to everyone. A submission that already carries a
`List-Unsubscribe`, from the client or from the list block, keeps it, and only
one ever goes out: the server never replaces an address the sender chose, never
adds a second one, and a sender who wrote two of its own keeps the first.

Nothing on the server answers that `mailto:` URI. It names the sender's own
mailbox and the subject the sender's own tooling has to recognise, so the
unsubscribe is the sender's to honour and not the server's: set
`default_list_unsubscribe = false` when no such tooling reads the subject, and
raise `bulk_recipients` for a submission list that is large but not a campaign.
An empty envelope sender gets no `mailto:` and no `Feedback-ID`, and a domain
outside ASCII leaves the `Feedback-ID` out with a line in the log, since
RFC 2919 has no room for one.

### What a client can and cannot say

A client over SMTP authenticates and then writes the message, so it can send
any header it likes. What reaches a receiver is what the server does with it:

- Rewritten by the server: `X-Epistle` and every name under it with a hyphen
  are removed before the server writes its own, `Authentication-Results` is
  removed because a submission had no check of ours to report, and
  `Organization` is replaced by the domain's configured value when one is
  configured.
- Left as the client wrote it: `Feedback-ID`, `List-Unsubscribe` with its
  `List-Unsubscribe-Post`, and `Organization` when no value is configured for
  the domain.
- One copy of each: a sender that writes one of these fields twice keeps the
  first and loses the second. RFC 2369 lets `List-Unsubscribe` appear more
  than once, but a receiver is then left to guess which one it should act on,
  and the copy it does not pick is a copy the sender wanted followed.
- Written once by the server: `List-Id`, `List-Post`, `List-Unsubscribe` and
  `X-Epistle`, each at most one.

What limits a forged claim is the signature, not the parser. Every field above
lands before the message is DKIM-signed, so it is inside the signature, and
`Auto-Submitted` is oversigned so a second copy added later breaks both
signatures. A receiver that trusts the signature over the bytes sees the
server's claim; one that only reads the bytes sees the client's. The REST API
and JMAP cannot submit these fields as custom headers: a REST custom header has
to be named `X-`, and a JMAP draft's `X-Epistle-*` and `Authentication-Results`
are stripped, though a draft may still carry a `Feedback-ID` or an
`Organization` of its own.

## System mail

The messages the server writes by itself. The table lists the top-level header
names the builder of each message writes; `tests/headers_system_mail.rs` builds
each one and compares.

| Message | Top-level headers |
|---|---|
| Failure notice | `From`, `To`, `Subject`, `Date`, `Auto-Submitted`, `MIME-Version`, `Content-Type` |
| Delay warning | `From`, `To`, `Subject`, `Date`, `Auto-Submitted`, `MIME-Version`, `Content-Type` |
| Vacation reply | `From`, `To`, `Subject`, `Date`, `Auto-Submitted`, `In-Reply-To`, `References`, `MIME-Version`, `Content-Type`, `Content-Transfer-Encoding` |
| Abuse report | `From`, `To`, `Subject`, `Date`, `Auto-Submitted`, `MIME-Version`, `Content-Type` |
| DMARC aggregate report | `Date`, `Message-ID`, `From`, `To`, `Subject`, `Auto-Submitted`, `MIME-Version`, `Content-Type` |
| TLS-RPT report | `Date`, `Message-ID`, `From`, `To`, `Subject`, `Auto-Submitted`, `MIME-Version`, `Content-Type`, `TLS-Report-Domain`, `TLS-Report-Submitter` |

Notes:

- The envelope sender of a failure notice, a delay warning and a vacation reply
  is empty, so the stored copy carries `Return-Path: <>`.
- The TLS-RPT sender adds `Date` and `Message-ID` in front of the report, and
  the alert emails carry `From`, `To`, `Subject`, `Date`, `Message-ID`,
  `Auto-Submitted`, `MIME-Version` and `Content-Type`; those two are covered by
  the source scan and not by the builder test.
- A vacation reply is DKIM-signed for the domain of its `From`. A failure or
  delay notice has an empty envelope sender, so it is signed only when the mail
  hostname is itself one of the hosted domains, and is otherwise sent unsigned
  (read from the routing code, not observed end to end).
- With `system_auto_submitted = false` the generated messages in the table above
  go out without `Auto-Submitted`, so the table of names no longer matches a
  server so configured. Nothing here reads that field back; what keeps a bounce
  from looping is the null return path.

## DKIM

`DKIM-Signature` is added to the copy of a message that leaves for a remote
recipient, by every submission path and for vacation replies. It is not added
to the copy delivered to a local mailbox, to the Sent copy, to a forwarded copy
or to inbound mail.

- Algorithm `ed25519-sha256`. When an RSA key is configured the message carries
  a second `DKIM-Signature` with `rsa-sha256` and the RSA selector.
- Canonicalization `relaxed/relaxed`.
- Both algorithms use the same `h=` list, covering every present instance of
  the fields below, selected from the bottom of the message upward.
- Important fields are oversigned: their name occurs in `h=` once more than
  the number of present instances. An absent important field, including
  `Reply-To`, is listed once. RFC 6376 sections
  [5.4](https://www.rfc-editor.org/rfc/rfc6376.html#section-5.4) and
  [5.4.2](https://www.rfc-editor.org/rfc/rfc6376.html#section-5.4.2) permit this
  to detect later additions. Adding even an identical copy breaks the signature.
- Both `List-Unsubscribe` and `List-Unsubscribe-Post` are covered when present,
  as required for one-click unsubscribe by
  [RFC 8058 section 4](https://www.rfc-editor.org/rfc/rfc8058.html#section-4).
- `Received`, `Return-Path`, `Authentication-Results`, a client's own `X-*` and
  other fields outside the table are excluded. `X-Epistle` is the one `X-`
  field signed: it is one of ours. Existing `Resent-*` fields are signed,
  without oversigning, so a later resending hop can prepend a new block.
- `d=` is the domain of the single `From` when the server hosts it, and the
  domain of the envelope sender otherwise (then DMARC does not align). With no
  such domain, or with two `From` fields, or none, the message is not signed.
- No `t=`, `x=`, `l=` or `i=` tag.

| Signed header | Oversigned |
|---|---|
| `From` | Yes |
| `To` | Yes |
| `Cc` | Yes |
| `Subject` | Yes |
| `Date` | Yes |
| `Message-ID` | Yes |
| `Reply-To` | Yes |
| `Sender` | No |
| `MIME-Version` | No |
| `Content-Type` | Yes |
| `Content-Transfer-Encoding` | No |
| `References` | No |
| `In-Reply-To` | No |
| `List-Id` | No |
| `List-Unsubscribe` | Yes |
| `List-Unsubscribe-Post` | Yes |
| `List-Help` | No |
| `List-Post` | No |
| `List-Owner` | No |
| `List-Archive` | No |
| `Feedback-ID` | No |
| `Auto-Submitted` | Yes |
| `Organization` | No |
| `X-Epistle` | No |
| `Resent-*` | No |

Oversigning and the `Resent-*` wildcard are deliberate, and they have a real
cost at delivery. A header covered by `h=` is locked: Rewriting `Content-Type`
to add a charset, adding an absent oversigned field, or any other change to a
field the signature covers breaks both signatures. Relaxed canonicalisation
tolerates equivalent folding and whitespace, the TCP line
limit, but it does not tolerate changes to field values, including the value
of `Content-Type`. A list, forwarder or relay that rewrites a covered field
or adds one that was absent makes DKIM fail for that copy, and the receiver
is then left with whatever SPF alignment it can compute. If SPF is no longer
aligned, DMARC alignment is lost for that copy as well. Transit fields are
excluded because relays change them, and a list rewriting `Content-Type` or
adding `List-Unsubscribe` of its own is what is meant by the warning.

## What passes through

The server removes only what the tables name. On unauthenticated SMTP
inbound mail, signature verification reads the original message first, then
local trust fields are removed before local headers are added and the message
reaches scanners, Sieve or delivery. `DKIM-Signature`, `ARC-*` and earlier
`Received` fields remain intact. Removing a field covered by a sender's
signature can affect later verification of that signature.

The names listed in the Removed columns are matched case-insensitively, and
whitespace or control bytes inside or around the name are aligned against the
canonical form so a sender cannot smuggle a reserved field past the stripper
by breaking up the name. The configured hostname is normalised before it is
compared with an `Authentication-Results` authserv-id and before it is emitted
in one, so the same identity reads and writes the field.

A preserved `Authentication-Results` with a foreign authserv-id is untrusted
information, even when it reports a pass. Only the result epistle writes for
its own hostname describes this hop's checks. Authenticated submission keeps
its separate header policy in the table above.

A second pass over the header section catches a reserved field the
stripper left behind. mail-parser 0.11.9 is the safety net's parser; DKIM
and ARC run their own parsers on the bytes the stripper produced and
fold trailing Unicode whitespace with `name.trim_end()`, so the union of
their interpretations is what the safety net covers. A reserved field the
second pass flags turns into a permanent `550 5.7.1` and never reaches a
mailbox.

## Planned changes

These are not done. Do not depend on any of them yet.

- BIMI. Which headers it will add or read is not decided. What the DNS side
  needs is in the [DNS guide](dns.md#bimi-optional); the server writes no BIMI
  header today.

Until BIMI lands, the `Feedback-ID`, `List-Id`, `List-Unsubscribe`,
`Auto-Submitted`, `Organization`, `X-Epistle` and `DKIM-Signature` rows above
are what the server does.
