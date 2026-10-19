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
| **SMTP submission** (587, 465, after AUTH) | `Received`; `Message-ID` and `Date` only when the client left them out; `DKIM-Signature` on the copy that leaves the server; `Precedence: bulk` for marketing mail | `Bcc` and `Resent-Bcc`; `Epistle-Class`; `X-Epistle-Attachment-Warning`; any `Precedence` the client wrote, for marketing mail | Everything else, including a `Received`, `Authentication-Results`, `Return-Path` or `Delivered-To` the client wrote |
| **REST API** (`POST /api/v1/send`) | `From`, `Subject`, `Date`, `Message-ID`, `MIME-Version`, `Content-Type` always; `To`, `Sender`, `Cc`, `Reply-To`, `In-Reply-To`, `References`, `Importance` with `X-Priority`, `List-Unsubscribe` with `List-Unsubscribe-Post`, `Auto-Submitted`, `Feedback-ID` and your `X-` headers when the request has the field; `Content-Transfer-Encoding`, `Content-Disposition`, `Content-ID` for bodies and attachments; `DKIM-Signature` on the copy that leaves the server; `Precedence: bulk` for marketing mail | `X-Epistle-Attachment-Warning` if you send it as a custom header | Nothing: the request names every header, and only the fields listed in the [API guide](api.md) turn into one |
| **JMAP** (`Email/set` then `EmailSubmission/set`) | The headers of the Email object (`From`, `Sender`, `To`, `Cc`, `Bcc`, `Reply-To`, `Subject`, `In-Reply-To`, `References`, `MIME-Version`, `Content-*`); `Message-ID` and `Date` when missing; `DKIM-Signature` on the copy that leaves the server; `Precedence: bulk` for marketing mail | `Bcc` and `Resent-Bcc` at submission; `Epistle-Class`; any `Precedence` the draft had, for marketing mail | Nothing the draft carries besides the above. Custom `header:` properties on `Email/set` create are ignored |
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
| `Authentication-Results` | Inbound mail from a peer that did not log in, when a resolver is configured and the peer address is known | Authserv-id is the mail hostname. Lists `spf`, one `dkim` entry per signature (`dkim=none` without one) and `dmarc`. On unauthenticated SMTP, fields naming our hostname (case-insensitively) or with an unparseable authserv-id are removed before ours is added. Parseable foreign ids are kept below ours as untrusted information. The preamble reader accepts MIME tokens and quoted values, comments, folding and an optional numeric version |
| `Auto-Submitted` | REST `auto_submitted` field; failure and delay notices (`auto-replied`); vacation replies (`auto-replied (vacation)`); alert emails and abuse reports (`auto-generated`) | The REST field accepts `no`, `auto-generated`, `auto-replied`, `auto-notified` (RFC 3834). Planned: see [Planned changes](#planned-changes) |
| `Bcc`, `Resent-Bcc` | Removed at SMTP submission and at JMAP `EmailSubmission/set`; never written by the REST API | The recipients stay on the envelope. A JMAP draft keeps `Bcc`. Inbound mail keeps whatever the sender wrote |
| `Cc`, `Sender`, `Reply-To` | REST fields `cc`, `sender`, `reply_to`; JMAP Email properties | Written only when given |
| `Content-Disposition`, `Content-ID`, `Content-Transfer-Encoding`, `Content-Type`, `MIME-Version` | The MIME builder behind REST, JMAP, replies and reports | `Content-Transfer-Encoding` is `7bit`, `quoted-printable` or `base64` as the content needs. `Content-ID` only on inline parts |
| `DKIM-Signature` | The copy of a message that goes to a remote recipient, from any submission path, and vacation replies | See [DKIM](#dkim). Not on the copy stored for a local recipient, not on the Sent copy |
| `Date` | REST always; SMTP submission and JMAP when missing; every system message | RFC 5322 format in UTC with `+0000` |
| `Delivered-To` | Every stored copy, once per mailbox delivery, and forwarded copies | Names the address the copy was finally delivered to. Sender-supplied fields are removed at unauthenticated SMTP ingress. Internal delivery and forwarding retain earlier fields for forwarding-loop detection; mail returning through SMTP is still subject to the `Received` hop limit |
| `Epistle-Class` | Removed from every submission and from unauthenticated SMTP inbound mail | The class of a message is decided by the server (see the [API guide](api.md#class-and-evidence)), never by this header |
| `Feedback-ID` | REST `feedback_id` field | Written only when given. Planned: see [Planned changes](#planned-changes) |
| `From` | REST (with the `from_name` or the account's display name as phrase); JMAP; system messages | On SMTP submission the client's `From` is kept as is. The send-as rule decides which addresses an account may use |
| `Importance`, `X-Priority` | REST `importance` field | `high` writes `Importance: high` and `X-Priority: 1 (Highest)`, `normal` writes `3 (Normal)`, `low` writes `5 (Lowest)` |
| `In-Reply-To`, `References` | REST fields; JMAP properties; vacation replies when the original had a `Message-ID` | |
| `List-Id`, `List-Post` | Local delivery to a list address (an alias with a list id) | Added above `Received`, together with a `List-Unsubscribe` |
| `List-Unsubscribe`, `List-Unsubscribe-Post` | REST `list_unsubscribe` and `list_unsubscribe_post`; local delivery to a list address (`List-Unsubscribe` only) | REST: at most four URLs, `mailto:` or `https://`, and `List-Unsubscribe-Post: List-Unsubscribe=One-Click` needs an `https://` URL. Marketing mail is refused without both. A list address gets a `mailto:` URL with `?subject=unsubscribe` |
| `Message-ID` | REST always; SMTP submission and JMAP when missing; alert emails; DMARC and TLS-RPT reports | `<uuid-v7@domain>`. REST uses the first configured domain, not the sender's. SMTP submission uses the domain of the envelope sender (the hostname when there is none). Failure notices, vacation replies and abuse reports get none from epistle |
| `Precedence` | `bulk` on marketing mail | Any `Precedence` the client wrote is removed first. Other classes are left alone |
| `Received` | SMTP, both inbound and submission | `Received: from <EHLO name> ([<peer ip>])` then `by <hostname> with <protocol>;` and the date. The protocol is `SMTP`, `ESMTP`, `ESMTPS`, `ESMTPA` or `ESMTPSA`. The client address appears even on submission, and there is no setting to leave it out. Not added by REST, JMAP, forwarding or the queue worker |
| `Received-SPF` | Inbound mail from a peer that did not log in | `Received-SPF: <result> (domain of <domain>) client-ip=<ip>`. Sender-supplied instances are removed before the local result is added. A failed SPF is refused at SMTP and never reaches this point |
| `Return-Path` | Every stored copy | The envelope sender, `<>` for a bounce. Any `Return-Path` the message arrived with is removed first. Not added to the copy that leaves for a remote recipient, and not to the Sent copy; a `Return-Path` a client wrote on submission goes out as written |
| `Subject` | REST always (empty when not given); JMAP; system messages | Non-ASCII text is written as RFC 2047 encoded words |
| `TLS-Report-Domain`, `TLS-Report-Submitter` | TLS-RPT report emails | RFC 8460 |
| `TLS-Required` | Read on submitted mail, removed from inbound mail | `TLS-Required: No` from a local sender makes the MTA-STS and DANE policies advisory for that message. Left in place when the message goes out |
| `To` | REST (empty `to` is allowed when `cc` or `bcc` has someone); JMAP; system messages | |
| `X-` custom headers | REST `headers` object | Up to 32, name `X-` plus letters, digits and hyphens, at most 76 characters, not `X-Priority`. Written after the other optional headers, before `MIME-Version`. The name keeps the case you gave it |
| `X-Epistle-*` | Reserved for local verdicts | All sender-supplied fields in this namespace are removed on unauthenticated SMTP ingress |
| `X-Epistle-Attachment-Warning` | Inbound mail the `[attachments]` policy flags or quarantines | Comma-separated reason codes only, never text from the message. Removed first from inbound and from every submission, so only the server's own verdict is ever in it |
| `X-Mailbox` | Written by `epistle export` and read by `epistle import` in an mbox file | A marker of the mbox format, not a header of any message in transit |
| `X-Spam-Score`, `X-Spam-Status` | Inbound mail from a peer that did not log in whose Bayesian score reaches `bayes_junk_at` | `X-Spam-Status: Yes` and the probability with six decimals, above `Received`. All sender-supplied `X-Spam-*` fields are removed on unauthenticated SMTP ingress before local verdicts are added |

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
| DMARC aggregate report | `Date`, `Message-ID`, `From`, `To`, `Subject`, `MIME-Version`, `Content-Type` |
| TLS-RPT report | `Date`, `Message-ID`, `From`, `To`, `Subject`, `MIME-Version`, `Content-Type`, `TLS-Report-Domain`, `TLS-Report-Submitter` |

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
- `Received`, `Return-Path`, `Authentication-Results`, `X-*` and other fields
  outside the table are excluded. Existing `Resent-*` fields are signed,
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

A second pass over the header section with the same parser the downstream
readers use (mail-parser 0.11.9) catches a reserved field the stripper left
behind; the message is then refused with `550 5.7.1` and never reaches a
mailbox.

## Planned changes

These are not done. Do not depend on any of them yet.

- A `Feedback-ID` by default on mail sent through the API.
- A `List-Id` and the matching list headers on API mail that asks for them.
- An `Auto-Submitted` value chosen by the server for the mail it generates, and
  a wider use of it.
- BIMI. Which headers it will add or read is not decided.

Until they land, the `Feedback-ID`, `List-Id`, `Auto-Submitted` and `DKIM-Signature`
rows above are what the server does.
