# Evidence of sending

Some mail has to be proved later: a notice of withdrawal, a receipt, a
legal warning. epistle can keep evidence that such a message was accepted
and what the receiving server answered, in a form a third party can check
without trusting the server.

## What it is, and what it is not

The evidence is a *mensaje de datos* in the sense of Ley 527 de 1999
(Colombia): articles 9 to 12 accept a data message as evidence when its
integrity can be shown, and its date and origin established. The evidence
log is built for that: every record is hash-chained, every day is signed,
and every day's signature is stamped by an independent timestamp authority
(RFC 3161).

It is **not** "correo electrónico certificado". Only entities accredited by
ONAC may offer that service, and epistle is not one. It does **not** prove
that anyone read a message: it proves what was sent, when, and what the
receiving server replied (`250 OK`, a bounce, or nothing at all).

## Mail classes

Every message has a class, decided by the server, never by the message:

| Class | What follows |
|---|---|
| `transactional` | Evidence always kept; refused (SMTP `451 4.3.0`, API `503`) when its record cannot be written; never copied to Sent |
| `marketing` | Refused without a one-click unsubscribe (RFC 8058); sent with `Precedence: bulk`; never to a suppressed address |
| `personal` | The default; no evidence unless a policy asks for it |

What is bound to the credential (`epistle app-password create --class`,
`epistle api-key create --class`), else to the account (`epistle account set
<name> --default-class`), is a floor. The `class` field of an API request or a
JMAP submission may ask for a stricter class, in the order personal,
marketing, transactional, and never for a looser one: a key made for notices
cannot send mail that skips their evidence. An `Epistle-Class` header in the
message changes nothing, and is removed before the message is queued.

## What is kept

Per message: who sent it, to whom, its `Message-ID`, date, subject and
SHA-256, and per recipient the outcome: delivered (with the remote reply,
the MX, the TLS version and cipher, DANE and MTA-STS status), bounced or
expired. With `full`, the exact message bytes too, encrypted like the
mailbox.

```sh
epistle evidence policy show
epistle evidence policy set --class transactional --mode full --days 365
epistle evidence policy set --class personal --tenant school --mode metadata --days 90
```

Without a rule, `transactional` keeps metadata for 365 days. A rule may
lengthen it or keep full messages, never turn it off. Every change is
recorded in the evidence.

Kept messages go when their own retention passes. Records go only when
every record of their day has expired, and only while the whole evidence
verifies, the day still matches its seal, and its timestamp token
verifies. A purge leaves a signed statement naming each day, its record
count and Merkle root, and a purge record in the chain, so the chain
still verifies after it. A day with an acknowledged break, or without a
token, is never purged.

## Timestamps

Every day after midnight UTC, the server seals the day (Merkle root, signed
with the evidence key) and asks a timestamp authority to stamp the seal.
Only the SHA-256 of the seal leaves the server: no message, no address.

The default authority is Sectigo's public service, trusted only when its
token chains to the pinned key of "Sectigo Public Time Stamping Root R46".
FreeTSA is not supported (ECDSA P-384 with SHA-512).

```sh
epistle evidence timestamp show
epistle evidence timestamp enable --tsa https://tsa.example.net --anchor <sha256-of-spki>
epistle evidence timestamp disable    # asks; --yes off a terminal; recorded in the evidence
```

## When the evidence does not verify

The server verifies the whole log every five minutes. It takes no
`transactional` mail until the first verification after it starts, nor
when the last clean one is more than 15 minutes old, nor while anything is
wrong (a changed record, a day left unsealed, a seal or token that does not
verify, a check that fails or runs past ten minutes). `epistle status` says
why. A token still being requested is not a break for three days. After three days
without one it is: a token issued later is refused, since it would date the
seal and not the sending, so the day stays without a timestamp. Acknowledge the
break to take transactional mail again; that day rests on the evidence key
alone, and `check` fails it for lack of a token. The
decision lives in the server's memory: no file can open it.

```sh
epistle evidence verify
epistle evidence acknowledge --reason "disk restored from the 2026-10-14 backup"
```

An acknowledgement is signed, kept in the chain, and names the exact
break; the break stays visible. Only root or the owner of the data
directory may make one.

A break found inside one day also names the day as it was when you looked: a
digest of its lines before the acknowledgement and of its checkpoint,
signature and token. Change the day afterwards, even leaving the break's
words the same, and the break is back. What the acknowledgement does not name
is still checked: the rest of the day, the day's seal and the link to the next
day. A break in a sealed day therefore usually shows twice, the chain and then
the seal that no longer matches; acknowledge each.

## Giving evidence to a third party

```sh
epistle evidence export --message-id '<notice-42@school.example>' --out notice-42
epistle evidence export --recipient student@example.net --from 2026-10-01 --to 2026-10-31 --out student
```

The bundle holds the records, their inclusion proofs, each day's signed
seal, its timestamp token and the authority's certificates, the public
evidence key, the message when it was kept, and a `README.md` with the
exact `sha256sum` and `openssl` steps. Anyone can check it, offline,
without any server or configuration, once they hold the key the operator
published (see below):

```sh
epistle evidence check --key 3f2a...e91c notice-42
```

Each check is reported by name. A file that no verified day and no
accepted record accounts for fails the check, even when `SHA256SUMS` lists
it, so nothing can be added to a bundle without being noticed. Certificate revocation (CRL, OCSP) of the
timestamp authority is **not** checked; certificates are judged valid at
the stamped time.

## The signing key

A bundle cannot vouch for the key that signed it: whoever holds the data
could re-sign every day with another key and put that key in the bundle. So
the reader brings the keys, and `check` fails without `--key` (a
fingerprint, or a PEM file).

```sh
epistle evidence key show     # the fingerprints to publish, with the day each earlier one handed over
epistle evidence key rotate   # asks; --yes off a terminal
epistle evidence check --key 3f2a...e91c --key 91b0...47aa@2026-10-17 notice-42
```

A rotation is a statement the old key signs. It names the new key and the
day of the hand-over, is kept in the evidence, and travels in every bundle
that needs it. The old key seals nothing from that day on, and the new one
nothing before it. A key that has handed over could otherwise be leaked and
used to seal a day that never existed, so the reader anchors the **current
key bare and every earlier one with the day its period ended**
(`KEY@YYYY-MM-DD`, the "until" that `key show` prints). `check` refuses
several bare keys, refuses a day sealed by an earlier key on or after its
`until`, and refuses a day sealed by a key whose hand-over, found in the
bundle, was earlier. A key signs from the rotation record that introduces it
to the one that hands over from it: the day a rotation is recorded in is
sealed by the new key, and an acknowledgement or a purge statement written
after a rotation must be signed by the key then in force. `verify` says so
when it is not.

A reader need not anchor every key in between: an old publication (an earlier
key with its period) and the current key are enough for the days the current
key sealed. What is asked of the keys between is only what leads back to a key
the reader did anchor: a path from the day's signer that reaches an anchored
key is followed no further, and an older key with a period still cannot hand
over to a key the reader has no path to.

A token stamped long after its day ended shows when the day was sealed, not
when its mail was sent, so `check` fails a day whose token is dated more
than four days after the day ended.

## What a bundle can and cannot show it is complete

Each record in a bundle is proved against the signed root of its day. That
shows the records are the ones written; it cannot show that others were
left out. What `check` does show is that the ones present contradict
nothing: each message has its acceptance, and either an abandonment or an
outcome (delivered, bounced, expired, suppressed) for every recipient the
bundle covers, which `manifest.json` names (the whole message, or one
recipient). Take out the abandonment, or a bounce, and the message is no
longer accounted for and the check fails. A message still in the queue has no
outcome yet, so a bundle made too early does not verify: export it again
later. A bundle says nothing about messages it does not contain.

The manifest is part of the bundle and is not signed, so a bundle for one
recipient could be made to look like the whole story of a message. `check`
prints what the bundle covers, says when the outcomes of other recipients were
**not** checked, and checks the manifest against the records. Say what the
story is about and the check holds the bundle to it:

```sh
epistle evidence check --key 3f2a...e91c --message-id '<notice-42@school.example>' notice-42
epistle evidence check --key 3f2a...e91c --recipient student@example.net --from 2026-10-01 --to 2026-10-31 student
```

A bundle with no acceptance of what was asked about checks nothing, and fails.
The report says what was verified: how many acceptances, on which days, and
that the other recipients' outcomes were not checked when the bundle is for one,
and that messages to that recipient which are not in the bundle were not
checked either, whatever days it names.

A bundle that verifies proves what the records say, which is not always that
the message arrived. `check` counts what became of the recipients it covers
(delivered, bounced, expired, suppressed, or abandoned: nothing was sent), says
so in a `delivery:` note and in the last line, and puts the counts and
`all_delivered` in the JSON. `--require-delivered` makes the exit code 1
unless every recipient covered was delivered. A recipient with two different
endings in the records fails the check. A bundle holds a selection of the
log, so it cannot show that no outcome came after the ones it holds: `check`
says how many records of the days it covers are not in the bundle, and that an
outcome among them cannot be ruled out.

## The clock

A clock that is wrong costs more than a wrong date. A record dated in the
future drags every later one into that day; sealing at a clock that is ahead
seals the day that is still open; purging at one deletes kept messages before
their retention; the queue gives up on mail that only waited. So none of
those read the machine's clock raw. They read one time reference that checks
it:

- against the monotonic clock: once a reading was believed, the reference
  moves only forward with the monotonic clock, never to a wall clock that is
  ahead of it. A clock more than five minutes ahead of it (plus one second per
  thousand that passed, the drift of a real clock) or more than an hour behind
  has jumped, and a clock that gains a little on every reading does not get
  believed by small steps: it drifts away until it is not;
- at start, against the newest record in the log (the head, else the newest
  record on disk): a clock before it, or more than a day after it, is not
  believed for sealing, purging or expiring. A log that cannot be read at
  start is not an empty log: nothing is believed;
- against a timestamp authority, when timestamping is on: a token is a time
  somebody else vouches for, and the server asks for one by itself when it
  does not believe the clock;
- against you: `epistle evidence clock accept` says the date this machine
  reads is the real one (for a server stopped for days, with no authority to
  ask). The running server takes it at its next check if it is less than an
  hour old.

While the clock is not believed, nothing is sealed, purged or expired on it,
the kept bytes and the records stay where they are, transactional mail is held,
and `epistle status` and the server log say why. Records are still written, so
a wrong clock never loses an acceptance and never refuses an outcome, an
acknowledgement or the repair at start: they are dated by the clock when it is
within 35 days after the newest record, else by an estimate (the last believed
time plus the monotonic clock, never earlier than the newest record). Mail in
the queue ages by the earlier of the clock and the estimate (a log that
could not be read leaves the queue nothing to compare to, so it ages by the
clock). When the clock
agrees again the tasks go on by themselves; starting the server again is also
enough, because the new process judges the clock by the log, not by what the
old one had seen. A clock that is behind a record dated in the future (a record
cannot be removed) is believed again when the date arrives. A key rotation
refuses to run at a clock more than 35 days past the newest record.

## Limits

- The server verifies the whole kept log every five minutes, from the oldest
  day. That reads every record again, by design: a changed day is found on the
  next tick. In a debug build it took about 47 seconds for 400 000 records, in
  flat memory; a release build was not measured. If a verification takes more
  than ten minutes the server holds transactional mail until it does not, so a
  log kept for a year has to stay below the number of records that fits.
  There is no incremental verification: caching a verified day would trust the
  files not to have changed, which is what the verification is for.
- One account may add 500 000 records a day (an acceptance and the outcome it
  owes each recipient, counted when it is accepted) and keep 4 GiB in full, and
  the whole log takes 5 000 000 records a day, so no account, whatever its
  fan-out, uses more than a tenth of what the others need. Past a limit the
  acceptance is refused with the retry-later answer, nothing is written, and
  `epistle status` warns at 80 percent. The counts are in memory and start
  again with the server. They keep the verification, which reads every record,
  from outgrowing its ten minutes; they are not a measurement of that time.
- The service account holds the evidence key and the data. Until a day is
  stamped, whoever controls that account can rewrite it and sign it again.
  The guarantee to a third party starts at the timestamp token: after it,
  a change to that day cannot be hidden.
- The evidence shows what this server sent and was told. It cannot show
  what the receiving server did next.
- Publish the evidence key's fingerprint (`epistle evidence key show`)
  where a third party can read it, with the period of every earlier one. The check is
  only as good as the key the reader brings.
