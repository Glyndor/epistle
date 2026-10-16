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

The class comes from, in order: the `class` field of an API request, the
credential (`epistle app-password create --class`, `epistle api-key create
--class`), the account (`epistle account set <name> --default-class`). An
`Epistle-Class` header in the message can only lower it to `personal`, and
is removed before the message is queued.

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
why. A token still being requested is not a break for three days. The
decision lives in the server's memory: no file can open it.

```sh
epistle evidence verify
epistle evidence acknowledge --reason "disk restored from the 2026-10-14 backup"
```

An acknowledgement is signed, kept in the chain, and names the exact
break; the break stays visible. Only root or the owner of the data
directory may make one.

## Giving evidence to a third party

```sh
epistle evidence export --message-id '<notice-42@school.example>' --out notice-42
epistle evidence export --recipient student@example.net --from 2026-10-01 --to 2026-10-31 --out student
```

The bundle holds the records, their inclusion proofs, each day's signed
seal, its timestamp token and the authority's certificates, the public
evidence key, the message when it was kept, and a `README.md` with the
exact `sha256sum` and `openssl` steps. Anyone can check it, offline,
without any configuration:

```sh
epistle evidence check notice-42
```

Each check is reported by name. Certificate revocation (CRL, OCSP) of the
timestamp authority is **not** checked; certificates are judged valid at
the stamped time.

## Limits

- The service account holds the evidence key and the data. Until a day is
  stamped, whoever controls that account can rewrite it and sign it again.
  The guarantee to a third party starts at the timestamp token: after it,
  a change to that day cannot be hidden.
- The evidence shows what this server sent and was told. It cannot show
  what the receiving server did next.
- Publish the evidence key's id (the file name under `keys/` in any
  bundle) where a third party can compare it, so a bundle signed by
  another key stands out.
