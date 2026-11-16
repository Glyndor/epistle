# Splitting `serve` by trust boundary

The design for splitting `epistle serve` by trust boundary: which process
holds which secret, which parser of hostile input runs where, and how the
processes talk to each other. The phases and the record of phase 1 are in
[the container split](container-split.md); [the container stack](container.md)
describes what runs. Nothing below exists in the tree unless the section
"What is separated today" says so.

## What is separated today

| Component | Process | Isolation | Holds |
|---|---|---|---|
| PostgreSQL | `db` container, uid 999 | `network_mode: none`; reached over a Unix socket on the `epistle-pgsock` volume | the directory, bans, Bayes, reputation, greylist |
| ClamAV | `clamav` and `freshclam` containers | reached over a Unix socket on the `clamd-socket` volume (`src/antispam/clamd/mod.rs`) | nothing of the installation; it parses the attachments it is sent |
| Certificates (phase 1, off by default) | `certs` container, `epistle serve --role certs` (`src/cli/serve/certs/mod.rs`) | its own `pasta` instance with the host alias closed; no port, no listener | the DNS credential and the ACME account key |
| DKIM record writes with phase 1 on | `certs`, asked by `mail` through the hand-off directory (`src/dns/handoff/mod.rs`) | a file exchange under `<data_dir>/dns-handoff`; `certs` refuses anything that is not a DKIM key record of a served domain | nothing new: `mail` keeps the DKIM keys |
| Everything else | `mail` container, `epistle serve` (`src/cli/serve/mod.rs`) | `pasta`, uid 65532, no capability, read-only root | every other secret and every parser below |

Where the code departs from the layout the container split describes:

- `certs` runs with the same uid and the same `keep-id` mapping as `mail`
  (`src/cli/init/compose/services/certs.rs::new_certs`), so the rule of a
  distinct uid per container is not met by phase 1 yet.
- `certs` mounts the whole configuration directory read-only. The process
  parses only `[acme]` and `[dns]` (`NOT_FOR_CERTS` in
  `src/cli/serve/mod.rs`), but the file it can read still carries the account
  hashes and the API token hash.
- `mail` reaches the hand-off directory through its read-write `data_dir`, so
  it can write results as well as requests. Only its own rotation reads the
  results, so a forged result can stall or mislead that rotation and nothing
  else.
- DKIM rotation keeps running with phase 1 on: the records go through the
  hand-off.

## Secrets: who holds what

"Today" is `epistle serve` with phase 1 off, which is the default.

| Secret | Read by today | Holder after the split | Phase |
|---|---|---|---|
| DNS provider credential | `mail` | `certs` | 1, built |
| ACME account key | `mail` | `certs` | 1, built |
| TLS private key | `mail` | every process that terminates TLS: inbound SMTP, mailbox access, the HTTP front if it terminates TLS | stays |
| DKIM keys, `[dkim]` and every `[[dkim.domain]]`, ed25519 and RSA | `mail` | signer | 2 |
| ARC sealing key (`[arc] key_file`) | `mail` | signer | 2 |
| Evidence signing key (`src/evidence/key/mod.rs`) | `mail` | signer | 2 |
| At-rest storage key (`[storage]`) | `mail`, in every path that reads or writes a message | every process that reads or writes a mailbox or the spool | not decided |
| SRS secret | `mail` | the process that forwards (`src/storage/routing/mod.rs`) | 5 |
| API token hash and `api_keys.toml` | `mail` | the core that serves the API; never the front | 4 |
| Account hashes, SCRAM verifiers, TOTP secrets, app passwords, the LDAP bind password | `mail` | credential service | 5 |
| OAuth signing key | `mail` | credential service, which issues the tokens | 5 |
| Webhook secret | `mail` | outbound dispatcher | 5 |
| LLM classifier API key | `mail` | classifier, not decided | 3 |
| Object storage secret (`[storage]` S3 backend) | `mail` | mailbox access | 5 |
| Database password | `mail` | each process that keeps state in PostgreSQL, with a role of its own | 5 |

The TLS key stays where TLS ends. Moving it behind a signing call would cost a
round trip per handshake and a new protocol for it, and the processes that
terminate TLS are the ones a TLS key protects in the first place.

## Parsers of hostile input

| Parser | Input from | Code | Runs in today | Runs in after the split |
|---|---|---|---|---|
| SMTP line, command, `DATA`, `BDAT`, SASL | the internet | `src/smtp/` | `mail` | inbound SMTP; it is the protocol |
| DKIM, ARC, SPF and DMARC verification | headers and DNS answers | `src/dkim/verify/`, `src/arc/`, `src/spf/`, `src/dmarc/` | `mail` | inbound SMTP |
| MIME walk and attachment inspection (archives, Office, SVG) | message bodies | `src/antispam/attachments/` | `mail` | sandbox, phase 3 |
| Virus scan | message bodies | `clamav` | `clamav` | `clamav`, built |
| Bayes tokenizer, scoring text, URL extraction | message bodies | `src/antispam/bayes/`, `src/antispam/scoring_text/`, `src/antispam/urls/` | `mail` | sandbox, phase 3 |
| LLM classifier | message text, sent out | `src/antispam/llm/` | `mail` | not decided |
| DMARC and TLS-RPT reports (gzip, zip, XML, JSON), ARF | mail to the report addresses | `src/reports/`, `src/antispam/arf/` | `mail`, at local delivery | sandbox, phase 3 |
| Sieve interpreter | delivered mail | `src/sieve/` | `mail`, at local delivery | local delivery |
| IMAP, POP3, ManageSieve commands | authenticated users | `src/imap/`, `src/pop3/`, `src/managesieve/` | `mail` | mailbox access, phase 5 |
| HTTP: API, JMAP, WebDAV with CalDAV and CardDAV, OAuth, SCIM, autoconfig, metrics | authenticated users and the panel | `src/api/`, `src/webdav/`, `src/autodiscovery/` | `mail` | the HTTP front, phase 4 |
| Remote MTA replies, MX, MTA-STS and DANE lookups | remote servers | `src/queue/` | `mail` | outbound delivery, phase 5 |

The verifiers stay with inbound SMTP. Their verdict is needed before the
server answers `250`, they read only headers and DNS answers, and each has a
fuzz target (`fuzz/fuzz_targets/message/dkim_signature.rs`,
`fuzz/fuzz_targets/message/arc_headers.rs`). A sandbox call per message would
cost more than the reach it removes.

Sieve stays with local delivery because what it decides is where the message
goes in the mailbox, and it already runs under a fixed budget per message
(`src/sieve/`).

## The processes after the split

| Process | Network | Mounts | Serves a socket to | Connects to |
|---|---|---|---|---|
| `certs` | DNS provider, CA | `acme/`, `dns-tlsa/`, `dns-handoff/` | nobody (file hand-off) | none |
| signer | none | the key directories, read-only | inbound SMTP, delivery, evidence writer | none |
| sandbox | none | nothing of `data_dir` | inbound SMTP, local delivery | none |
| HTTP front | its own published port, private address | its socket volume only | nobody | the core |
| inbound SMTP (today's `mail`) | port 25 and submission | spool (append), mailboxes (append) | the core's internal API | signer, sandbox, `db`, `clamav` |
| outbound delivery | port 25 out | spool | nobody | signer |
| dispatcher | egress to configured URLs only | none | the core | none |
| mailbox access | IMAP, POP3, ManageSieve ports | mailboxes | nobody | credential service |
| credential service | none | the directory files | inbound SMTP, mailbox access, the core | `db` |

The table is the target, not a commitment to ship all of it. Each row moves
only when its phase is decided and measured.

## How the processes talk

Each line is a design choice and the reason for it.

- **Transport: a Unix socket in a directory that only the server and its
  clients mount.** It is what `db` and `clamav` already do, there is no TCP
  path to misconfigure, and the mount list in the Compose file is the access
  list. There is no TCP or mTLS on a container network: `mail` runs on `pasta`
  to keep the client's address and cannot join a bridge, and a network shared
  by components is what this design rules out.
- **One socket per class of caller.** The signer gets one socket per client
  set (inbound SMTP and delivery, the evidence writer), each in its own
  volume. The server knows the class of the caller from the socket the
  connection came in on, and the volumes decide who reaches which. A single socket
  where the caller states who it is would let a compromised client state
  whatever it needs.
- **Caller identity beyond the socket: the peer's uid, once measured.**
  `SO_PEERCRED` gives the uid of the connecting process. Under rootless
  Podman with a different user namespace per container, the uid the server
  sees has not been measured, and an unmapped one reads as the overflow uid.
  Until it is measured, the socket's volume is the only identity. A shared
  token in each request is not used: every client would hold it, so it would
  add a secret to the exposed process and prove nothing the mount does not.
- **Framing: a hand-written binary frame.** A version byte, an operation byte,
  length-prefixed fields, a cap per field and per frame, one request and one
  answer per exchange, and a deadline on the whole exchange. The decoder reads
  input from a process that may be compromised, so it is a hostile parser on
  both sides and gets a fuzz target. JSON or `serde` types on the wire would
  put a bigger parser in the process that holds the keys and make the wire
  follow every refactor of an internal type, and HTTP on the socket would
  bring the whole HTTP stack into the signer.
- **Authorization is checked again by the server.** The signer checks that
  `d=` is a domain it holds a key for. The core checks the API credential
  itself: the front forwards the credential and the client address it saw,
  not an identity. If the front stated "key X" and the core trusted it, a
  compromised front would act as any key.
- **A server that cannot be reached fails the operation.** The client never
  falls back to doing the work in its own process and never skips it.
  Signing is where this bites: `SplitDelivery::sign_outbound`
  (`src/storage/routing/outbound.rs`) sends a message unsigned when the
  signer returns nothing, and with a remote signer "unreachable" must not
  take that path. What it does instead is not defined yet.
- **State with a single writer keeps it.** Rate limiters, bans, the evidence
  chain and the queue stay in one process and are reached through its socket.

## The signing interface (phase 2)

What crosses the boundary is the canonical header block, not the message:

| Field | From the requester | Checked by the signer |
|---|---|---|
| `d=` | the domain `SplitDelivery::signing_domain` picked | a domain the signer holds a key for |
| header names (`h=`) | the signed headers present, plus the oversigned ones | each a valid field name, no `:` or `;` |
| header block | the relaxed canonical form of those headers | one line per name, in order, each ending in CRLF; exactly one `from:` line |
| body hash (`bh=`) | SHA-256 of the relaxed canonical body | 32 bytes |

The signer picks the selector, builds the tag list, signs, and returns the
`DKIM-Signature` fields, ed25519 first and RSA after it when the domain has
both, exactly as `Signer::sign` (`src/dkim/sign/mod.rs`) writes them today.

- **The body never reaches the signer.** Sending the message would copy up to
  25 MiB per message through the socket and make the key holder parse MIME.
- **The signer picks `s=`.** The selector is inside the signed data, and a
  rotation can replace the key between two calls. When the holder of the key
  also writes `s=`, the selector always names the key that signed. If the
  requester named the selector, every rotation would open a window of refused
  signatures.
- **No bare digest.** A signer that signs any 32 bytes is an oracle for any
  `d=` and any protocol that uses the same key, and it cannot check the
  domain.

ARC follows the same shape: inbound SMTP computes the chain status and the
authentication results, and the signer builds and signs the
`ARC-Message-Signature` and the `ARC-Seal`. The evidence writer keeps the
chain and sends the statement bytes to be signed; the signer checks their
shape. Key creation for rotation moves to the signer, and publication stays with
`certs` through the hand-off.
