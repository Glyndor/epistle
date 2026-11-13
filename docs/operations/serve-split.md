# Splitting `serve` by trust boundary

This is the design behind #1400 and #1399: which process holds which secret,
which parser of hostile input runs where, how the processes talk to each
other, the order of the pull requests, and what still needs a decision. The
phases and the record of phase 1 are in [the split plan](container-split.md);
[the container stack](container.md) describes what runs. Nothing below exists
in the tree unless the section "What is separated today" says so.

## What is separated today

Read from `develop` on 2026-11-13.

| Component | Process | Isolation | Holds |
|---|---|---|---|
| PostgreSQL | `db` container, uid 999 | `network_mode: none`; reached over a Unix socket on the `epistle-pgsock` volume | the directory, bans, Bayes, reputation, greylist |
| ClamAV | `clamav` and `freshclam` containers | reached over a Unix socket on the `clamd-socket` volume (`src/antispam/clamd/mod.rs`) | nothing of the installation; it parses the attachments it is sent |
| Certificates (phase 1, off by default) | `certs` container, `epistle serve --role certs` (`src/cli/serve/certs/mod.rs`) | its own `pasta` instance with the host alias closed; no port, no listener | the DNS credential and the ACME account key |
| DKIM record writes with phase 1 on | `certs`, asked by `mail` through the hand-off directory (`src/dns/handoff/mod.rs`) | a file exchange under `<data_dir>/dns-handoff`; `certs` refuses anything that is not a DKIM key record of a served domain | nothing new: `mail` keeps the DKIM keys |
| Everything else | `mail` container, `epistle serve` (`src/cli/serve/mod.rs`) | `pasta`, uid 65532, no capability, read-only root | every other secret and every parser below |

Four things the code says that the plan does not:

- `certs` runs with the same uid and the same `keep-id` mapping as `mail`
  (`src/cli/init/compose/services/certs.rs::new_certs`), so the rule of a
  distinct uid per container is not met by phase 1 yet.
- `certs` mounts the whole configuration directory read-only. The process
  parses only `[acme]` and `[dns]` (`NOT_FOR_CERTS` in
  `src/cli/serve/mod.rs`), but the file it can read still carries the account
  hashes and the API token hash. #1614 lists this among its medium findings.
- `mail` reaches the hand-off directory through its read-write `data_dir`, so
  it can write results as well as requests. Only its own rotation reads the
  results, so a forged result can stall or mislead that rotation and nothing
  else.
- DKIM rotation keeps running with phase 1 on: since #1631 the records go
  through the hand-off. The two documents that said rotation waits are
  corrected in the same change as this page.

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
| At-rest storage key (`[storage]`) | `mail`, in every path that reads or writes a message | every process that reads or writes a mailbox or the spool | see decision 5 |
| SRS secret | `mail` | the process that forwards (`src/storage/routing/mod.rs`) | 5 |
| API token hash and `api_keys.toml` | `mail` | the core that serves the API; never the front | 4 |
| Account hashes, SCRAM verifiers, TOTP secrets, app passwords, the LDAP bind password | `mail` | credential service | 5 |
| OAuth signing key | `mail` | credential service, which issues the tokens | 5 |
| Webhook secret | `mail` | outbound dispatcher | 5 |
| LLM classifier API key | `mail` | classifier, see decision 8 | 3 |
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
| LLM classifier | message text, sent out | `src/antispam/llm/` | `mail` | see decision 8 |
| DMARC and TLS-RPT reports (gzip, zip, XML, JSON), ARF | mail to the report addresses | `src/reports/`, `src/antispam/arf/` | `mail`, at local delivery | sandbox, phase 3 |
| Sieve interpreter | delivered mail | `src/sieve/` | `mail`, at local delivery | local delivery |
| IMAP, POP3, ManageSieve commands | authenticated users | `src/imap/`, `src/pop3/`, `src/managesieve/` | `mail` | mailbox access, phase 5 |
| HTTP: API, JMAP, WebDAV with CalDAV and CardDAV, OAuth, SCIM, autoconfig, metrics | authenticated users and the panel | `src/api/`, `src/webdav/`, `src/autodiscovery/` | `mail` | the HTTP front, phase 4 |
| Remote MTA replies, MX, MTA-STS and DANE lookups | remote servers | `src/queue/` | `mail` | outbound delivery, phase 5 |

The verifiers stay with inbound SMTP. Their verdict is needed before the
server answers `250`, they read only headers and DNS answers, and each has a
fuzz target (`fuzz/fuzz_targets/message/dkim_signature.rs`,
`fuzz/fuzz_targets/message/arc_headers.rs`). A sandbox call per message would
cost more than the reach it removes. The rejected alternative was to send them
to the sandbox with the body parsers.

Sieve stays with local delivery because what it decides is where the message
goes in the mailbox, and it already runs under a fixed budget per message
(`src/sieve/`).

## The processes after the split

| Process | Network | Mounts | Serves a socket to | Connects to |
|---|---|---|---|---|
| `certs` | DNS provider, CA | `acme/`, `dns-tlsa/`, `dns-handoff/` | nobody (file hand-off) | none |
| signer | none | the key directories, read-only | inbound SMTP, delivery, evidence writer | none |
| sandbox | none | nothing of `data_dir` | inbound SMTP, local delivery | none |
| HTTP front (#1399) | its own published port, private address | its socket volume only | nobody | the core |
| inbound SMTP (today's `mail`) | port 25 and submission | spool (append), mailboxes (append) | the core's internal API | signer, sandbox, `db`, `clamav` |
| outbound delivery | port 25 out | spool | nobody | signer |
| dispatcher | egress to configured URLs only | none | the core | none |
| mailbox access | IMAP, POP3, ManageSieve ports | mailboxes | nobody | credential service |
| credential service | none | the directory files | inbound SMTP, mailbox access, the core | `db` |

The table is the target, not a commitment to ship all of it. Each row moves
only when its phase is decided and measured.

## How the processes talk

Each line is a design choice, with the reason and the alternative it replaced.

- **Transport: a Unix socket in a directory that only the server and its
  clients mount.** It is what `db` and `clamav` already do, there is no TCP
  path to misconfigure, and the mount list in the Compose file is the access
  list. Rejected: TCP or mTLS on a container network. `mail` runs on `pasta`
  to keep the client's address and cannot join a bridge, and a network shared
  by components is what #1400 rules out.
- **One socket per class of caller.** The signer gets one socket per client
  set (inbound SMTP and delivery, the evidence writer), each in its own
  volume. The server knows the class of the caller from the socket the
  connection came in on, and the volumes decide who reaches which. Rejected:
  one socket where the caller states who it is. A compromised client would
  state whatever it needs.
- **Caller identity beyond the socket: the peer's uid, once measured.**
  `SO_PEERCRED` gives the uid of the connecting process. Under rootless
  Podman with a different user namespace per container, the uid the server
  sees has not been measured, and an unmapped one reads as the overflow uid.
  Until it is measured, the socket's volume is the only identity. Rejected: a
  shared token in each request. Every client would hold it, so it adds a
  secret to the exposed process and proves nothing the mount does not.
- **Framing: a hand-written binary frame.** A version byte, an operation byte,
  length-prefixed fields, a cap per field and per frame, one request and one
  answer per exchange, and a deadline on the whole exchange. The decoder reads
  input from a process that may be compromised, so it is a hostile parser on
  both sides and gets a fuzz target. Rejected: JSON or `serde` types on the
  wire, which put a bigger parser in the process that holds the keys and make
  the wire follow every refactor of an internal type. Rejected too: HTTP on
  the socket, which would bring the whole HTTP stack into the signer.
- **Authorization is checked again by the server.** The signer checks that
  `d=` is a domain it holds a key for. The core checks the API credential
  itself: the front forwards the credential and the client address it saw,
  not an identity. Rejected: the front states "key X" and the core trusts it.
  A compromised front would then act as any key.
- **A server that cannot be reached fails the operation.** The client never
  falls back to doing the work in its own process and never skips it.
  Signing is where this bites: `SplitDelivery::sign_outbound`
  (`src/storage/routing/outbound.rs`) sends a message unsigned when the
  signer returns nothing, and with a remote signer "unreachable" must not
  take that path. What it takes instead is decision 1.
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
  Rejected for that reason.
- **The signer picks `s=`.** The selector is inside the signed data, and a
  rotation can replace the key between two calls. When the holder of the key
  also writes `s=`, the selector always names the key that signed. Rejected:
  the requester names the selector, and the signer refuses one it does not
  hold, which turns every rotation into a window of refused signatures.
- **No bare digest.** A signer that signs any 32 bytes is an oracle for any
  `d=` and any protocol that uses the same key, and it cannot check the
  domain. Rejected.

ARC follows the same shape: inbound SMTP computes the chain status and the
authentication results, and the signer builds and signs the
`ARC-Message-Signature` and the `ARC-Seal`. The evidence writer keeps the
chain and sends the statement bytes to be signed; the signer checks their
shape. Key creation for rotation moves to the signer, as the split plan
already says; publication stays with `certs` through the hand-off.

## Order of the pull requests

1. This document.
2. Signing in two halves, in one process: the half that reads the message and
   the half that holds the key, behind a named interface, with output that is
   identical byte for byte. No socket, no role, no Compose change. Built: the
   reader is `HeaderBlock` (`src/dkim/sign/block.rs`) and the key half is
   `KeyHolder` (`src/dkim/sign/holder.rs`), which `Signer` and
   `PerDomainSigner` implement.
3. The frame codec, the socket server and client for that interface, and a
   fuzz target for the codec, tested over a socket pair. The stack does not
   run it. Needs the uid measurement of decision 3. Built without it: the
   codec, `SignerServer` and `RemoteSigner` are in `src/dkim/remote/`, the
   fuzz target is `signer_frame`, and the socket's directory is the only
   identity (`0700`, the signer's uid, no `SO_PEERCRED`). A client that gets
   no answer it can trust returns `Unavailable`, which no caller takes yet:
   what `SplitDelivery` does with it is decision 1.
4. `epistle serve --role signer`, the `signer` service off by default,
   `epistle stack signer enable|disable`, an area in `epistle status` and the
   rollback, the way phase 1 did it. Needs decisions 1 to 4, 6 and 7.
5. ARC and the evidence key on the signer.
6. Phase 3, the sandbox: the same steps, interface first, then the socket,
   then the service.
7. Phase 4, the HTTP front of #1399.
8. Phase 5, one piece per pull request: outbound delivery, the dispatcher,
   mailbox access, the credential service.

Every phase adds its cross-process cases to the concurrency suite of #1426
before it merges, and passes the clean install and upgrade checks on the
Debian 13 machine. Each new service is off by default and removable with
`epistle stack rollback`, as `certs` is.

## Decisions for the owner

1. **Signer unreachable: defer or send unsigned.** Deferring answers a
   temporary failure, and the sender or the queue retries; sending unsigned
   keeps mail moving and fails DMARC wherever the domain publishes
   `p=reject`. Deferring is the recommendation: an unsigned message from a
   domain that signs is the outcome the split is meant to stop an attacker
   from forcing.
2. **What the signer refuses.** Today the path signs for the envelope domain
   when the From domain is not hosted, and the default `[dkim]` key signs any
   `d=`. The recommendation is that the signer refuses a `d=` outside the
   hosted domains and keeps the rest of today's behaviour, after a counter
   shows how often the current path signs outside them.
3. **A distinct uid per container under rootless Podman.** `keep-id` maps one
   uid, so a uid per service needs an explicit mapping per service inside the
   installation's 65536-id block, and the volumes two services share need a
   group both are in. The cost is a change of ownership on upgrade. The
   recommendation is to measure it on the Debian 13 machine first, together
   with what `SO_PEERCRED` reports across the two namespaces, and to decide
   the identity check from that measurement.
4. **Whether phase 2 waits for #1614.** The signer reuses the machinery of
   `stack certs`: the compose lock, the container check and the rollback.
   The recommendation is to wire the signer (step 4 above) only after #1614 is
   closed, while steps 2 and 3 go ahead.
5. **The storage key.** It is symmetric, so every process that writes a
   message (inbound SMTP, local delivery, the API) holds the same key as
   every process that reads one. Taking it out of inbound SMTP needs an
   asymmetric envelope: the writer encrypts to a public key and only mailbox
   access can decrypt. That is a change of the on-disk format, and the
   recommendation is a separate issue after phase 5.
6. **Memory per container.** Each new service gets a limit measured in its
   own pull request, inside the 85 % that `epistle status` warns at. The
   decision is which hosts get each service by default once it is measured;
   the recommendation is opt-in everywhere until then, as `certs` is.
7. **Rotation when the signer holds the keys.** The signer creates the keys
   and `certs` publishes them, which keeps two containers in every rotation.
   The alternative is to give key creation to `certs` and copy the private
   key to the signer, which puts the key in a container with a network. The
   recommendation is the first.
8. **The LLM classifier.** It is the only parser that needs to reach out.
   Either the sandbox gets that one egress route, or the classifier runs in a
   container of its own with egress and no other secret. The recommendation
   is the second, so the sandbox keeps no network at all.
