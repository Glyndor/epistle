# Recovering after a compromise

This page is for the day someone got into the server and may have read its keys or its files. It says what rotating the keys fixes, what it does not fix, in which order to work, and what to tell the users.

Start by listing every secret the server holds:

```sh
epistle rotate --all --dry-run
```

The command changes nothing. For each kind of secret it says where it is stored, how it is rotated and revoked, and what stays with the operator outside the server. Rows marked `not supported yet` link the work that is still missing.

Then, on the rebuilt server (see below), rotate what it can rotate by itself:

```sh
epistle rotate --all
```

It gives every API key and app password a new secret, replaces the webhook secret and the SRS secret of every domain that has its own, asks the server to rotate and publish every DKIM key a `[dns]` entry publishes at, and restarts the mail service. When the server runs the web panel, the panel's new key is written to the file it reads and its container is made again. It asks once before it starts, prints the new API key, app password and webhook secrets once at the end, and lists what is left to you. If it is interrupted, run it again: it continues the same run from its journal and rotates nothing twice. [The command reference](../cli.md#secrets-and-credentials-epistle-rotate) has the details.

## Rebuild first, then generate the keys

Rotating the keys on a host that is still compromised achieves nothing: whoever is inside reads the new keys as they are written. So the order is:

1. Stop the service and take a copy of the data directory for investigation. Do not repair the host.
2. Build a new server from a clean image, and install `epistle` from the package archive again.
3. Generate every new key on a clean machine, or on the rebuilt server before it is reachable from outside. That covers the DKIM, ARC, OAuth and evidence keys, the SRS and webhook secrets, and the storage key if you replace it. `epistle rotate --all` does the API keys, app passwords, webhook and SRS secrets and DKIM keys in one go; the ARC, OAuth and evidence keys are still one command or one edit each, as the dry run says.
4. Restore the mail from a backup made before the compromise, or from the copy you trust.
5. Change what lives at other parties: the DNS provider token, the database password, the relay password, the S3 access key, the LDAP bind password. Create the new credential at the provider, then revoke the old one there. `epistle` holds nothing that can revoke them.
6. Publish the new DNS records (DKIM and ARC selectors) and remove the records of the keys that were exposed. `epistle verify-dns` checks what is published.
7. Renew the TLS certificate with `epistle tls renew`, and ask the certificate authority to revoke the old one if its key was exposed.

## What rotation fixes

- **Signing as your domains.** A new DKIM or ARC key signs from then on, and mail signed with the old key stops verifying once its DNS record is removed. Until the record is removed a stolen key still signs mail that verifies, so remove it when the overlap window of the rotation ends. A new SRS secret keeps the old one as `previous_secret` for 14 days so return addresses already out still verify; remove it when you want the old secret dead.
- **Sessions and tokens.** A new OAuth signing key makes every token the old one signed stop verifying. New API keys and app passwords replace the old secrets in the same write, so every client using an old one stops working until it is given the new one.
- **Webhook receivers.** A new webhook secret stops the receiver accepting events signed with the old one.

## What rotation does not fix

- **Copies already taken.** A copy of the encrypted mail files and of the storage key stays readable forever, whatever you do afterwards. Replacing the key on your server protects the mail written after it, not the copies someone already holds.
- **Backups.** Every backup made before the rotation is still encrypted with the old keys and still holds the old credentials. Keep the old key with those backups, and destroy the backups you do not need.
- **Mail that was read, forwarded or sent.** What the intruder read stays read. Mail sent from your domains while the keys were exposed was signed as you.
- **Passwords.** The password hashes are argon2id, so a stolen hash costs work to crack, but a weak password falls. Every password in the stolen file should be treated as exposed.
- **Second factors.** The TOTP seeds are sealed with the storage key when `[storage]` encryption is on and kept in the clear when it is off. A stolen copy of `accounts.toml` with the key, or without encryption, lets its holder produce valid codes until the account enrols again.
- **Evidence.** Evidence signed with a stolen key cannot be trusted for the period the key was exposed. Rotate the key and tell whoever verifies the evidence which period to treat with care.

## What is not available yet

Two parts of the procedure are tracked in [#1497](https://github.com/Glyndor/epistle/issues/1497) and do not exist yet:

- **Replacing the storage key.** Changing only the key makes the existing mail unreadable. There is a documented path with `retired_key_files` and `epistle storage tenant-keys migrate` (see [security](../security.md#keys-per-tenant)); a re-encryption that is resumable after a crash and checks each file is still to come.
- **Resetting every credential at once.** Today it is one account at a time: `epistle account password N` for the password and `epistle account 2fa disable N` so the user enrols again. A command that does it for every account and refuses sign-in until it is done is still to come.

## What to tell the users

Send the message from a channel that does not depend on the server, because the server is the thing in doubt. Say it plainly:

- That the server was accessed by someone who should not have, when you found out, and the period during which mail stored on it may have been read.
- That they must choose a new password, and enrol their authenticator again.
- That every app password and API key was replaced, and the new ones are issued separately.
- That they should check their forwarding rules, filters and signatures for anything they did not set.
- That messages claiming to come from the server and asking them to sign in through a link are not from you. Give them the address to type, not a link.
- Who to write to if they see something strange.

Do not tell them what is not true: if you cannot say what was read, say that, and say what you did to find out.
