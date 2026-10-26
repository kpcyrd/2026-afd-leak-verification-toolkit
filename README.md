# 2026 AFD Leak Verification Toolkit

This toolkit is designed to cryptographically verify the authenticity of emails
by checking their DKIM signatures.

**This repository does not contain any email data!**

## What is DKIM

DKIM is an email authentication method designed to detect forged sender
addresses in emails, and is commonly used by email providers to prevent email
spoofing and phishing attacks.

As a byproduct, this produces a cryptographic papertrail allowing independent
verification of the leaked email's authenticity.

The signatures do not prove the email was sent by a specific person, but they
are a strong indicator the emails were sent through the respective email server.

The `verify` command in this toolkit reports 3 possible results per email:

- **DKIM PASS**: The email's DKIM signature has been successfully verified,
indicating the email has been cryptographically signed by the respective email
server and has not been tampered with.
- **DKIM FAIL**: The email's DKIM signature could not be verified, even though
at least one public key has been archived for the respective DKIM selector. See
below for details.
- **DKIM MISSING PUBLIC KEY**: The email's DKIM signature could not be verified
because the public key referenced in the email's DKIM selector is not available
in the archive (please send a pull request if you have a copy of the missing
public key).

Possible reasons for **DKIM FAIL** include:

- Due to a bug in my verification code (most likely)
- The public key in DNS has been modified since, and we don't have the old
public key archived (yet)
- The email has been modified after signing
- The email server was misconfigured and genuinely produced a bogus DKIM
signature

## About trusting the DKIM public key archive

The keys in `dkim/` are collected in good faith on best-effort basis from
sources like live DNS data and community contributions. The archive may include
keys that are no longer published in DNS, including keys whose removal may be
relevant for forensical analysis of historical email records.

The archive is intended as a useful reference, but independent verification
against authoritative DNS data and other email archive records is recommended.

## Usage

Fetch the source code and compile the tool:

```bash
git clone https://github.com/kpcyrd/2026-afd-leak-verification-toolkit.git
cd 2026-afd-leak-verification-toolkit
cargo build --release
# Optionally, to avoid copying the full path every time you run the tool
cp ./target/release/afd-leak-verification-toolkit .
./afd-leak-verification-toolkit --help
```

Alternatively, pull the code from seeders in the radicle network:

```
rad clone rad:z2whGjakKzs4D3wex4J4Mw24CVvCL 2026-afd-leak-verification-toolkit
```

### List mbox contents

For a quick sanity check, use this command to scan through an mbox file (processing about 1gb/sec):

```bash
# Print metadata for each email
./afd-leak-verification-toolkit ls emails.mbox
# Print only sender, subject and message-id header
./afd-leak-verification-toolkit ls -fsi emails.mbox
# Print metadata as JSON, but only of emails with DKIM signatures
./afd-leak-verification-toolkit ls --dkim-only --json emails.mbox
```

### Verify DKIM signatures

To verify DKIM signatures for an entire inbox, use one of the following commands:

```bash
# Human-readable output
./afd-leak-verification-toolkit verify emails.mbox
# JSON output
./afd-leak-verification-toolkit verify --json emails.mbox
```

### Populate DKIM archive

The verification step works offline, using a local DKIM public key archive
(`./dkim/`). To (re-)populate the archive from live DNS data:

```bash
./afd-leak-verification-toolkit fetch-dkim emails.mbox
```

To rebuild the archive from scratch, you can remove the existing `./dkim/`
directory and then run the `fetch-dkim` command again:

```bash
rm -r ./dkim/
./afd-leak-verification-toolkit fetch-dkim ./*/*.mbox
```

At the time of writing, if a file exists in the `./dkim/` directory, the
`fetch-dkim` command will not re-fetch it from DNS, even though it may have
changed.

The archive supports storing multiple DKIM public keys for the same selector
however, one key per line.

## License

The code in this repository is licensed under the `MIT-0` license, which is the
MIT license without the attribution clause.

The DKIM verification library (`viadkim`) is licensed under the `GPL-3.0`
license, if you were to compile this into a binary and distribute it, the
resulting binary would be subject to the `GPL-3.0` license.
