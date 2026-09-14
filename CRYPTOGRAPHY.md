# Cryptography background

Reference notes for the crypto primitives this service *depends on but does not design*.
SPIKE.md's thesis is explicit that "the bit the Staff role is being hired to design is the
canonical, queryable, policy-aware representation - not the signing or the crypto
primitives" (SPIKE.md:14). This doc exists so that scoping decision doesn't mean the team
is hazy on what sits underneath. It covers Sigstore **keyless** signing and verification, as
used by `actions/attest-build-provenance`, `cosign`, PyPI (PEP 740), npm.

## What you have to trust

Keyless verification gives you a trustworthy *identity for the signer*. It does **not** tell
you the signer's environment was doing what you think. The trust dependencies:

- **The CI pipeline / repository.** The signing identity is a workflow ref
  (`…/release.yml@refs/heads/main`). If someone can modify that workflow on that branch, or
  trigger it with malicious inputs, the *legitimate* workflow will sign whatever they want,
  and every crypto check below still passes. This is the gap people miss.
- **The OIDC issuer (IdP).** e.g. `token.actions.githubusercontent.com` - that it only
  issues a token with a given `sub` to the actual workflow it names.
- **Fulcio.** That it validated the OIDC token correctly and its CA key is not compromised.
- **Rekor.** For the signing timestamp and for making mis-issuance publicly detectable.
- **The trust root distribution (TUF).** That the Fulcio/Rekor/CT keys you pin are the real
  ones.
- **Your policy.** That you have decided *this specific identity string* is authoritative
  for *this* artifact.

## Signing flow (how a bundle is produced)

1. **Ephemeral keypair.** The signing client generates a keypair in memory. The private key
   never touches disk and is discarded after signing. Nothing long-lived to steal later.

2. **OIDC token.** The CI platform's OIDC provider issues the workflow a short-lived JWT
   (`header.payload.signature`, base64url). Header: `alg`, `kid`. Payload: standard claims
   (`iss`, `sub`, `aud`, `exp`, `iat`) plus provider claims - for GitHub Actions
   `repository`, `repository_owner`, `ref`, `sha`, `workflow`, `job_workflow_ref`,
   `runner_environment`, `event_name`. The client requests `aud=sigstore`.

3. **Fulcio request.** Client sends Fulcio: the OIDC token + the ephemeral public key + a
   proof-of-possession signature (a challenge - historically the token `sub` - signed with
   the ephemeral private key).

4. **Fulcio verifies the JWT cryptographically:**
   - `iss` is on Fulcio's configured issuer allowlist.
   - OIDC discovery: fetch `<iss>/.well-known/openid-configuration` → `jwks_uri` → the
     issuer's public signing keys (JWKS).
   - Verify the JWT signature over `header.payload` using the JWK whose `kid` matches.
   - Validate claims: `exp` not passed, `iat`/`nbf` sane, `aud == sigstore` (the audience
     check stops a token minted for another service being replayed to Fulcio).
   - Verify the proof-of-possession signature against the presented public key.

5. **Fulcio issues the certificate.** A short-lived X.509 leaf cert (**~10 minutes**):
   - subject public key = the ephemeral public key
   - **SAN** (URI) = the identity, derived per-issuer from the claims - for GitHub Actions
     from `job_workflow_ref`
   - **OIDC issuer extension** - OID `1.3.6.1.4.1.57264.1.8`
   - **CI claim extensions** - OIDs `1.3.6.1.4.1.57264.1.9`–`.22`: source repo URI, source
     repo digest (commit SHA), source repo ref, repo owner, build config URI + digest,
     build trigger, run invocation URI, runner environment, repo visibility at signing, …
   - signed by Fulcio's intermediate CA key (chains to the Fulcio root)
   - submitted to a CT log; the SCT is embedded in the cert

   The cert is Fulcio *asserting*: "I verified an unexpired, correctly-audienced token from
   a trusted issuer whose signature checked out against that issuer's published keys, and
   here are the claims it contained." The raw JWT is **not** retained anywhere - you trust
   Fulcio's transcription because you trust Fulcio's signature over the cert. Re-verifying
   the token later is impossible anyway (IdP keys rotate, tokens expire in minutes).

6. **DSSE envelope.** The payload to sign is an in-toto Statement:
   `{_type, subject: [{name, digest: {sha256}}], predicateType, predicate}`,
   `payloadType = application/vnd.in-toto+json`.

   DSSE does **not** sign the payload directly. It signs the **PAE** (Pre-Authentication
   Encoding) of it:

   ```
   PAE = "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
   ```

   where `LEN(x)` is the ASCII-decimal UTF-8 byte length of `x`, `SP` is a single space,
   and `payload` / `payloadType` are the exact bytes. The signature is computed over these
   PAE bytes with the ephemeral private key. Length-prefixing every field makes the
   encoding unambiguous, so the signature can't be replayed under a different `payloadType`.

   The envelope:
   ```json
   {
     "payload": "<base64(statement bytes)>",
     "payloadType": "application/vnd.in-toto+json",
     "signatures": [ { "sig": "<base64(signature over PAE)>", "keyid": "" } ]
   }
   ```

   **Consequence for storage:** re-serialising the parsed JSON changes byte length /
   whitespace / key order → different PAE → signature no longer verifies. Whatever stores
   this must keep the `payload` bytes **verbatim** (SPIKE.md's raw-store guarantee).

7. **Rekor entry.** The signing event (a hash of the envelope + the cert) is submitted to
   the Rekor transparency log. Rekor returns an inclusion proof (Merkle proof the entry is
   in the tree) and a **Signed Entry Timestamp** (SET) - Rekor's countersignature that it
   accepted the entry at time `T`. Rekor periodically publishes a signed checkpoint (signed
   tree head).

8. **Sigstore bundle.** Everything a verifier needs, packaged together
   (`application/vnd.dev.sigstore.bundle.v0.3+json`):
   - `dsseEnvelope` - payload, payloadType, signatures
   - `verificationMaterial`:
     - `certificate` - the Fulcio leaf cert (with its embedded SCT and claim extensions)
     - `tlogEntries` - the Rekor inclusion proof + SET
     - `timestampVerificationData` - any RFC 3161 timestamps

   (In older bare-DSSE form the cert could instead sit in the envelope's optional
   `signatures[].cert` field. The bundle pulls it up alongside the envelope.)

## Verification flow (what a verifier checks)

Against the trust root **as it was at signing time** - not today's (see rotation below):

1. Reconstruct the PAE from the payload bytes; verify `signatures[].sig` under the cert's
   public key.
2. Chain the cert: leaf → Fulcio intermediate → Fulcio root (pinned via TUF).
3. Establish signing time from the Rekor SET (or an RFC 3161 timestamp) and check the
   signature was made **inside the cert's validity window** - the cert is expired by the
   time you verify, so this step is what makes the 10-minute cert meaningful.
4. Verify the Rekor inclusion proof against the log; optionally the SCT against the CT log.
5. Read the SAN identity and issuer extension from the cert; check both against policy
   (identity == expected workflow ref, issuer == expected IdP).

Output is a **structured record**, not a boolean - see SPIKE.md's VERIFY section for the
fields (`signature_verified`, `chain_verified`, `sct_verified`, `tlog_verified`, `identity`,
`issuer`, `verified_at`, `trust_root`). Step 5's policy check (identity/issuer against an
expected value) is EVALUATE's job in this build, not VERIFY's - see
`models/verification.py`'s docstring.

sigstore-python's `verify_dsse` runs steps 1-4 above as one all-or-nothing call and raises a
single flat `VerificationError` with no error code on any failure, so the four check fields
above can't be read straight off a return value on the failure path. `verifier.py` classifies
which check broke from the exception's message text against an allowlist of substrings
observed at `sigstore==4.5.0`'s actual `raise` sites (message text isn't a documented contract,
so a sigstore-python upgrade can reword these without notice). A message that doesn't
unambiguously match leaves all four fields `None` rather than guessing - per
`VerificationRecord`'s None-vs-False distinction (models/verification.py), a wrong specific
`False` overclaims more than an honest "don't know."

## Trust-root rotation and re-verification

The "trust root" is the set: Fulcio CA cert(s), Rekor public key(s), CT log key(s), TSA
key(s) - distributed and versioned via **TUF** (`trusted_root.json`), each key carrying a
validity window.

These rotate (routine, or emergency after a compromise). Re-verification years later must
use the root **in force at signing time**: an old signature chains to a Fulcio root you may
have rotated out, and its Rekor SET was signed by a key since retired. TUF's per-key
validity windows let a verifier pick the right historical key for an entry's timestamp.

This is why SPIKE.md's raw store keeps verbatim bytes and records `verified_at` +
`trust_root` version per attestation: on a compromise disclosure for window `[T0, T1]`, you
can identify every attestation verified in that window and re-run full verification against
the corrected root. A stored pass/fail boolean gives you nothing to reassess.

## Key-compromise modes (brief)

- **Fulcio CA key** (in practice the online intermediate): attacker mints leaf certs that
  chain to the real root, binding *their* ephemeral key to *any* identity, with no OIDC
  token. Every identity-based policy check becomes attacker-controlled. Mitigated by: Rekor
  inclusion requirement (forces a public, timestamped, monitorable record), CT monitoring,
  and rotation + re-verification bounded by SET timestamps.
- **Rekor key**: attacker forges SETs (fake "logged at time T"), signs alternate checkpoints
  (split-view / equivocation), or backdates entries to predate a known Fulcio compromise.
  The log stops being a trustworthy witness. Mitigated by independent witnesses co-signing
  checkpoints and by clients retaining a checkpoint to demand a consistency proof against.
- **Both together (or Fulcio key + no log monitoring)**: forge the cert *and* fabricate a
  timestamped log entry, no independent contradiction. This is the scenario with no clean
  detection - the reason Sigstore is moving toward multiple independent witnesses.

## OID quick reference (Fulcio X.509 extensions)

| OID | Meaning |
|-----|---------|
| `1.3.6.1.4.1.57264.1.1` | OIDC issuer (deprecated, plain string) |
| `1.3.6.1.4.1.57264.1.8` | OIDC issuer (current, DER-encoded) |
| `1.3.6.1.4.1.57264.1.9` | Build signer URI |
| `1.3.6.1.4.1.57264.1.10` | Build signer digest |
| `1.3.6.1.4.1.57264.1.11` | Runner environment |
| `1.3.6.1.4.1.57264.1.12` | Source repository URI |
| `1.3.6.1.4.1.57264.1.13` | Source repository digest (commit SHA) |
| `1.3.6.1.4.1.57264.1.14` | Source repository ref |
| `1.3.6.1.4.1.57264.1.15` | Source repository identifier |
| `1.3.6.1.4.1.57264.1.16` | Source repository owner URI |
| `1.3.6.1.4.1.57264.1.17` | Source repository owner identifier |
| `1.3.6.1.4.1.57264.1.18` | Build config URI |
| `1.3.6.1.4.1.57264.1.19` | Build config digest |
| `1.3.6.1.4.1.57264.1.20` | Build trigger |
| `1.3.6.1.4.1.57264.1.21` | Run invocation URI |
| `1.3.6.1.4.1.57264.1.22` | Source repository visibility at signing |
