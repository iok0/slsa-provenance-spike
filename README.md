# Provenance Ingestion Spike

A spike into the hard parts of ingesting software supply-chain attestations (SLSA provenance,
in-toto, Sigstore bundles), verifying them, and turning them into trust decisions that an
artifact registry can store and query.

> Standards and ecosystem tooling provide the evidence and the verification mechanisms.
> This service turns that evidence into a canonical, queryable, policy-aware representation
> associated with the platform's artifacts.

One path is built in depth and tested against two real, independently signed Sigstore bundles.
Everything else is designed, with its boundary written down. The full write-up, covering
rationale, findings, API output and open questions, is in [DESIGN.md](DESIGN.md).

## The model: evidence → facts → decisions

```
RAW EVIDENCE        "someone asserted X"       DSSE envelope, stored as verbatim bytes
      │  verify (crypto)  +  normalise (schema), both read from the raw bytes
VERIFIED FACTS      "we verified X"            signer identity, Fulcio cert claims,
      │                                        builder_id, source repo + revision
      │  policy
DECISIONS           "we therefore trust X"     ALLOW / DENY + reasons + policy_version
```

"Asserted", "verified" and "trusted" are three separate states, and no layer may claim more
certainty than the one beneath it earned. The code enforces this:

- **Raw bytes are kept forever, keyed by content hash.** When a trust root rotates or a
  normaliser is fixed, the whole corpus can be re-verified or re-normalised from the original
  bytes.
- **Verification produces a per-check record.** Each check (signature, chain, SCT, tlog) is
  `None` for "not reached" or `False` for "checked and failed", and the record is stamped with
  the trust root it was checked against. Verification runs with sigstore-python's
  `UnsafeNoOp` policy: it proves the cryptography and asserts nothing about who signed.
- **Normalised facts never travel without their verification record.**
- **Every decision is stamped with the `policy_version` that produced it.**

## What's built

| Stage | Status |
|---|---|
| Raw store + verify from raw | Built. Content-addressed and idempotent; verification reads only stored bytes |
| Normalise | Built. SLSA v0.2 and v1.0 adapters onto one canonical model, with adapter version tracked separately from spec version |
| Evaluate | Built as a plain Python function. The input-document contract is the point; OPA/Cedar can sit behind it later |
| Associate | Thin stub, keyed by `(tenant_id, digest)` so lookups can't cross tenants |
| Expose | One FastAPI route: provenance and trust decision by artifact |
| SBOM, corpus-wide policy, re-verification cadence | Design only |

## Findings from the real bundles

The fixtures are ruff 0.16.7 (SLSA v1.0, GitHub `attest-build-provenance`) and scorecard 5.5.0
(SLSA v0.2, `slsa-github-generator`). Both were captured from their public sources.

1. **SLSA level is not in the attestation.** It's a property of the build platform, claimed
   outside the attestation. Policy derives it from an allowlist of verified builder identities.
2. **`builder_id` is self-asserted.** It's a string the signer wrote into its own payload. Policy
   trusts it only when it equals the certificate's verified signer identity. Without that
   check, any GitHub Actions run could claim an allowlisted builder. This gap was found in
   review and fixed.
3. **The Fulcio cert outranks the predicate.** Fulcio copies CI claims (runner environment,
   source repo, commit) from GitHub's signed OIDC token into the cert. Where cert and predicate
   both make a claim, the cert decides and a contradiction is a DENY. With a reusable workflow,
   though, the cert describes the generator's job rather than the build job, so its runner
   claim can't confirm build isolation.
4. **Both real fixtures are denied, for different reasons.** ruff was built on a *self-hosted*
   runner, which falls outside GitHub's Build L3 isolation guarantee. scorecard's evidence can't
   confirm its runner at all. Policy fails closed. The ALLOW path is covered by labelled,
   constructed test evidence.
5. **The spec doesn't match the bytes.** The v1.0 predicate type is `.../provenance/v1`, not
   `v1.0`. Build timestamps are absent from both predicates. One artifact had two attestations
   of different predicate types, and a sha1 subject sat next to sha256 ones.

Flipping one byte of a stored payload breaks verification and produces a new content address.
That test runs against the real bundle.

## Known gaps

- **Live trust root in the tests.** Verification fetches the current TUF trust root, so a
  rotation could break CI. The fix is a pinned `trusted_root.json` loaded through the existing
  `offline` flag.
- **No source binding.** Any repo using an allowlisted generator passes the builder check. The
  cert claims needed to fix this are already recorded.
- **Not yet designed:** decision drift when a policy changes, a waiver workflow, and OCI
  index-vs-manifest association. These and others are listed in DESIGN.md.

## Running it

```
uv sync --locked --extra dev
uv run pytest -v          # 58 tests; verification hits the network for the TUF root
uv run python scripts/run_demo_api.py
curl http://127.0.0.1:8000/v1/provenance/acme/sha256:73894c7b7c9a53fd66ed715eb3a1ec65077f316328e377057a98bdb7fcba0326
```

## Docs and layout

- [DESIGN.md](DESIGN.md): full design, findings, API output, production seams, open questions
- [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md): Sigstore keyless-signing background
- [TESTING.md](TESTING.md): test list, real vs constructed evidence, mutation testing

```
src/provenance/   raw_store/  verify/  normalize/  policy/  associate.py  api/  models/
tests/fixtures/   two real Sigstore bundles, each with a meta.json chain-of-custody sidecar
```

Built with Python, FastAPI, sigstore-python (exact-pinned) and Pydantic. I wrote a spec first
(not included here), then built the code with Claude Code and reviewed it iteratively.
DESIGN.md describes the design as built.

MIT licensed. See [LICENSE](LICENSE).
