# Provenance Ingestion Spike

A short spike exploring the hard parts of ingesting, verifying, and making trust decisions
about software supply-chain attestations (SLSA provenance, in-toto, Sigstore bundles) - the
kind of evidence CI/CD systems and package registries produce today, and that a platform
sitting in the middle of software distribution needs to turn into something queryable and
trustworthy.

Goal: explore the hard parts of the problem properly, not build all of it. One thing is built
deep; everything else is designed and named honestly as not built.

## Summary

Software gets built by pipelines, signed, and shipped. This service checks that a signature
is real, records what it proves and how sure we are, and turns that into a simple decision -
allow it or don't, with reasons - that can be queried later without redoing the cryptography.
It keeps the original signed evidence forever, so if a signing method or trust source is later
found to be compromised or replaced, the whole corpus can be rechecked against the new
information instead of trusting a stored pass/fail verdict from the past.

## Thesis

> Standards and ecosystem tooling provide the evidence and the verification mechanisms.
> This service turns that evidence into a canonical, queryable, policy-aware representation
> associated with the platform's artifacts.

Everything below is in service of demonstrating that sentence. The interesting design problem
is the "canonical, queryable, policy-aware representation" layer - not the signing or
cryptographic primitives underneath it, which are covered as background in
[CRYPTOGRAPHY.md](CRYPTOGRAPHY.md).

What that sentence cashes out to, concretely, in what's built here - and what each is meant
to demonstrate:

- **Content-addressed immutability** - designing for replay as trust and policy evolve. Raw
  DSSE bytes are stored verbatim, addressed by their own digest, never rewritten - the reason
  a signature can still be re-verified against a rotated trust root, or re-normalized by a
  newer adapter version, years later.
- **Version-aware normalization** - integrating an evolving external standard without coupling
  the domain model to either version. SLSA v0.2 and v1.0 predicates - materially different
  shapes, not just field renames - project onto one stable canonical model via per-version
  adapters, with the adapter's own version tracked separately from the spec version it targets.
- **Identity-bound policy evaluation** - separating verification, normalization, and policy so a
  self-asserted field can never allowlist itself. `builder_id` - the one field in the signed
  payload that policy allowlists on - is only trusted once it's checked against the identity
  the cryptography actually verified.
- **Real-evidence testing and named scope boundaries.** Every claim above is checked against
  two independently-signed real Sigstore bundles, not synthetic fixtures, and everything not
  built (SBOM, corpus policy, a wired policy engine) is named as a scoping decision rather than
  left implicit.

## The problem

An artifact registry that sits in the middle of how organizations store and distribute
software is well placed to answer two questions enterprise customers actually ask: *what
build produced this artifact, and can I trust it?* Doing that well means ingesting attestation
payloads that arrive in a genuinely varied, schema-evolving shape - different predicate
specs, different spec versions, different packaging conventions, from CI systems the platform
doesn't control - verifying their cryptographic integrity without reimplementing Sigstore,
and evaluating them against a customer's trust policy (SLSA level, allowed builder identity,
signing issuer) without pretending a policy engine and a corpus query engine are the same
kind of thing. All of that has to happen without ever letting a downstream layer imply more
certainty than the layer beneath it actually earned - an unverified field surfaced next to a
verified one, styled the same way, is a real way to mislead a security team relying on this
data for an admission decision.

## The core conceptual model: evidence → facts → decisions

Three layers that must not be conflated. Keeping them separate *is* the design, and it's
enforced in code here, not just described in this prose - see "what's actually enforced,
not just described" below.

```
RAW EVIDENCE                 "someone asserted X"
  DSSE envelope (verbatim bytes)
  SBOM attestation
  Sigstore bundle
        │
        ▼   verify + normalise
VERIFIED FACTS               "we verified X"
  from verification:
    artifact_digest(s)
    signing identity + issuer
    verification result (+ when, + against which trust root)
  from normalization (per-version adapters):
    builder_id, build_type
    source_repo, source_revision
        │
        ▼   policy
DERIVED DECISIONS            "our organisation therefore trusts X"
  trusted builder / SLSA level met
  policy = ALLOW / DENY + reasons
```

- Raw evidence is **authoritative** as a record of what was asserted, and immutable - not a
  claim that the assertion is true. Everything else is a derived projection.
- "Asserted", "verified", and "trusted" are three different states. The service's job is to
  move evidence through them without a downstream layer implying more certainty than the
  layer beneath it earned.
- The middle layer is fed by two operations, not one: verification establishes the
  *certainty* (and is the only thing that moves a fact from "asserted" to "verified"),
  normalization establishes the *shape*. Normalization changes representation, not
  certainty status - an adapter-extracted `builder_id` is exactly as trustworthy as the
  verification record attached to it, and must never be surfaced without it.
- A verification record is stamped with the `trust_root` it was checked against so a later
  re-check doesn't silently use today's (rotated) root in place of the root actually in force
  at verification time; a **decision** is stamped with the `policy_version` that produced it
  for the same reason. An ALLOW issued under last quarter's policy and an ALLOW issued under
  today's are not the same fact wearing the same label.

## Scope: six stages

A lifecycle view for readability, not the architecture - the architecture is the three-layer
model above. The only genuinely fixed ordering is that verification and normalization both
consume the raw record; verification and *association* are independent and either can arrive
first.

```
INGEST     Receive a real DSSE / in-toto / SLSA attestation
VERIFY     Cryptographic verification via Sigstore tooling (sigstore-python)
ASSOCIATE  Resolve independently-arriving evidence to platform artifact identity (late-binding)
NORMALISE  Extract builder / source / build facts into a canonical model (per-version adapters)
EVALUATE   Apply a small trust policy (two-tier: per-subject + corpus-wide)
EXPOSE     API showing provenance + trust decision
```

```
                         External Evidence
                                │
                ┌───────────────┼───────────────┐
                │               │               │
             SLSA/in-toto     SBOM          Signature
                │               │               │
                └───────────────┼───────────────┘
                                ▼
                         ┌─────────────┐
                         │   INGEST    │
                         └──────┬──────┘
                                ▼
                         Raw Evidence
                          (immutable)
                                │
                                ▼
                         ┌─────────────┐
                         │   VERIFY    │
                         │  Sigstore   │
                         └──────┬──────┘
                                ▼
                    ┌───────────────────────┐
                    │      ASSOCIATE        │
                    │ artifact digest /     │
                    │ tenant / late binding │
                    └───────────┬───────────┘
                                ▼
                         ┌─────────────┐
                         │  NORMALISE  │
                         │ versioned   │
                         │ adapters    │
                         └──────┬──────┘
                                ▼
                    Canonical Provenance Facts
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
             Per-subject policy      Corpus projection
                (sync)                   (async)
                    │                       │
                    └───────────┬───────────┘
                                ▼
                             EXPOSE
```

VERIFY → ASSOCIATE is linearised above for readability but the two are independent: digest
association needs no crypto, and either side can arrive first. VERIFY and NORMALISE are a
different case - not independent, but not sequential either: both read the same raw bytes as
two separate operations, neither waiting on or feeding the other, and only merge again at
policy time:

```
                         ┌───────────────────┐
                         │    RAW EVIDENCE    │
                         │  (verbatim bytes)  │
                         └──────────┬─────────┘
                                    │
                    ┌───────────────┴────────────────┐
                    ▼                                 ▼
           verify (cryptographic)            normalise (schema, per version)
                    │                                 │
                    ▼                                 ▼
      ┌───────────────────────────┐     ┌───────────────────────────┐
      │     VerificationRecord    │     │     CanonicalProvenance    │
      │ signature/chain/sct/tlog  │     │  builder_id, build_type,   │
      │ identity, issuer (facts,  │     │  source_repo, revision,... │
      │ not yet trust decisions)  │     │  (facts, not yet decisions)│
      └───────────────┬───────────┘     └───────────────┬───────────┘
                       │                                 │
                       └────────────────┬────────────────┘
                                         ▼
                              EVALUATE (policy)
                     builder_id trusted only if it matches
                       the verified identity above it
                                         ▼
                          Decision: ALLOW/DENY + reasons
                              + policy_version
```

Both branches produce *facts*, not trust - `identity` is what the certificate says, not an
endorsement; `builder_id` is what the payload says about itself. Only EVALUATE, reading both
records together, turns them into a decision, and only after checking one against the other
(see "a real gap, found after the fact" below for why that check exists at all).

Correlation is demonstrated simply here - a fan-out, not a lineage graph:

```
Artifact
   |-- Provenance
   |-- Signature
   |-- SBOM
   |-- Consumption   (out of scope - see below)
```

## What I built vs. designed

Six stages + two possible deep dives + several milestones is not a short build that ends up
genuinely good - a half-working sprawl would undersell the point more than a narrow, excellent
slice. So: **one built spine, everything else designed with the seams named.**

| Stage | Status |
|---|---|
| **VERIFY + raw store** | **Built.** Deep dive 1 - see below. |
| **NORMALISE** | **Built.** Deep dive 1 - SLSA v0.2 *and* v1.0, versioned adapters. |
| EVALUATE | Built, but as a plain Python predicate function, no policy engine - the input-document contract is the artifact (deep dive 2, design-first). |
| ASSOCIATE | Built as one thin function against a hand-seeded stub table - the design is real, the code is a stand-in on purpose. |
| INGEST | Not a real pipeline - `api/demo_bootstrap.py` seeds the store directly from fixture files. Idempotency dedupe *is* real (raw store's content addressing); poison-payload handling and dead-lettering are named, not built. |
| EXPOSE | Built - one FastAPI route, by-artifact lookup. |
| SBOM | **Not built at all** - see "What I deliberately didn't build." |
| Corpus-wide policy, multi-tenancy beyond a `tenant_id` column, re-verification cadence | Design only. |

### Deep dive 1 (built): raw-preserving store + versioned normalizer

These two pieces share one load-bearing idea, and that idea is the thesis: **verbatim raw
payload bytes are what make everything else replayable later.** The same stored bytes let you
(a) re-run PAE signature verification years later against a rotated trust root, and (b) re-run
a newer normalizer version over evidence ingested before that version existed. One design
decision, two payoffs.

**Raw store** (`raw_store/store.py`): a content-addressed, effectively-immutable store of raw
envelope bytes, keyed by `sha256` of the exact bytes. `put()` is idempotent - storing identical
bytes twice is a no-op, because the digest of the content *is* the dedupe key. Two-level
directory fan-out so the store doesn't become one flat listing as the corpus grows. Production
seam: this becomes S3, tenant-partitioned; the interface is three methods on purpose so that
swap is a backend change behind an unchanged call site.

**Verify from raw** (`verify/verifier.py`): cryptographic verification only - signature over
PAE, cert chain to the Fulcio root, SCT, Rekor inclusion - sourced from bytes read back *from
the store*, never from whatever the caller originally handed in. That's what makes "verify
from raw" a guarantee rather than a convention. Identity (cert SAN) and issuer (OIDC issuer
extension) are *extracted* as facts, independent of whether verification passed; deciding
whether an identity is *trusted* is EVALUATE's job, not VERIFY's. Concretely, this runs
sigstore-python's own `policy.UnsafeNoOp()` - its own name for "prove the crypto, assert
nothing about who signed it" - deliberately, not by omission. It's a precise, one-line proof,
straight from the dependency's own vocabulary, that verification and trust-of-identity are
kept apart in code, not just described as separate in prose.

**Verification result is a structured record, not a boolean** (`models/verification.py`):
`signature_verified`, `chain_verified`, `sct_verified`, `tlog_verified`, `identity`, `issuer`,
`verified_at`, `trust_root`. A field is `None` when that check was never reached or can't be
confirmed to have run - distinct from `False`, which means the check specifically ran and
failed; collapsing "unknown" into "failed" would let the record imply more certainty than
verification actually earned. This is enforced by the exception-handling branch in
`verifier.py`, not just declared in a docstring - `sigstore-python` raises one flat,
undocumented exception on any verification failure, so the branch has to classify which check
broke from the exception's own message text (mechanics, and the library-upgrade fragility that
implies, are in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md)).

**Normalize SLSA provenance v0.2 and v1.0** (`normalize/v0_2.py`, `normalize/v1_0.py`): one
adapter per `(predicateType, version)` into a stable canonical Pydantic model
(`models/provenance.py`). This is the point, not an extension - see the rationale below. The
raw record retains the full predicate; unmapped fields surface via `raw_unmapped` as a debugging
convenience only - the completeness guarantee is the verbatim raw record, not this field (size
asymmetry between the two is a concrete data point under Demo).

**Adapter version is a separate axis from predicate spec version.** A canonical record carries
`adapter_id` + `adapter_version` (the code that produced it) distinct from `predicate_type` /
`predicate_version` (the spec it was produced from), because an adapter can get a bug fix -
e.g. a corrected source-extraction rule for one build type - without the underlying SLSA spec
changing at all. Re-running a newer adapter over old raw evidence needs to know which adapter
version made the record it's superseding, not just which spec version the predicate claims.

#### Why v0.2 + v1.0 is core, not an extension

Normalizing only one predicate shape would make the normalizer look trivial and imply the two
spec versions map mechanically onto each other. They don't:

| v0.2                              | v1.0                                    | notes |
|-----------------------------------|-----------------------------------------|-------|
| `predicateType .../provenance/v0.2` | `predicateType .../provenance/v1`     | mechanical (exact string differs - see corrections below) |
| `builder.id`                      | `runDetails.builder.id`                 | mechanical |
| `buildType` (top level)          | `buildDefinition.buildType`             | mechanical, relocated |
| `materials[]`                    | `buildDefinition.resolvedDependencies[]` | mechanical; entry shape gains optional fields |
| `metadata.buildInvocationID`     | `runDetails.metadata.invocationId`      | mechanical (naming quirk - see corrections below) |
| `metadata.buildStartedOn`        | `runDetails.metadata.startedOn`         | mechanical; absent from both real fixtures |
| `invocation.configSource`        | `buildDefinition.externalParameters` (+ a `resolvedDependencies` entry) | **not mechanical** - build-type-specific, not SLSA-defined |

`source_repo` / `source_revision` extraction is therefore **build-type-specific** in v1.0. For
GitHub Actions (`https://actions.github.io/buildtypes/workflow/v1`) the source is in
`externalParameters.workflow.repository` plus a `resolvedDependencies` entry; in v0.2's GitHub
generator it was `invocation.configSource`. Each adapter hides a per-build-type extractor, and
the v1.0 adapter raises a named `UnsupportedBuildType` for anything but the one buildType this
repo has a real fixture for, rather than guessing at an unfamiliar shape.

Every extraction rule in both adapters is pinned against the **real captured fixtures** in
`tests/fixtures/bundles/`, not against the table above or the SLSA spec from memory - three
corrections only found by looking at actual bytes:

- The real v1.0 predicate type string is `.../provenance/v1`, not the more readable
  `.../v1.0` some docs use.
- v0.2's build-invocation-id field is `metadata.buildInvocationID` - capital "ID".
- `metadata.buildStartedOn` / `buildFinishedOn` don't exist in either real predicate at all.
  `started_at` / `finished_at` stay `None` - no fallback invented for a field that's genuinely
  absent (Rekor's `integratedTime` is a *signing* time, not a *build* time, and reusing it here
  would misrepresent what the field means).

### Deep dive 2 (design-first, thin build): two-tier trust policy

The separation is the point. `policy/evaluate.py` is a plain Python predicate function over a
hand-defined input document (`EvidenceItem` = normalized facts + verification result + a raw
pointer, per attestation) - no policy engine wired at all. OPA (or Cedar, or CEL) is future
work, struck from this spike deliberately: it can be dropped in later without touching the
input-document contract, which is the actual artifact here.

- **Per-subject (admission-time) policy** is a pure function of an artifact's *evidence set*,
  not a single bundle in isolation - admission-relevant facts that don't exist when each
  attestation is evaluated alone. "Provenance present but SBOM missing" is the motivating
  example for why, but it's illustrative only: no SBOM evidence type exists in this build (see
  "what I deliberately didn't build" below), so nothing here actually checks it. The one
  set-level check that's real is two provenance attestations disagreeing on builder identity -
  and even that is only reachable by a constructed test, since both real fixtures are singleton
  evidence sets. Synchronous, runs on ingest. The decision is stamped with the `policy_version`
  it was evaluated against, same discipline as `trust_root` on the verification record it
  consumed.
- **"SLSA level met" is not a field in the attestation.** Neither SLSA v0.2 nor v1.0 provenance
  carries an explicit level - level is a property of the *build platform* (isolation,
  non-falsifiable provenance generation), asserted out-of-band by whoever operates it (GitHub
  documents that GitHub-*hosted* Actions runners meet Build L3; that claim lives nowhere in the
  attestation itself). So the canonical model correctly has no `slsa_level` field - level comes
  from mapping the verified `builder_id` against a maintained allowlist (`_BUILDER_ALLOWLIST`
  in `evaluate.py`), not from reading it off the predicate.
- **`builder_id` is only trustworthy if it matches who actually signed.** `builder_id` is
  NORMALISE output - a string read verbatim out of the *signed payload's content*. Verification
  proves who held the signing key; it proves nothing about whether that identity was entitled
  to write this particular `builder_id` into its own predicate. `_evaluate_item` requires
  `builder_id == item.verification.identity` before trusting an allowlist hit at all - see
  "a real gap, found after the fact" below for how this got caught.
- **Corpus-wide (aggregate) policy** - a fold over the whole corpus ("no artifact without
  provenance," "all prod releases signed by builder X") - is design-only here, not wired.
  Different latency SLA and failure modes than per-subject; needs an incrementally-maintained
  projection (a `provenance_facts` table updated on ingest) plus scheduled/event-driven
  re-evaluation producing a **violations feed**. A policy engine is not a corpus query engine -
  it decides over the context it's handed and doesn't scan or join across an external corpus,
  so corpus-scale policy needs a query/projection layer that reduces the corpus to decision
  context *before* evaluation. This is why the normalized projection exists, and why policy
  can't run over a million raw envelopes per pass - though it also caps corpus-policy
  expressiveness at mapped fields, noted under Open questions.

  The evidence set itself is a **named, queryable grouping**, keyed by
  `(tenant_id, artifact_digest)`, not an implicit per-evaluation join - the corpus projection
  needs the same grouping, so materialising it once avoids defining it twice.

One-line framing: *the normalized projection is the contract between synchronous per-subject
decisions and asynchronous corpus queries.*

## What's actually enforced, not just described

A few places where the evidence→facts→decisions discipline above isn't just prose - it's a
property the code makes hard to violate:

- `VerificationRecord`'s `None` (not reached) vs. `False` (checked and failed) split is
  enforced by the exception-handling branch in `verifier.py`; the code never backfills a
  guessed `False` for a check that was never attempted.
- VERIFY runs with sigstore-python's `UnsafeNoOp` policy - asserting no identity - so identity
  *trust* structurally cannot leak into the verification step.
- `CanonicalProvenance` is never returned or stored without an `EvidenceItem` wrapper carrying
  its `VerificationRecord` alongside it (`models/evidence.py`) - there's no code path that
  surfaces normalized facts unaccompanied by the certainty they were built from.
- `associate()`'s stub table is keyed by `(tenant_id, digest)`, not `digest` alone - a lookup
  can never cross tenants even if two tenants coincidentally reference the same bytes. Tested
  directly: `test_known_digest_wrong_tenant_is_404_not_leaked`.

## A real gap, found after the fact: `builder_id` was never bound to the verified signer

Worth stating plainly rather than glossing over, because it's the most concrete evidence in
this repo that the "don't let a downstream layer imply more certainty than it earned" rule is
easy to violate even while trying to follow it.

`_evaluate_item` originally allowlisted `item.provenance.builder_id` directly. That field is
NORMALISE output - a string read verbatim out of the *signed payload's content*. Verification
proves who held the signing key; it proves nothing about whether that identity was entitled to
write this particular `builder_id` into its own predicate. Since the acceptable-issuer set is
GitHub's OIDC issuer for *every* repo on GitHub, not one scoped to a trusted org, the original
check reduced to "signed by some GitHub Actions run, whose payload happens to contain an
allow-listed `builder_id` string" - not "built by the allow-listed builder." Exactly the
certainty-inflation failure the rest of this design exists to avoid, and unlike every other
scoping decision in this repo, this one wasn't named anywhere before it was pointed out in
review.

It stayed invisible against both real fixtures because GitHub-native `attest-build-provenance`
and `slsa-github-generator`'s reusable workflow both generate provenance in a context the
calling job can't write to - `identity` (the cert SAN) and `builder_id` (the payload's own
self-assertion) are equal by construction for both. The gap only shows up for a builder that
lets the calling job set its own `builder_id`, which neither real fixture exercises.

Fix: `_evaluate_item` now requires `builder_id == item.verification.identity` before trusting
an allowlist hit at all, denying otherwise
(`tests/test_policy.py::test_constructed_builder_id_identity_mismatch_is_denied` - constructed,
since neither real fixture reaches this branch either).

## Demo

Two things to look at directly rather than take on faith. Both are real pytest output and a
real API response from this repo, run against two independently-signed real bundles:

- **ruff 0.16.7**, linux-x86_64 release tarball - SLSA **v1.0**, signed by GitHub-native
  `actions/attest-build-provenance`, fetched read-only via `gh api
  repos/astral-sh/ruff/attestations/{digest}`.
- **scorecard 5.5.0**, darwin-amd64 release tarball - SLSA **v0.2**, signed by
  `slsa-framework/slsa-github-generator`'s reusable workflow, fetched read-only via a plain
  HTTPS GET of the public release asset. (Its asset is still named `multiple.intoto.jsonl` for
  historical reasons - the current release actually ships exactly one line / one subject,
  confirmed by counting newlines before writing the fixture, not by trusting the filename.)

Both fixtures ship with a `meta.json` sidecar recording source, endpoint/URL, subject digest,
and `fetched_at` - chain-of-custody applied to the repo's own test evidence.

### Demo moment 1: two independently-signed real bundles converge on the same canonical shape

The versioned-adapter claim, made concrete: different predicate spec (v0.2 vs. v1.0),
different builder identity, different signing workflow - normalized into the same
`CanonicalProvenance` shape with semantically equivalent facts populated.

| field | ruff (v1.0) | scorecard (v0.2) |
|---|---|---|
| `predicate_type` | `https://slsa.dev/provenance/v1` | `https://slsa.dev/provenance/v0.2` |
| `adapter_id` | `slsa_provenance_v1_0` | `slsa_provenance_v0_2` |
| `builder_id` | `.../ruff/.github/workflows/release.yml@refs/heads/main` | `.../slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0` |
| `build_type` | `https://actions.github.io/buildtypes/workflow/v1` | `https://github.com/slsa-framework/slsa-github-generator/generic@v1` |
| `source_repo` | `https://github.com/astral-sh/ruff` | `git+https://github.com/ossf/scorecard@refs/tags/v5.5.0` |
| `source_revision` | `b5dba861cc38e3f7fb4524c9ceba3e01a474ea13` | `c395761df6afe1a69e476bc60a013a94bcbc153f` |
| `invocation_id` | full run URL | opaque `{run_id}-{attempt}` string |

Two independently-signed real bundles, two different predicate specs, converging on one shape.
Real pytest output (`tests/test_raw_store_and_verify.py`, `tests/test_normalize.py`):

```
tests/test_raw_store_and_verify.py::test_put_is_content_addressed_and_idempotent PASSED [ 20%]
tests/test_raw_store_and_verify.py::test_verify_from_raw_succeeds_on_real_bundle PASSED [ 40%]
tests/test_raw_store_and_verify.py::test_verify_from_raw_succeeds_on_second_real_bundle_different_slsa_version PASSED [ 60%]
tests/test_raw_store_and_verify.py::test_byte_flip_breaks_verification PASSED [ 80%]
tests/test_normalize.py::test_v0_2_and_v1_0_converge_on_the_same_canonical_shape PASSED [100%]

============================== 5 passed in 2.47s ===============================
```

### Demo moment 2: flip one byte of the stored payload, verification fails

Proves the raw store's integrity guarantee is real, not just content-addressed bookkeeping.
`tests/test_raw_store_and_verify.py::test_byte_flip_breaks_verification` stores a real bundle,
flips one character deep inside the base64-encoded DSSE payload (which changes the decoded
statement bytes, which changes the PAE, which invalidates the signature computed over the
original PAE), re-stores the tampered bytes (getting a *different* content address, as the
raw-store model says it should), and asserts verification now fails:

```
tests/test_raw_store_and_verify.py::test_byte_flip_breaks_verification PASSED [100%]
```

Full suite, for completeness - 21 tests, all against the two real fixtures above or explicitly
labeled constructed evidence:

```
tests/test_api.py::test_get_provenance_for_known_ruff_artifact PASSED    [  4%]
tests/test_api.py::test_get_provenance_for_known_scorecard_artifact PASSED [  9%]
tests/test_api.py::test_unknown_digest_for_known_tenant_is_404 PASSED    [ 14%]
tests/test_api.py::test_known_digest_wrong_tenant_is_404_not_leaked PASSED [ 19%]
tests/test_normalize.py::test_adapt_v0_2_matches_real_scorecard_fixture PASSED [ 23%]
tests/test_normalize.py::test_adapt_v1_0_matches_real_ruff_fixture PASSED [ 28%]
tests/test_normalize.py::test_v0_2_and_v1_0_converge_on_the_same_canonical_shape PASSED [ 33%]
tests/test_normalize.py::test_unsupported_predicate_type_raises PASSED   [ 38%]
tests/test_normalize.py::test_unsupported_v1_0_build_type_raises PASSED  [ 42%]
tests/test_policy.py::test_real_ruff_fixture_denied_for_self_hosted_runner PASSED [ 47%]
tests/test_policy.py::test_real_scorecard_fixture_denied_for_missing_signal PASSED [ 52%]
tests/test_policy.py::test_constructed_github_hosted_evidence_is_allowed PASSED [ 57%]
tests/test_policy.py::test_constructed_issuer_mismatch_is_denied PASSED  [ 61%]
tests/test_policy.py::test_constructed_builder_id_identity_mismatch_is_denied PASSED [ 66%]
tests/test_policy.py::test_constructed_unverified_evidence_is_denied PASSED [ 71%]
tests/test_policy.py::test_constructed_conflicting_builder_identities_in_one_set_is_denied PASSED [ 76%]
tests/test_policy.py::test_empty_evidence_set_is_denied PASSED           [ 80%]
tests/test_raw_store_and_verify.py::test_put_is_content_addressed_and_idempotent PASSED [ 85%]
tests/test_raw_store_and_verify.py::test_verify_from_raw_succeeds_on_real_bundle PASSED [ 90%]
tests/test_raw_store_and_verify.py::test_verify_from_raw_succeeds_on_second_real_bundle_different_slsa_version PASSED [ 95%]
tests/test_raw_store_and_verify.py::test_byte_flip_breaks_verification PASSED [100%]

============================== 21 passed in ~8s ===============================
```

### What the API actually returns

`GET /v1/provenance/acme/sha256:73894c...` (the real ruff fixture) - the full, real response:

```json
{
  "artifact": {
    "tenant_id": "acme",
    "repo": "acme-tools",
    "format_namespace": null,
    "package": "ruff",
    "version": "0.16.7",
    "file": "ruff-x86_64-unknown-linux-gnu.tar.gz"
  },
  "association_basis": "sha256:73894c7b7c9a53fd66ed715eb3a1ec65077f316328e377057a98bdb7fcba0326",
  "provenance_records": [
    {
      "raw_digest": "51bd5bab704bd4f6fa6501f090bb5eb2c1338bfe8917a941f218a2560a836a28",
      "verification": {
        "raw_digest": "51bd5bab704bd4f6fa6501f090bb5eb2c1338bfe8917a941f218a2560a836a28",
        "signature_verified": true,
        "chain_verified": true,
        "sct_verified": true,
        "tlog_verified": true,
        "identity": "https://github.com/astral-sh/ruff/.github/workflows/release.yml@refs/heads/main",
        "issuer": "https://token.actions.githubusercontent.com",
        "verified_at": "2026-09-13T20:41:15.072283Z",
        "trust_root": "production",
        "payload_type": "application/vnd.in-toto+json",
        "error": null
      },
      "provenance": {
        "predicate_type": "https://slsa.dev/provenance/v1",
        "predicate_version": "v1",
        "adapter_id": "slsa_provenance_v1_0",
        "adapter_version": "1.0.0",
        "builder_id": "https://github.com/astral-sh/ruff/.github/workflows/release.yml@refs/heads/main",
        "build_type": "https://actions.github.io/buildtypes/workflow/v1",
        "source_repo": "https://github.com/astral-sh/ruff",
        "source_revision": "b5dba861cc38e3f7fb4524c9ceba3e01a474ea13",
        "invocation_id": "https://github.com/astral-sh/ruff/actions/runs/34510395395/attempts/1",
        "started_at": null,
        "finished_at": null,
        "dependencies": [
          {
            "uri": "git+https://github.com/astral-sh/ruff@refs/heads/main",
            "digest": { "gitCommit": "b5dba861cc38e3f7fb4524c9ceba3e01a474ea13" }
          }
        ],
        "raw_unmapped": {
          "buildDefinition": {
            "internalParameters": {
              "github": {
                "event_name": "workflow_dispatch",
                "repository_id": "523043277",
                "repository_owner_id": "115962839",
                "runner_environment": "self-hosted"
              }
            }
          },
          "runDetails": { "metadata": {} }
        }
      }
    }
  ],
  "trust_decision": {
    "outcome": "DENY",
    "reasons": [
      "51bd5bab...: builder '...ruff/.../release.yml@refs/heads/main''s claimed level 3 is documented for GitHub-hosted runners; this attestation's runner_environment was not github-hosted"
    ],
    "policy_version": "1.0.0"
  }
}
```

That `DENY` is not a placeholder or a bug to route around before a demo. Run the real
`evaluate()` against both real fixtures in this repo and it denies **both**, for two different
reasons - checked directly, not assumed:

- **ruff (v1.0)** positively confirms `runner_environment == "self-hosted"` in
  `internalParameters.github`. GitHub's documented Build L3 claim is specifically about
  GitHub-*hosted*-runner non-falsifiability; it doesn't cover self-hosted (operator-controlled)
  runners. So this specific attestation's allowlisted level-3 ceiling doesn't hold - a real,
  positively-confirmed "no."
- **scorecard (v0.2)** has no equivalent field at all in its predicate - checked by grepping
  its `raw_unmapped`, not assumed absent. v0.2's predicate shape structurally cannot confirm
  this either way.

Both are treated as "cannot positively confirm the required runner isolation" and denied -
fail-closed on missing confirmation, not fail-open, since an unconfirmed non-falsifiability
claim gives no more assurance than no claim at all. That's more interesting than a clean
double-`ALLOW` would have been: it's the actual output of a real policy check against two real,
well-regarded open-source projects' release provenance. The `ALLOW` branch, the
issuer-mismatch `DENY`, and the conflicting-builder-identity `DENY` are all real, tested code -
just not reachable by either real fixture, so they're exercised by constructed `EvidenceItem`
instances in `tests/test_policy.py`, each labeled `constructed_*` rather than passed off as
real evidence.

`GET /v1/provenance/acme/sha256:979487...` (scorecard) shape is the same; its `raw_unmapped`
carries the full GitHub webhook event payload verbatim (`invocation.environment.
github_event_payload`), which is ~8.5KB on this real fixture versus ~150 bytes for ruff's -
elided here for legibility:

```json
{
  "trust_decision": {
    "outcome": "DENY",
    "reasons": [
      "95ae0e8e...: builder '...slsa-github-generator/.../generator_generic_slsa3.yml@refs/tags/v2.1.0''s claimed level 3 depends on runner isolation that https://slsa.dev/provenance/v0.2 evidence does not expose a signal for - cannot confirm"
    ],
    "policy_version": "1.0.0"
  }
}
```

That size asymmetry (~150 bytes vs. ~8.5KB of `raw_unmapped` per record) is measured, not
estimated, and is a real forward-looking concern at "millions of records" scale, especially if
`raw_unmapped` is ever indexed the way the corpus projection's mapped fields would be -
`raw_unmapped`'s purpose is debugging convenience, not queryability, so indexing it would be a
category error. Not fixed here - excluding a specific known-bulk subtree
(`github_event_payload`) would just hardcode "whatever was big in these two fixtures" as a
general rule. Recorded instead under Open questions.

## How this was built

Built in collaboration with Claude Code. I wrote a spec up front - the evidence → facts
→ decisions layering, the requirement to keep raw evidence forever, late-binding for
independently-arriving attestations on the same artifact - then we stress-tested that
approach together before settling on the detailed design. Most of the implementation was
generated from the spec and reviewed by me iteratively.

## Real-world evidence: things observed, not assumed

Everything above is pinned to two real fixtures. Things noticed only by looking at the actual
bytes, not by reasoning about the spec from memory:

- **Multiple attestations, materially different predicate *types*, same subject.** GitHub's
  attestations API returned *two* attestations for the same ruff binary digest: one
  `https://in-toto.io/attestation/release/v0.2` (a release-metadata predicate, not SLSA at all)
  and one real `https://slsa.dev/provenance/v1`. Directly relevant to the provenance
  cardinality open question - this isn't a hypothetical "what if a downstream repackaging step
  re-attests," it's the default shape one real GitHub Actions setup already produces for one
  artifact.
- **The weak-digest floor is real, not hypothetical.** That same ruff attestation's subject
  list includes a `pkg:github/astral-sh/ruff@0.16.7` entry digested only in **sha1**, sitting
  alongside ~35 file subjects digested in sha256. A real vendor, today, publishing a weak
  digest in the same subject array as strong ones - the reason association here (and the raw
  store's own content addressing) is sha256-only, deliberately, and treats a weak digest as
  informational only, never as an association basis.
- **Naming conventions lie; verify by inspection.** `cosign`'s release `.sigstore.json` files
  are bare signatures (`messageSignature`), not attestations, despite sitting next to real
  DSSE bundles elsewhere in the ecosystem - a generic ingester can't dispatch on filename.
  `ossf/scorecard`'s asset is still named `multiple.intoto.jsonl` though the current release
  ships exactly one line, caught by counting newlines rather than trusting the name.
- **Format plurality is at least three independent axes, not one**: predicate-type version
  (this repo's focus), envelope/bundle packaging (bare-DSSE-with-embedded-cert vs. modern
  Sigstore Bundle v0.3 - the *same* v0.2 predicate has shipped in both across scorecard's own
  release history), and Rekor entry kind (legacy `intoto` vs. current `dsse`/`hashedrekord`).
  None of these move in lockstep - a real ingester has to expect independent versioning at
  each layer, not one "format version" field.
- **The legacy Rekor `intoto` entry kind isn't just under-documented - sigstore-python doesn't
  parse it at all.** Confirmed by trying: fetched a real historical log entry by digest via
  Rekor's public API, attempted to reconstruct a `Bundle` from it, and hit
  `InvalidBundle("log entry is not of expected type")` - the parser only accepts `hashedrekord`
  and `dsse` kinds. Re-verifying attestations from that era means reimplementing Merkle-proof
  and SET verification outside `sigstore-python` entirely (see Open questions - a different
  failure mode than routine trust-root rotation).
- **No public "just give me the identity" accessor in sigstore-python.** Its identity classes
  (`Identity`, `OIDCIssuer`, `GitHubWorkflowRef`, …) are all *comparison* policies - they assert
  against an expected value and raise, rather than returning the cert's actual value. Recording
  identity/issuer as a fact meant going around the public verify API into `cryptography`'s x509
  extension API directly, plus a manual DER decode for Fulcio's OIDC-issuer extension - a
  surprising gap given how central "record who signed this" is to any real usage.

## What I deliberately didn't build

Naming a cut well should read as "understood the assignment," not "ran out of time." Every one
of these is a scoping decision, made and stated up front, not scope that quietly slipped:

- **SBOM ingestion - not built at all, not even a thin CycloneDX parse.** The original plan was
  to parse one SBOM format (CycloneDX) and associate it with an artifact digest, showing the
  canonical model could accommodate a second format (SPDX) behind the same adapter seam. Under
  the timebox, the two-version SLSA normalizer convergence (the actual thesis demonstration) and
  the EVALUATE fix above took priority over a third input format - a stated cut, not something
  silently assumed away: the platform already has substantial SBOM handling elsewhere, and this
  spike is about provenance/attestation ingestion and trust.
- **Re-verification over time.** The right instinct for "hard and interesting," the wrong
  choice for a built centerpiece - a Fulcio/Rekor trust root can't be rotated inside a spike, so
  anything "built" here would be prose in a code costume. What *is* built: the structured
  verification record, and the raw store that makes re-verification possible at all. Cadence,
  how a "was verified" record ages, fail-closed-vs-queue on Rekor/Fulcio unavailability - design
  prose, in Open questions below.
- **A wired policy engine (OPA/Cedar/CEL).** Kept as the input-document design - normalized
  facts + verification record + raw pointer - deliberately not wired to an engine. The
  interesting artifact is the contract, not the engine that will eventually read it.
- **Corpus projection.** Design section only (see Deep dive 2) - a `provenance_facts` schema
  and a violations-feed query sketch, not a running fold.
- **Multi-tenancy beyond scoped lookups.** `tenant_id` is real in the stub artifact table and
  is a genuine security boundary there (tested directly), but there's no audit log ("who
  verified / queried what, when") - a cheap addition in a real build, not built here.
- **Deterministic, offline verification tests.** `verify/verifier.py` takes an `offline` flag
  as the seam for a pinned historical trust-root snapshot, but it isn't wired to one yet - see
  "a present, not hypothetical, risk" below.
- **By-attestation lookup, a dry-run endpoint, a live skippable Rekor/Fulcio integration test.**
  Scoped out in that order to protect the by-artifact lookup and the two demo moments above.
- **Downstream consumption** ("which services consumed this artifact") - a separate evidence
  domain, discussed in full below.

### Downstream consumption - a separate evidence domain, out of scope

*"Which services consumed this artifact?"* is not the same question as *"what provenance does
this artifact have?"*, and it isn't answered by a different query over the same evidence. It
needs a **different evidence source** - pipeline and deployment events recording an artifact
being consumed - with different characteristics from attestation ingest: higher volume,
arrival independent of any attestation, and a need for temporal/environment context.

Not implemented here. The seam it would attach through is **tenant-scoped late-binding
association + the fact store** - the fan-out diagram above (Scope) simply gains a
`Consumption` arm. It is not the `CanonicalProvenance` model, which stays provenance-specific;
consumption events would be a sibling fact type.

This isn't just an adjacent gap: "a builder is retroactively found compromised" (see Open
questions) only answers "which artifacts are affected" from the provenance side - "who needs
to be told" requires joining that set against Consumption on artifact identity. The two open
items are one incident-response capability, split deliberately across this scope boundary.

## A present, not hypothetical, risk: live TUF fetch in the test suite

`Verifier.production()` fetches the *current* TUF trust root over the network on every call -
both real fixtures verify successfully against today's live root right now, which is
informative in itself (their cert validity windows and timestamps still check out), but it also
means this test suite isn't yet the deterministic/offline suite the design above calls for. A
trust-root rotation between now and whenever this gets re-run could break a previously-green
test - this is a live, present flakiness risk in this repo's own CI (`.github/workflows/test.yml`
runs the full suite, including the live-verifying tests, on every push), not a someday
concern filed purely under future work.

`verify_from_raw` already takes an `offline: bool` parameter as the seam for fixing this, but
it is *only* a seam - it's threaded straight through to `Verifier.production(offline=offline)`
and nothing else exists yet. There is no pinned local trust-root snapshot in this repo. The
concrete next step, not yet done: capture the TUF `trusted_root.json` that was live when the
two real fixtures were captured, commit it under `tests/fixtures/`, and load tests against it
via `offline=True` instead of a bare unwired flag.

## Production seams (named, not built)

| spike                     | production                           |
|----------------------------|--------------------------------------|
| SQLite / no database        | PostgreSQL (RDS)                     |
| Local blob dir (`raw_store`) | S3, tenant-partitioned              |
| In-process handoff          | Kinesis / SQS between stages         |
| FastAPI app                 | Existing platform service boundary   |
| Plain Python predicate fn   | Policy engine (OPA/Cedar/…) service or sidecar |
| Hand-seeded stub artifact table | Real artifact identity service, late-binding association |

## Open questions (named, not solved)

- **Association late-binding**: retry/resolve semantics, TTL for unresolved attestations.
- **OCI/container manifest depth**: most provenance for container formats attaches to an image
  *manifest* via OCI referrers / `cosign attach`, not a bare file digest - and "manifest" isn't
  one fixed level. A multi-arch image has an index digest and N per-platform manifest digests
  underneath it; nothing restricts an attestation to naming a leaf manifest over the index. An
  SBOM is a claim about filesystem contents (plausibly platform-scoped, so a per-platform
  digest is the expected subject); provenance is a claim about the build event (less obviously
  platform-scoped, so index-level attachment is more defensible) - though which level real
  build tooling actually uses for provenance in practice is left open, not asserted.
  Association therefore can't assume one fixed resolution depth in a real implementation: it
  would need to check the subject digest against every digest in the artifact's tracked
  identity set and succeed on whichever matches. Not built here - file digests only, matching
  what both real fixtures actually are - but for a platform storing container formats this is
  close to the default path, not an edge case, which is why it's named here rather than left
  implicit.
- **Corpus-policy execution**: scheduled vs. event-driven; incremental recompute scope.
- **Trust-root rotation**: re-verification cadence; how a "was verified" record ages.
- **Rekor/Fulcio unavailability during ingest**: fail closed, queue, or accept-unverified-and-flag?
- **Cross-tenant digest collisions**: one artifact digest, many logical artifacts.
- **SBOM depth**: how much of CycloneDX/SPDX to normalize vs. keep raw for policy, once SBOM
  ingestion exists at all (see "what I deliberately didn't build").
- **Long-tail corpus queries and `raw_unmapped`**: the projection caps expressiveness at mapped
  fields; whether an indexed full-predicate store beside it earns its cost (see the size
  asymmetry under Demo - ~150 bytes vs. ~8.5KB per record on two real fixtures - for why
  indexing it wholesale would be expensive, not just architecturally wrong), and whether
  `raw_unmapped` should ever exclude known-bulk subtrees like v0.2's `github_event_payload`,
  are both open - neither fixed here, since excluding one known-bulk field would just hardcode
  today's fixtures as a general rule.
- **Legacy Rekor entry-kind incompatibility** (see "real-world evidence" above): the client
  library dropped the ability to parse the evidence at all - a different failure mode than
  routine trust-root rotation, not addressed here.
- **Retroactive incident response**: a legitimately-signed attestation from a builder later
  found to be compromised (insider, compromised CI - the xz-utils lesson) stays cryptographically
  valid forever; re-verification never catches it. Flagging every artifact attested under a
  now-revoked builder/identity/time-window is a corpus-policy re-evaluation against an updated
  allowlist, not a re-verification pass - a different trigger than routine trust-root rotation.
  This is also where the Consumption domain stops being purely out of scope: flagging *which*
  artifacts are affected is a provenance-side corpus query, but "who needs to be told" crosses
  into Consumption.
- **Provenance cardinality**: is `CanonicalProvenance` 1:1 with an artifact, or 1:many (rebuild,
  re-attestation by a downstream repackaging step, dual-signing by two CI systems)? Directly
  observed, not hypothetical - GitHub's attestations API returned two materially different
  predicate types for the same real ruff artifact digest (see "real-world evidence" above). If
  many, what selects the "primary" record for a trust decision, and does policy ever need to
  reason over disagreement between them? `ProvenanceResponse.provenance_records` is a list, not
  a single record, precisely so returning it doesn't presuppose an answer by picking a
  "primary" record when there's more than one.
- **Exception/waiver workflow**: policy correctly denies a real, valid-but-not-yet-compliant
  artifact (e.g. a vendor not yet at the required SLSA level - both real fixtures in this repo
  are denied today, for exactly this kind of reason). A break-glass override - time-boxed,
  audit-logged, distinct from changing the policy itself - is a near-term gap, not designed
  here.
- **Policy-version drift on existing decisions**: a `Decision` is stamped with the
  `policy_version` that produced it (see the conceptual model above), which correctly stops a
  stale decision from being *misread* as current - but nothing here decides what happens to
  the decision itself once a tenant's policy moves from one version to the next. Does an old
  ALLOW quietly keep serving under a superseded policy until something else triggers a
  re-evaluation? Re-evaluate eagerly, for every affected artifact, the moment a policy
  changes? Only on next read? This is unresolved, not designed here - not even at the
  input-document-contract level deep dive 2 stopped at - and it's a real gap: a customer who
  tightens their policy would reasonably expect that to apply going forward without needing to
  know it doesn't retroactively touch already-issued decisions unless told so explicitly.
- **Raw store tenant boundary**: the raw store today has no tenant dimension at all - bytes are
  addressed purely by content digest, globally, and the built spine never partitions them.
  That's not a considered "shared CAS" design decision, just the omission you'd expect from a
  stub - but it raises a real question a production version has to actually answer rather than
  default into: Sigstore evidence is often public by construction (published to a public Rekor
  log), so a global content-addressed store might be the *right* call, saving real dedup cost
  when two tenants reference the same public artifact - but the tenant boundary that matters
  (association, and therefore what a query can ever resolve to) is enforced one layer up, in
  `associate()`'s `(tenant_id, digest)` keying, not in the raw store itself. Whether that's
  sufficient, or whether some evidence (a private-repo attestation, say) needs the raw bytes
  themselves partitioned too - as this doc's own production-seams table above currently
  assumes without arguing for it - is open, not settled.

## Repo layout

```
src/provenance/
  raw_store/       Content-addressed store of verbatim raw bytes (built)
  verify/          PAE/DSSE verification from raw store bytes (built)
  models/          Pydantic models for each layer: verification, provenance, evidence, artifact
  normalize/       Dispatch + per-version SLSA adapters (v0_2, v1_0) (built)
  associate.py     Digest -> artifact resolution (thin stub, design in the docstring)
  policy/          EVALUATE: plain predicate function + input-document contract + Decision model (built, no engine)
  api/             FastAPI app (EXPOSE) + demo bootstrap (seeds from fixtures)
tests/
  fixtures/bundles/  Two real, captured Sigstore bundles + meta.json provenance sidecars
scripts/
  fetch_github_attestation.py   How the ruff fixture was captured
  run_demo_api.py               Run the API locally against both fixtures
CRYPTOGRAPHY.md   Sigstore keyless-signing background this service depends on but doesn't design
```

## Running it

```
uv sync --locked --extra dev
uv run pytest -v          # 21 tests; verification tests hit the network - see risk note above
uv run python scripts/run_demo_api.py
# then: curl http://127.0.0.1:8000/v1/provenance/acme/sha256:73894c7b7c9a53fd66ed715eb3a1ec65077f316328e377057a98bdb7fcba0326
```

## Stack

- Python + FastAPI
- `sigstore-python` for verification (exact-pinned - see `pyproject.toml`'s comment on why the
  trust boundary gets exact pins and everything else gets bounded ranges)
- `pydantic` for the canonical model
- Local content-addressed dir for raw blobs; no database - the demo API's index is in-memory,
  built by `api/demo_bootstrap.py` at process start
- Policy: a plain Python predicate function over the input document, no engine
- pytest with two captured real bundles as fixtures

MIT licensed - see [LICENSE](LICENSE).
