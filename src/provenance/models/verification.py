"""The structured verification record.

Design intent (see the README): verification result is a structured record,
not a boolean. Field names match what sigstore-python surfaces (see
CRYPTOGRAPHY.md's verification flow) so the record stays legible against
the library producing it, not a paraphrase of it.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class CertClaims(BaseModel):
    """CI claims Fulcio copied out of the signer's OIDC token into the leaf
    cert (OIDs in CRYPTOGRAPHY.md's quick reference). Fulcio vouches for
    these — they came from the IdP's signed token, not from the signer —
    which is why EVALUATE prefers them over the predicate's self-asserted
    equivalents wherever both exist.

    Read off the cert regardless of verification outcome, like `identity`:
    a fact about what the cert says, only as trustworthy as
    `fully_verified`. Each is `None` when the extension is absent (a
    non-GitHub issuer, or a Fulcio too old to emit it).

    Scope caveat on `runner_environment`: it describes the job that
    requested the cert. When the signer is a reusable workflow
    (`build_signer_uri != build_config_uri`), that's the reusable
    workflow's own job, not the caller's build job.
    """

    build_signer_uri: str | None = None
    """`.9` — the workflow that requested the cert; equals the SAN on GitHub."""
    runner_environment: str | None = None
    """`.11` — `github-hosted` / `self-hosted`."""
    source_repo_uri: str | None = None
    """`.12` — the repository the workflow run belongs to (the caller's)."""
    source_repo_digest: str | None = None
    """`.13` — the commit the run was triggered at."""
    build_config_uri: str | None = None
    """`.18` — the top-level (calling) workflow file at its ref."""


class VerificationRecord(BaseModel):
    """Outcome of verifying one raw envelope's DSSE signature over PAE.

    A field is `None` when that check was never reached, or when it can't be
    confirmed to have run — distinct from `False`, which means the check
    specifically ran and failed. This matters because sigstore-python's
    `verify_dsse` is a single all-or-nothing call that raises one flat
    `VerificationError` on any failure: the ingest path
    (`verify.verifier.verify_from_raw`) therefore leaves all four `None` on
    failure and keeps sigstore's message in `error`, rather than parsing
    that message to guess which check broke (its wording isn't a documented
    API contract). That includes cases where sigstore-python verified
    chain/SCT/tlog internally before failing later on the DSSE signature
    itself — a thrown exception gives this caller no partial result to
    record. `False` is unused today; it's reserved for when a failure can be
    attributed to one check from a typed signal (see CRYPTOGRAPHY.md).
    Collapsing "unknown" into "failed" would let this record imply more
    certainty than verification actually earned, which is precisely the
    discipline the README's evidence→facts→decisions model is about.

    `identity` / `issuer` are read off the leaf certificate's SAN and OIDC
    issuer extension regardless of whether verification passed — they are
    facts about what the certificate *claims*, not an endorsement. Whether
    that identity is *trusted* is EVALUATE's job (a policy decision over
    this record), not VERIFY's — which is also why verification is run with
    sigstore-python's `UnsafeNoOp` policy (crypto-only, no identity
    assertion) rather than asserting an expected identity here.
    `cert_claims` is the same kind of fact, for the rest of the cert's CI
    claims (see CertClaims).
    """

    raw_digest: str

    signature_verified: bool | None = None
    chain_verified: bool | None = None
    sct_verified: bool | None = None
    tlog_verified: bool | None = None

    identity: str | None = None
    issuer: str | None = None
    cert_claims: CertClaims = CertClaims()

    verified_at: datetime
    trust_root: str
    payload_type: str | None = None

    error: str | None = None

    @property
    def fully_verified(self) -> bool:
        """True only if every crypto check ran and passed.

        Deliberately *not* `not self.error` — see the class docstring on
        `None` vs `False`. This is the one place that collapses the
        granular record into a single boolean, and it's a derived
        convenience for callers, not what gets stored.
        """
        return _all_checks_passed(self)


def _all_checks_passed(record: VerificationRecord) -> bool:
    # Module-level rather than inline in the property so mutation testing
    # reaches it: mutmut doesn't mutate decorated functions, and this is the
    # one line EVALUATE's verification gate rests on.
    return bool(
        record.signature_verified
        and record.chain_verified
        and record.sct_verified
        and record.tlog_verified
    )
