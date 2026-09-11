"""The structured verification record.

Design intent (see the README): verification result is a structured record,
not a boolean. Field names match what sigstore-python surfaces (see
CRYPTOGRAPHY.md's verification flow) so the record stays legible against
the library producing it, not a paraphrase of it.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class VerificationRecord(BaseModel):
    """Outcome of verifying one raw envelope's DSSE signature over PAE.

    A field is `None` when that check was never reached — e.g. the
    signature itself didn't verify, so cert-chain building, SCT, and tlog
    inclusion were never attempted — distinct from `False`, which means the
    check ran and failed. Collapsing "not reached" into "failed" would let
    this record imply more certainty than verification actually earned,
    which is precisely the discipline the README's evidence→facts→decisions
    model is about.

    `identity` / `issuer` are read off the leaf certificate's SAN and OIDC
    issuer extension regardless of whether verification passed — they are
    facts about what the certificate *claims*, not an endorsement. Whether
    that identity is *trusted* is EVALUATE's job (a policy decision over
    this record), not VERIFY's — which is also why verification is run with
    sigstore-python's `UnsafeNoOp` policy (crypto-only, no identity
    assertion) rather than asserting an expected identity here.
    `policy_identity_matched` is therefore only ever populated by a caller
    that *did* supply an expected identity (e.g. a future re-verification
    pass); it is not set by the default ingest path.
    """

    raw_digest: str

    signature_verified: bool | None = None
    chain_verified: bool | None = None
    sct_verified: bool | None = None
    tlog_verified: bool | None = None

    identity: str | None = None
    issuer: str | None = None
    policy_identity_matched: bool | None = None

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
        return bool(
            self.signature_verified
            and self.chain_verified
            and self.sct_verified
            and self.tlog_verified
        )
