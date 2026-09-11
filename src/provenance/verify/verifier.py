"""PAE / DSSE verification via sigstore-python, sourced from raw store bytes.

Design intent (see the README): cryptographic verification only —
signature over PAE, cert chain to the Fulcio root, SCT, Rekor inclusion.
Identity is *extracted* from
the cert and recorded as a fact; deciding whether that identity is trusted
belongs to EVALUATE, not here (the three-layer model: verification
establishes certainty, policy establishes trust; conflating them would let
this layer imply more than it verified). Concretely: we verify with
sigstore-python's `policy.UnsafeNoOp()` — its own name for "prove the
crypto, assert nothing about who signed it" — deliberately, not by omission.

TODO (noted in the README, not solved here): `Verifier.production()`
fetches the *current* TUF trust root over the network. Deterministic,
offline tests need a pinned historical trust-root snapshot instead — captured
bundles rot as certs expire and roots rotate. This module takes an
`offline` flag as the seam for that; it is not yet wired to a pinned
snapshot.
"""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography.x509 import Certificate, ObjectIdentifier, UniformResourceIdentifier
from cryptography.x509.oid import ExtensionOID
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.type.char import UTF8String
from sigstore.errors import VerificationError as SigstoreVerificationError
from sigstore.models import Bundle
from sigstore.verify import Verifier, policy

from provenance.models.verification import VerificationRecord

# Fulcio's DER-encoded OIDC issuer extension (CRYPTOGRAPHY.md's OID table:
# "current", as opposed to the deprecated plain-string `.1.1`).
_OIDC_ISSUER_V2_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.8")


def _extract_identity(cert: Certificate) -> tuple[str | None, str | None]:
    """Best-effort extraction of SAN identity + OIDC issuer from the leaf
    cert. Independent of verification outcome — these are read off
    whatever certificate Fulcio issued, not asserted by us.
    """
    identity: str | None = None
    issuer: str | None = None
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        uris = san.get_values_for_type(UniformResourceIdentifier)
        identity = uris[0] if uris else None
    except Exception:
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(_OIDC_ISSUER_V2_OID).value
        issuer = str(der_decode(ext.value, asn1Spec=UTF8String())[0])
    except Exception:
        pass
    return identity, issuer


def verify_from_raw(
    raw_bytes: bytes, *, raw_digest: str, offline: bool = False
) -> VerificationRecord:
    """Verify a Sigstore bundle's DSSE envelope, sourced from raw bytes
    already committed to the raw store.

    Callers must pass the bytes read back *from the store* (by digest), not
    whatever they originally received — that's what makes "verify from raw"
    a guarantee rather than a convention. See raw_store.store.

    Returns a structured VerificationRecord and does not raise on a normal
    verification failure (a bad signature is an expected outcome to record,
    not an exception to propagate). A malformed bundle that isn't even
    parseable still raises — that's an ingest-time error, not a
    verification result.
    """
    verifier = Verifier.production(offline=offline)
    trust_root_label = "production" + ("-offline" if offline else "")

    bundle = Bundle.from_json(raw_bytes)
    identity, issuer = _extract_identity(bundle.signing_certificate)

    record = VerificationRecord(
        raw_digest=raw_digest,
        identity=identity,
        issuer=issuer,
        verified_at=datetime.now(timezone.utc),
        trust_root=trust_root_label,
    )

    try:
        payload_type, _payload = verifier.verify_dsse(bundle, policy.UnsafeNoOp())
    except SigstoreVerificationError as e:
        record.error = str(e)
        # sigstore-python's verify_dsse is one all-or-nothing call: on
        # failure we know verification-as-a-whole didn't succeed, but not
        # which sub-check first broke. Every failure path raises the same
        # flat `VerificationError` with no error code (sigstore's
        # errors.py), so message text is the only signal available — and
        # it isn't a documented API contract, just log wording that a
        # sigstore-python upgrade can reword without notice.
        #
        # So this matches on specific substrings observed at the actual
        # `raise` sites (checked against sigstore==4.5.0's
        # verify/verifier.py, dsse/__init__.py, and
        # _internal/rekor/checkpoint.py) rather than loose tokens like
        # "cert" or "signature", which show up in more than one category's
        # messages (e.g. the SCT failure message itself says "...on
        # signing certificate") and would misfire across the elif chain.
        # A message that doesn't unambiguously match a category — e.g.
        # "not enough sources of verified time" (no check reached yet) or
        # a cert-profile failure like "Key usage is not of type ..."
        # (there's no VerificationRecord field for that) — leaves all four
        # fields `None` ("not reached") rather than guessing. A wrong,
        # specific `False` overclaims more than an honest "don't know" —
        # see VerificationRecord's docstring on the None-vs-False
        # distinction.
        msg = str(e).lower()
        if "failed to verify sct" in msg:
            record.sct_verified = False
        elif "log entry" in msg:
            # Covers both the wrapped inclusion/checkpoint failures
            # ("invalid log entry: ...") and the step-8 body-consistency
            # checks, which mention "log entry" directly (e.g. "log entry
            # payload hash does not match bundle").
            record.tlog_verified = False
        elif "certificate chain" in msg or "signing cert" in msg:
            # "failed to build timestamp certificate chain: ..." (chain
            # build) and "invalid signing cert: expired at time of
            # signing, ..." (validity-period check) — both about the
            # cert's trust path, not the DSSE signature itself.
            record.chain_verified = False
        elif "dsse" in msg or "signature is invalid" in msg or "bundle message" in msg:
            record.signature_verified = False
        return record

    record.payload_type = payload_type
    record.signature_verified = True
    record.chain_verified = True
    record.sct_verified = True
    record.tlog_verified = True
    return record
