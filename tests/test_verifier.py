"""Unit tests for verifier.py's helpers, below the level of a real bundle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.char import UTF8String

from provenance.models.verification import CertClaims
from provenance.verify.verifier import _extract_cert_claims, _extract_identity, _fulcio_oid

_WORKFLOW = "https://github.com/astral-sh/ruff/.github/workflows/release.yml@refs/heads/main"


def _der_utf8(value: str) -> bytes:
    return der_encode(UTF8String(value))


def _cert(*extensions: x509.ExtensionType) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-fulcio")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
    )
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(key, hashes.SHA256())


def _fulcio_ext(n: int, raw_value: bytes) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(_fulcio_oid(n), raw_value)


def test_extract_identity_is_none_for_cert_without_fulcio_extensions():
    """A cert with no SAN and no Fulcio extensions yields None for every
    identity fact and cert claim — absent, not an empty-string fact, and
    not a decode error either."""
    cert = _cert()
    errors: list[str] = []

    assert _extract_identity(cert, errors) == (None, None)
    assert _extract_cert_claims(cert, errors) == CertClaims()
    assert errors == []


@pytest.mark.parametrize(
    ("field", "n"), [("runner_environment", 11), ("build_config_uri", 18)]
)
def test_undecodable_claim_is_recorded_not_mistaken_for_absent(field, n):
    """Raw bytes instead of a DER UTF8String (the deprecated .1-.6 style).
    The claim is None, like absent — but recorded, so EVALUATE can tell
    the two apart. The claims that did decode are unaffected."""
    good = {9: _WORKFLOW, 11: "self-hosted", 18: _WORKFLOW}
    exts = [
        _fulcio_ext(k, b"not-der" if k == n else _der_utf8(v)) for k, v in good.items()
    ]
    errors: list[str] = []

    claims = _extract_cert_claims(_cert(*exts), errors)

    assert getattr(claims, field) is None
    assert claims.build_signer_uri == _WORKFLOW
    [error] = errors
    assert error.startswith(f"{_fulcio_oid(n).dotted_string}: ")


def test_trailing_bytes_after_claim_are_a_decode_error():
    errors: list[str] = []

    claims = _extract_cert_claims(
        _cert(_fulcio_ext(11, _der_utf8("github-hosted") + b"\x00")), errors
    )

    assert claims.runner_environment is None
    [error] = errors
    assert "trailing bytes" in error


def test_malformed_san_is_recorded_not_mistaken_for_absent():
    """A malformed SAN makes the cert's whole extension list unparseable,
    so every lookup after it fails too — each is recorded."""
    cert = _cert(
        x509.UnrecognizedExtension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, b"garbage")
    )
    errors: list[str] = []

    identity, issuer = _extract_identity(cert, errors)

    assert (identity, issuer) == (None, None)
    assert errors[0].startswith(f"{ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string}: ")


def test_san_without_uri_is_absent_not_an_error():
    """An email SAN (a human keyless signer) has no URI identity — a
    legitimate absence, not a decode failure."""
    cert = _cert(x509.SubjectAlternativeName([x509.RFC822Name("dev@example.com")]))
    errors: list[str] = []

    assert _extract_identity(cert, errors) == (None, None)
    assert errors == []
