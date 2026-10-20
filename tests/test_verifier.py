"""Unit tests for verifier.py's helpers, below the level of a real bundle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from provenance.verify.verifier import _extract_identity


def test_extract_identity_is_none_for_cert_without_fulcio_extensions():
    """A cert with no SAN and no Fulcio issuer extension yields None for
    both — absent, not an empty-string fact."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-fulcio")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    assert _extract_identity(cert) == (None, None)
