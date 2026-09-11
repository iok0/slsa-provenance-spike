"""Deep dive 1 (built spine): raw-preserving store + verify-from-raw.

Two things get proved here, matching the README's demo moments:

1. A real, independently-signed Sigstore bundle verifies when read back
   from the raw store (not from the original file handle) — proves
   "verify from raw" is real, not just a claim.
2. Flipping one byte of the *stored* payload breaks verification — proves
   the raw store's integrity guarantee is real, not just content-addressed
   bookkeeping.

Fixture provenance: tests/fixtures/bundles/ruff-0.16.7-linux-x86_64-slsa-v1/
is a real SLSA v1.0 attestation for a real astral-sh/ruff release binary,
fetched read-only from GitHub's attestations API
(GET /repos/{owner}/{repo}/attestations/{digest}) — see meta.json alongside
it and scripts/fetch_github_attestation.py for how.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from provenance.raw_store.store import RawEnvelopeStore, digest_of
from provenance.verify.verifier import verify_from_raw

FIXTURES = Path(__file__).parent / "fixtures" / "bundles"


def _load_bundle_bytes(fixture_dir: str) -> bytes:
    return (FIXTURES / fixture_dir / "bundle.json").read_bytes()


@pytest.fixture
def store(tmp_path):
    return RawEnvelopeStore(tmp_path / "raw")


def test_put_is_content_addressed_and_idempotent(store):
    raw = _load_bundle_bytes("ruff-0.16.7-linux-x86_64-slsa-v1")

    digest1 = store.put(raw)
    digest2 = store.put(raw)  # re-ingest of the same bundle: INGEST's dedupe

    assert digest1 == digest2 == digest_of(raw)
    assert store.exists(digest1)
    assert store.get(digest1) == raw


def test_verify_from_raw_succeeds_on_real_bundle(store):
    """Demo moment: a real GH Actions SLSA v1.0 bundle, verified from the
    stored raw bytes, not from the original file."""
    raw = _load_bundle_bytes("ruff-0.16.7-linux-x86_64-slsa-v1")
    digest = store.put(raw)

    stored_bytes = store.get(digest)  # read back — never reuse `raw` below
    record = verify_from_raw(stored_bytes, raw_digest=digest)

    assert record.fully_verified, record.error
    assert record.signature_verified is True
    assert record.chain_verified is True
    assert record.sct_verified is True
    assert record.tlog_verified is True
    assert record.error is None
    assert record.payload_type == "application/vnd.in-toto+json"

    # Identity is a recorded fact, not an enforced policy (see
    # VerificationRecord's docstring) — but it should be the real workflow
    # that actually signed this release.
    assert record.identity == (
        "https://github.com/astral-sh/ruff/.github/workflows/release.yml"
        "@refs/heads/main"
    )
    assert record.issuer == "https://token.actions.githubusercontent.com"
    assert record.policy_identity_matched is None  # not asserted at this layer


def test_byte_flip_breaks_verification(store):
    """Demo moment 2: flip one byte of the *stored* payload and
    verification must fail. Proves the raw store's integrity guarantee is
    real — this isn't just a hash comparison, the flipped bytes genuinely
    fail PAE / DSSE signature verification.
    """
    raw = _load_bundle_bytes("ruff-0.16.7-linux-x86_64-slsa-v1")
    digest = store.put(raw)
    good_record = verify_from_raw(store.get(digest), raw_digest=digest)
    assert good_record.fully_verified

    envelope = json.loads(raw)
    payload_b64 = envelope["dsseEnvelope"]["payload"]
    # Flip one character deep inside the base64 payload — this changes the
    # decoded statement bytes, which changes the PAE, which invalidates the
    # signature computed over the original PAE.
    flip_at = len(payload_b64) // 2
    original_char = payload_b64[flip_at]
    replacement = "A" if original_char != "A" else "B"
    tampered_b64 = payload_b64[:flip_at] + replacement + payload_b64[flip_at + 1 :]
    envelope["dsseEnvelope"]["payload"] = tampered_b64
    tampered_raw = json.dumps(envelope).encode()

    # Tampered bytes get their own content address — this is a *different*
    # raw record, exactly as the README's raw-store model says it should be.
    tampered_digest = store.put(tampered_raw)
    assert tampered_digest != digest

    bad_record = verify_from_raw(store.get(tampered_digest), raw_digest=tampered_digest)

    assert not bad_record.fully_verified
    assert bad_record.error is not None
