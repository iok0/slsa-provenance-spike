"""Decode the in-toto Statement out of raw envelope bytes.

Deliberately independent of provenance.verify — normalization and
verification both consume the same raw record, but neither depends on the
other's output (see the README's note that VERIFY and NORMALISE are not a
pipeline, just two things that both read the raw bytes).

Only handles the Sigstore Bundle shape (`dsseEnvelope` + `verificationMaterial`
at the top level) — the shape both real fixtures actually are. The older
bare-DSSE shape (payload/payloadType/signatures at the top level, cert
embedded in signatures[].cert — see implementation_learnings.md's Rekor
`intoto`-kind finding) is a known, real, *un*implemented case: no fixture
in this repo exercises it, so no parsing code claims to handle it.
"""

from __future__ import annotations

import base64
import json
from typing import Any

_EXPECTED_PAYLOAD_TYPE = "application/vnd.in-toto+json"


class UnsupportedEnvelopeShape(ValueError):
    """Raised for raw bytes that aren't the Bundle shape this module
    handles — not guessed at, not silently passed through."""


def statement_from_raw(raw_bytes: bytes) -> dict[str, Any]:
    """Decode raw envelope bytes into the in-toto Statement dict.

    Raises UnsupportedEnvelopeShape for anything that isn't a Bundle with
    a `dsseEnvelope` whose payloadType is the in-toto media type.
    """
    envelope = json.loads(raw_bytes)

    if "dsseEnvelope" not in envelope:
        raise UnsupportedEnvelopeShape(
            "raw record has no dsseEnvelope — bare-DSSE envelopes (no "
            "enclosing Bundle) are a known real shape (see "
            "implementation_learnings.md) but are not handled here; no "
            "fixture in this repo exercises that path"
        )

    dsse = envelope["dsseEnvelope"]
    payload_type = dsse.get("payloadType")
    if payload_type != _EXPECTED_PAYLOAD_TYPE:
        raise UnsupportedEnvelopeShape(
            f"unexpected payloadType {payload_type!r}, expected "
            f"{_EXPECTED_PAYLOAD_TYPE!r}"
        )

    statement_bytes = base64.b64decode(dsse["payload"])
    return json.loads(statement_bytes)
