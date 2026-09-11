"""Seed a RawEnvelopeStore + subject-digest index from a list of raw
bundle files, verifying and normalizing each one once.

This is a stand-in for real INGEST (see README's INGEST section:
idempotency, poison payloads, dead-letter — none of that is here), not a
demo of it. It exists so the API has something real to answer queries
against, using the exact same verify_from_raw / normalize_from_raw the
rest of the built spine uses — no shortcut path.

VERIFY and NORMALISE run once here, at seed time, and the results are
cached — matching the architecture (facts are established once, when
evidence arrives; a query reads them, it doesn't recompute them). The API
route does not call sigstore-python per request.

Only reads a subject's `sha256` digest key when building the index — see
associate.py's docstring on why: that's the strong-digest floor in
practice for the two real fixtures (neither has ever forced this code to
reject an actual weaker alternative, since neither fixture's subject
entries carry more than one digest algorithm — this only ever *reads*
sha256, it doesn't need to reject anything else because nothing else is
there to reject).
"""

from __future__ import annotations

import tempfile
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from provenance.models.evidence import EvidenceItem
from provenance.normalize import normalize_from_raw, statement_from_raw
from provenance.raw_store.store import RawEnvelopeStore
from provenance.verify.verifier import verify_from_raw


@dataclass
class DemoData:
    store: RawEnvelopeStore
    subject_index: dict[str, list[str]] = field(default_factory=dict)
    records_by_raw_digest: dict[str, EvidenceItem] = field(default_factory=dict)


def seed_from_fixtures(bundle_paths: Sequence[Path]) -> DemoData:
    """Ingest each raw bundle file at `bundle_paths` into a fresh store,
    verifying and normalizing it once, and index it by every sha256
    subject digest its statement lists."""
    store = RawEnvelopeStore(Path(tempfile.mkdtemp()))
    subject_index: dict[str, list[str]] = defaultdict(list)
    records: dict[str, EvidenceItem] = {}

    for path in bundle_paths:
        raw_bytes = path.read_bytes()
        raw_digest = store.put(raw_bytes)

        records[raw_digest] = EvidenceItem(
            raw_digest=raw_digest,
            verification=verify_from_raw(raw_bytes, raw_digest=raw_digest),
            provenance=normalize_from_raw(raw_bytes),
        )

        statement = statement_from_raw(raw_bytes)
        for subject in statement.get("subject", []):
            sha256 = subject.get("digest", {}).get("sha256")
            if sha256:
                subject_index[f"sha256:{sha256}"].append(raw_digest)

    return DemoData(
        store=store,
        subject_index=dict(subject_index),
        records_by_raw_digest=records,
    )
