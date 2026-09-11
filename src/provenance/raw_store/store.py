"""Raw-preserving, content-addressed store for ingested attestation bundles.

This is the built spine's central design decision (see the README): whatever
bytes are ingested are stored verbatim, addressed by the digest of
those exact bytes, and never rewritten. Re-verification — against a rotated
trust root years later, or with a newer normalizer version — must always be
possible by reading back from here, not from a caller-held or re-serialized
copy. This module does not parse or validate the bytes; that is VERIFY's and
NORMALISE's job, and both must read from this store, never from whatever the
caller originally passed in, or the "verify from raw" guarantee is fiction.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def digest_of(raw_bytes: bytes) -> str:
    """The content address for raw bytes: a sha256 hex digest.

    This is the association basis's strong-digest floor applied to storage
    identity too — sha256 only, deliberately (see the README's discussion
    of association).
    """
    return hashlib.sha256(raw_bytes).hexdigest()


class RawEnvelopeStore:
    """Content-addressed, effectively-immutable store of raw envelope bytes.

    Production seam (see the README): this becomes S3, tenant-partitioned.
    The interface is deliberately three methods so that swap is a backend
    change behind an unchanged call site.
    """

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, digest: str) -> Path:
        # Two-level fan-out so the directory doesn't become one giant flat
        # listing as the corpus grows.
        return self.root / digest[:2] / digest[2:4] / f"{digest}.bin"

    def put(self, raw_bytes: bytes) -> str:
        """Store raw bytes verbatim.

        Idempotent: storing identical bytes twice is a no-op — dedupe by
        envelope digest (see the README's ingest section) — the digest of
        the content *is* the dedupe key, there's no separate check.

        Returns the content digest — the durable identifier for this raw
        record from here on.
        """
        digest = digest_of(raw_bytes)
        path = self._path_for(digest)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(raw_bytes)
            tmp.rename(path)  # atomic within the same filesystem
        return digest

    def get(self, digest: str) -> bytes:
        """Read back the exact bytes previously stored under `digest`."""
        path = self._path_for(digest)
        if not path.exists():
            raise KeyError(f"no raw record for digest {digest}")
        return path.read_bytes()

    def exists(self, digest: str) -> bool:
        return self._path_for(digest).exists()
