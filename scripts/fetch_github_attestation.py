#!/usr/bin/env python3
"""Fetch a real GitHub Actions attestation bundle and save it as a test fixture.

Uses the GitHub REST attestations API directly (`gh api`) rather than the
`gh attestation` subcommand, which requires a newer gh CLI than may be
installed. See: GET /repos/{owner}/{repo}/attestations/{subject_digest}

Usage:
    python scripts/fetch_github_attestation.py OWNER/REPO SHA256_DIGEST \
        --predicate-type-contains slsa.dev/provenance \
        --out tests/fixtures/bundles/my-fixture

Saves:
    <out>/bundle.json   — the raw Sigstore bundle, exactly as returned by GitHub
    <out>/meta.json     — provenance metadata about how/when this was fetched

The bundle.json is the raw evidence (the README's "authoritative, immutable"
layer) — do not hand-edit it. Re-serializing the *outer* JSON structure is
safe (doesn't affect PAE verification, which is computed over the *decoded*
payload bytes referenced by the inner base64 string); this script does not
touch that string.
"""

import argparse
import base64
import json
import subprocess
import sys
from datetime import datetime, timezone


def gh_api(path: str) -> dict:
    result = subprocess.run(
        ["gh", "api", path], capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)


def statement_of(bundle: dict) -> dict:
    payload_b64 = bundle["dsseEnvelope"]["payload"]
    return json.loads(base64.b64decode(payload_b64))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="OWNER/REPO")
    parser.add_argument("digest", help="sha256:... subject digest, or bare hex")
    parser.add_argument(
        "--predicate-type-contains",
        default=None,
        help="substring to select among multiple attestations for the same subject",
    )
    parser.add_argument("--out", required=True, help="output directory for the fixture")
    args = parser.parse_args()

    digest = args.digest if args.digest.startswith("sha256:") else f"sha256:{args.digest}"
    resp = gh_api(f"repos/{args.repo}/attestations/{digest}")
    attestations = resp.get("attestations", [])
    if not attestations:
        print(f"No attestations found for {args.repo}@{digest}", file=sys.stderr)
        return 1

    chosen = attestations
    if args.predicate_type_contains:
        chosen = [
            a
            for a in attestations
            if args.predicate_type_contains in statement_of(a["bundle"]).get("predicateType", "")
        ]
        if not chosen:
            found = [statement_of(a["bundle"]).get("predicateType") for a in attestations]
            print(f"No attestation matched {args.predicate_type_contains!r}. Found: {found}", file=sys.stderr)
            return 1

    if len(chosen) > 1:
        found = [statement_of(a["bundle"]).get("predicateType") for a in chosen]
        print(f"Multiple attestations matched, pick one with --predicate-type-contains: {found}", file=sys.stderr)
        return 1

    bundle = chosen[0]["bundle"]
    statement = statement_of(bundle)

    out_dir = args.out
    subprocess.run(["mkdir", "-p", out_dir], check=True)

    with open(f"{out_dir}/bundle.json", "w") as f:
        json.dump(bundle, f, indent=2)
        f.write("\n")

    meta = {
        "source": "github_attestations_api",
        "endpoint": f"repos/{args.repo}/attestations/{digest}",
        "repo": args.repo,
        "subject_digest": digest,
        "predicate_type": statement.get("predicateType"),
        "statement_type": statement.get("_type"),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "note": "Fetched read-only via `gh api`; bundle.json is saved verbatim as returned.",
    }
    with open(f"{out_dir}/meta.json", "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")

    print(f"Saved {out_dir}/bundle.json  (predicateType: {statement.get('predicateType')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
