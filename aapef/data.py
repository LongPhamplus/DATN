"""Hash-checked loader for KEV / NVD / EPSS snapshots (MasterPlan §5.1).

`scripts/fetch_snapshots.py` writes the files and `MANIFEST.json`; this module
only reads them. Every file's SHA-256 is recomputed and compared with the
manifest before use, so an edited or truncated file is refused. No network.

    snap = load_snapshot("data/snapshots")          # latest snapshot
    rec = snap.cves["CVE-2021-44228"]
    rec.vector, rec.epss, rec.kev, rec.kev_added

`snap.id` ("<date>:<12 hex>") names the data in every result file.
"""

import hashlib
import json
import os
from dataclasses import dataclass

from .cvss import exploitability, parse_vector_string


class SnapshotError(ValueError):
    """Raised when a snapshot is missing, incomplete or fails its hash check."""


@dataclass(frozen=True)
class CveRecord:
    id: str
    vector_string: str = None     # CVSS v3 vector from NVD, None if NVD has none
    vector: dict = None           # parsed exploitability metrics (AV, AC, PR, UI, S)
    vector_source: str = None     # "nvd" (Primary) or "cna" (Secondary)
    base_score: float = None
    exploitability: float = None  # computed from `vector` (cvss.exploitability)
    published: str = None
    epss: float = None
    percentile: float = None
    kev: bool = False
    kev_added: str = None         # dateAdded in the KEV catalog


@dataclass(frozen=True)
class Snapshot:
    id: str
    name: str
    files: dict    # manifest entries of the files read
    cves: dict     # CVE id -> CveRecord


def _read_checked(root, name, entry):
    path = os.path.join(root, name)
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise SnapshotError(f"{path}: {exc}") from None
    got = hashlib.sha256(raw).hexdigest()
    if got != entry.get("sha256"):
        raise SnapshotError(f"{path}: SHA-256 {got} does not match the manifest "
                            f"({entry.get('sha256')}); the file was changed")
    return json.loads(raw)


def load_manifest(root):
    path = os.path.join(root, "MANIFEST.json")
    try:
        with open(path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except OSError as exc:
        raise SnapshotError(f"{path}: {exc}") from None
    if not isinstance(manifest.get("snapshots"), dict) or not manifest["snapshots"]:
        raise SnapshotError(f"{path}: no snapshots listed")
    return manifest


def load_snapshot(root="data/snapshots", name=None):
    """Load snapshot `name` (default: the latest by name) after checking hashes."""
    snapshots = load_manifest(root)["snapshots"]
    name = name or max(snapshots)
    if name not in snapshots:
        raise SnapshotError(f"snapshot {name!r} not in manifest (have {sorted(snapshots)})")
    files = snapshots[name]["files"]
    by_kind = {}
    for fname, entry in files.items():
        if entry.get("kind") in by_kind:
            raise SnapshotError(f"snapshot {name}: two files of kind {entry['kind']!r}")
        by_kind[entry.get("kind")] = fname
    missing = {"kev", "nvd", "epss"} - set(by_kind)
    if missing:
        raise SnapshotError(f"snapshot {name}: missing {sorted(missing)}")
    data = {k: _read_checked(root, f, files[f]) for k, f in by_kind.items()}

    kev = {v["cveID"]: v.get("dateAdded") for v in data["kev"]["vulnerabilities"]}
    nvd = data["nvd"]["records"]
    epss = data["epss"]["records"]
    cves = {}
    for cid in sorted(set(nvd) | set(kev) | set(epss)):
        n = nvd.get(cid, {})
        vec = parse_vector_string(n["vector"]) if n.get("vector") else None
        e = epss.get(cid)
        cves[cid] = CveRecord(
            id=cid, vector_string=n.get("vector"), vector=vec,
            vector_source=n.get("vector_source"), base_score=n.get("base_score"),
            exploitability=exploitability(vec) if vec else None,
            published=n.get("published"),
            epss=e[0] if e else None, percentile=e[1] if e else None,
            kev=cid in kev, kev_added=kev.get(cid))
    digest = hashlib.sha256("".join(
        files[f]["sha256"] for f in sorted(files)).encode()).hexdigest()
    return Snapshot(id=f"{name}:{digest[:12]}", name=name, files=files, cves=cves)
