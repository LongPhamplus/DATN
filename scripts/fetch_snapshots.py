"""Download a dated snapshot of KEV, NVD and EPSS data (MasterPlan §5.1).

This is the only code in the project that touches the network. Experiments read
the files it writes through `aapef/data.py`, which checks their SHA-256 against
`MANIFEST.json`, so a result can always be tied to the exact data it used.

Sources (all public):
  KEV   CISA Known Exploited Vulnerabilities, official mirror on GitHub
        (cisa.gov answers 403 to scripted downloads). Stored verbatim.
  NVD   NVD CVE API 2.0. Population = every CVE with `hasKev` plus every CVE
        published in the `--pub-range` windows. Each record is reduced to the
        fields the experiments use (see `slim_nvd`).
  EPSS  FIRST/Empirical Security daily CSV for `--epss-date`. Only the CVEs of
        the NVD population and KEV are kept; the hash of the original .csv.gz is
        recorded so the subset can be checked against the published file.

Usage (run from the repo root):
    python scripts/fetch_snapshots.py --pub-range 2024-01-01:2024-12-31

NVD allows 5 requests per 30 s without an API key; the script waits 6.5 s
between pages (0.7 s if the environment variable NVD_API_KEY is set).
Snapshots are never overwritten: a new date gives a new entry in the manifest.
"""

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KEV_URL = ("https://raw.githubusercontent.com/cisagov/kev-data/main/"
           "known_exploited_vulnerabilities.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
NVD_PAGE = 2000             # maximum resultsPerPage of the NVD API
NVD_MAX_WINDOW_DAYS = 120   # NVD rejects longer pubStartDate..pubEndDate ranges
USER_AGENT = "AAPEF-snapshot/1.0 (graduation project; research use)"


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def http_get(url, headers=None, tries=5):
    """GET with retries on rate limiting and server errors."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code not in (403, 429, 500, 502, 503, 504) or attempt == tries - 1:
                raise
            wait = 30 * (attempt + 1)
        except urllib.error.URLError:
            if attempt == tries - 1:
                raise
            wait = 10 * (attempt + 1)
        log(f"  retry in {wait}s: {url[:100]}")
        time.sleep(wait)
    raise RuntimeError("unreachable")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def dump_records(header, records):
    """JSON with one record per line, keys sorted: stable bytes, readable diffs."""
    head = json.dumps(header, sort_keys=True, ensure_ascii=False)
    lines = [f"  {json.dumps(k)}: {json.dumps(records[k], sort_keys=True, ensure_ascii=False)}"
             for k in sorted(records)]
    return (head[:-1] + ', "records": {\n' + ",\n".join(lines) + "\n}}\n").encode("utf-8")


# --- NVD ---------------------------------------------------------------------

NVD_SOURCE = "nvd@nist.gov"


def pick_cvss3(metrics):
    """Choose one CVSS v3 entry.

    Order: NVD's own assessment (source nvd@nist.gov, whatever its `type`;
    NVD sometimes lists its own entry as "Secondary", e.g. CVE-2020-1472),
    v3.1 before v3.0; then a "Primary" entry; then the first CNA entry.
    """
    entries = (metrics.get("cvssMetricV31") or []) + (metrics.get("cvssMetricV30") or [])
    for test in (lambda m: m.get("source") == NVD_SOURCE,
                 lambda m: m.get("type") == "Primary",
                 lambda m: True):
        for m in entries:
            if test(m):
                return m
    return None


def slim_nvd(cve):
    """The fields of one NVD record that the experiments use."""
    rec = {"published": cve.get("published", "")[:10], "status": cve.get("vulnStatus")}
    m = pick_cvss3(cve.get("metrics", {}))
    if m:
        rec.update(vector=m["cvssData"]["vectorString"],
                   base_score=m["cvssData"]["baseScore"],
                   exploitability_score=m.get("exploitabilityScore"),
                   vector_source="nvd" if m.get("source") == NVD_SOURCE else "cna")
    cwes = sorted({d["value"] for w in cve.get("weaknesses", [])
                   for d in w.get("description", []) if d.get("value", "").startswith("CWE-")})
    if cwes:
        rec["cwe"] = cwes
    return rec


def nvd_pages(params, headers, pause):
    start = 0
    while True:
        q = dict(params, resultsPerPage=NVD_PAGE, startIndex=start)
        url = NVD_URL + "?" + urllib.parse.urlencode(q).replace("hasKev=", "hasKev")
        data = json.loads(http_get(url, headers))
        yield data
        start += data["resultsPerPage"]
        log(f"  NVD {params} {min(start, data['totalResults'])}/{data['totalResults']}")
        time.sleep(pause)
        if start >= data["totalResults"] or data["resultsPerPage"] == 0:
            return


def windows(first, last):
    """Split [first, last] into NVD-sized publication windows."""
    day = dt.timedelta(days=1)
    lo = first
    while lo <= last:
        hi = min(lo + dt.timedelta(days=NVD_MAX_WINDOW_DAYS - 1), last)
        yield (lo.isoformat() + "T00:00:00.000", hi.isoformat() + "T23:59:59.999")
        lo = hi + day


def fetch_nvd(pub_ranges):
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    pause = 0.7 if key else 6.5
    queries = [{"hasKev": ""}]
    for first, last in pub_ranges:
        queries += [{"pubStartDate": a, "pubEndDate": b} for a, b in windows(first, last)]
    records = {}
    for params in queries:
        for page in nvd_pages(params, headers, pause):
            for v in page["vulnerabilities"]:
                records[v["cve"]["id"]] = slim_nvd(v["cve"])
    return records, queries


# --- EPSS --------------------------------------------------------------------

def fetch_epss(date, wanted):
    url = EPSS_URL.format(date=date)
    raw = http_get(url)
    text = gzip.decompress(raw).decode("utf-8")
    first, _, rest = text.partition("\n")
    meta = dict(part.split(":", 1) for part in first.lstrip("#").split(","))
    scores = {}
    for row in csv.DictReader(io.StringIO(rest)):
        if row["cve"] in wanted:
            scores[row["cve"]] = [float(row["epss"]), float(row["percentile"])]
    return url, raw, meta, scores


# --- main --------------------------------------------------------------------

def parse_range(text):
    a, sep, b = text.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD:YYYY-MM-DD")
    first, last = dt.date.fromisoformat(a), dt.date.fromisoformat(b)
    if last < first:
        raise argparse.ArgumentTypeError("range end before start")
    return first, last


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="data/snapshots")
    ap.add_argument("--date", default=dt.date.today().isoformat(),
                    help="snapshot name (default: today)")
    ap.add_argument("--epss-date", default=None,
                    help="EPSS score date (default: the day before --date)")
    ap.add_argument("--pub-range", type=parse_range, action="append", default=[],
                    help="add CVEs published in START:END to the NVD population "
                         "(repeatable)")
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    manifest_path = os.path.join(args.out, "MANIFEST.json")
    manifest = {"snapshots": {}}
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    if args.date in manifest["snapshots"]:
        sys.exit(f"snapshot {args.date} already exists; snapshots are never overwritten")
    epss_date = args.epss_date or (dt.date.fromisoformat(args.date)
                                   - dt.timedelta(days=1)).isoformat()
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    files = {}

    def write(name, data, entry):
        with open(os.path.join(args.out, name), "wb") as fh:
            fh.write(data)
        files[name] = {**entry, "sha256": sha256(data), "bytes": len(data)}
        log(f"wrote {name} ({len(data)} bytes)")

    log("KEV ...")
    kev_raw = http_get(KEV_URL)
    kev = json.loads(kev_raw)
    write(f"kev_{args.date}.json", kev_raw, {
        "kind": "kev", "url": KEV_URL, "retrieved": now,
        "records": len(kev["vulnerabilities"]),
        "catalog_version": kev.get("catalogVersion"),
        "note": "verbatim copy of the official CISA mirror"})

    log("NVD ...")
    nvd, queries = fetch_nvd(args.pub_range)
    population = {"has_kev": True,
                  "published": [[a.isoformat(), b.isoformat()] for a, b in args.pub_range]}
    write(f"nvd_{args.date}.json", dump_records(
        {"source": NVD_URL, "retrieved": now, "population": population,
         "fields": "published, status, vector (NVD own entry v3.1 then v3.0, else Primary, "
                   "else first CNA entry), base_score, exploitability_score, vector_source, cwe"},
        nvd), {"kind": "nvd", "url": NVD_URL, "retrieved": now, "records": len(nvd),
               "population": population, "queries": len(queries)})

    log(f"EPSS {epss_date} ...")
    wanted = set(nvd) | {v["cveID"] for v in kev["vulnerabilities"]}
    epss_url, epss_raw, meta, scores = fetch_epss(epss_date, wanted)
    write(f"epss_{epss_date}.json", dump_records(
        {"source": epss_url, "retrieved": now, "model_version": meta.get("model_version"),
         "score_date": meta.get("score_date"), "source_sha256": sha256(epss_raw),
         "fields": "[epss, percentile]; subset: CVEs of the NVD and KEV files"},
        scores), {"kind": "epss", "url": epss_url, "retrieved": now,
                  "records": len(scores), "model_version": meta.get("model_version"),
                  "score_date": meta.get("score_date"), "source_sha256": sha256(epss_raw)})

    manifest["snapshots"][args.date] = {"created": now, "files": files}
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    log(f"manifest updated: {manifest_path}")


if __name__ == "__main__":
    main()
