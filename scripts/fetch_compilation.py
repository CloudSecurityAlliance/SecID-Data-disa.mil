#!/usr/bin/env python3
"""Download a DISA SRG/STIG Library Compilation and record its SHA-256.

Every stig.json already records the SHA-256 of its own inner archive. That proves which
bytes a record came from, but not which compilation those bytes arrived in, and DISA stops
serving a compilation after roughly six quarters. This script closes that gap. It streams
the whole compilation to disk, hashes it on the way, and records name, URL, size, SHA-256
and Last-Modified in indexes/compilations.json, one entry per compilation.

Re-fetching a compilation that is already recorded must produce the same hash. If it does
not, DISA has republished different bytes under the same name, and the script stops instead
of overwriting the record. Investigate before ingesting.

The zip is written outside git (*.zip is ignored). Keep the original: once DISA drops it,
nothing can reconstruct it (see README, "Archiving originals").

Usage:
    python3 scripts/fetch_compilation.py                        # newest published compilation
    python3 scripts/fetch_compilation.py U_SRG-STIG_Library_October_2026.zip
    python3 scripts/fetch_compilation.py --dest ~/stig-archive  # where the zip goes (default: .)
    python3 scripts/fetch_compilation.py --record PATH.zip      # hash a file you already have
"""
import argparse, hashlib, json, re, sys, urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

BASE = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip"
UA = {"User-Agent": "Mozilla/5.0 (SecID data ingest; +https://secid.cloudsecurityalliance.org)"}
MONTHS = ["January", "February", "March", "April", "May", "June",
          "July", "August", "September", "October", "November", "December"]
NAME_RE = re.compile(r"^U_SRG-STIG_Library_(?P<month>[A-Z][a-z]+)_(?P<year>\d{4})\.zip$")
LEDGER = Path(__file__).resolve().parent.parent / "indexes" / "compilations.json"


def head(url):
    """Return (size, last_modified) or None if the URL is absent."""
    try:
        req = urllib.request.Request(url, headers=dict(UA), method="HEAD")
        with urllib.request.urlopen(req, timeout=60) as r:
            return int(r.headers.get("Content-Length") or 0), r.headers.get("Last-Modified")
    except Exception:
        return None


def discover(today=None):
    """Newest compilation DISA is serving. Same quarter walk as SecID/scripts/sync-disa-stigs.py."""
    today = today or date.today()
    quarters = [1, 4, 7, 10]
    y, m = today.year, max((q for q in quarters if q <= today.month), default=None)
    if m is None:
        y, m = y - 1, 10
    for _ in range(8):
        name = f"U_SRG-STIG_Library_{MONTHS[m - 1]}_{y}.zip"
        if head(f"{BASE}/{name}"):
            return name
        i = quarters.index(m) - 1
        if i < 0:
            i, y = 3, y - 1
        m = quarters[i]
    sys.exit("Could not locate any SRG/STIG Library Compilation; check naming or connectivity.")


def download(name, dest):
    url = f"{BASE}/{name}"
    info = head(url)
    if not info:
        sys.exit(f"{url} is not being served (DISA drops compilations after ~6 quarters).")
    size, last_modified = info
    out = dest / name
    part = out.with_name(out.name + ".part")
    h = hashlib.sha256()
    got = 0
    req = urllib.request.Request(url, headers=dict(UA))
    with urllib.request.urlopen(req, timeout=120) as r, open(part, "wb") as fh:
        while chunk := r.read(1 << 20):
            fh.write(chunk)
            h.update(chunk)
            got += len(chunk)
    if size and got != size:
        part.unlink()
        sys.exit(f"{name}: received {got:,} bytes, Content-Length said {size:,}; not recorded.")
    part.rename(out)
    return out, h.hexdigest(), got, last_modified


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest(), path.stat().st_size


def chronological(name):
    m = NAME_RE.match(name)
    return (int(m["year"]), MONTHS.index(m["month"])) if m else (9999, 99)


def record(entry):
    ledger = json.loads(LEDGER.read_text()) if LEDGER.is_file() else {"compilations": []}
    existing = {e["name"]: e for e in ledger["compilations"]}
    prev = existing.get(entry["name"])
    if prev and prev["sha256"] != entry["sha256"]:
        sys.exit(f"{entry['name']}: SHA-256 {entry['sha256']} differs from the recorded "
                 f"{prev['sha256']}. DISA has republished different bytes under this name; "
                 f"the ledger was not changed.")
    if prev:
        print(f"{entry['name']}: already recorded, hash matches")
        return
    existing[entry["name"]] = entry
    ledger["compilations"] = sorted(existing.values(), key=lambda e: chronological(e["name"]))
    LEDGER.parent.mkdir(exist_ok=True)
    LEDGER.write_text(json.dumps(ledger, indent=2) + "\n")
    print(f"recorded {entry['name']} in {LEDGER.relative_to(LEDGER.parent.parent)}")


def main():
    ap = argparse.ArgumentParser(description="Download a DISA SRG/STIG compilation and record its SHA-256.")
    ap.add_argument("name", nargs="?", help="compilation file name; default: newest published")
    ap.add_argument("--dest", default=".", help="directory for the downloaded zip (default: .)")
    ap.add_argument("--record", metavar="ZIP", help="hash an already-downloaded compilation instead")
    args = ap.parse_args()

    if args.record:
        path = Path(args.record)
        name = path.name
        if not NAME_RE.match(name):
            sys.exit(f"{name} does not look like U_SRG-STIG_Library_<Month>_<Year>.zip")
        sha, size = hash_file(path)
        info = head(f"{BASE}/{name}")
        last_modified = info[1] if info else None
    else:
        name = args.name or discover()
        if not NAME_RE.match(name):
            sys.exit(f"{name} does not look like U_SRG-STIG_Library_<Month>_<Year>.zip")
        dest = Path(args.dest)
        dest.mkdir(parents=True, exist_ok=True)
        path, sha, size, last_modified = download(name, dest)

    print(f"{path}: {size:,} bytes, sha256 {sha}")
    record({
        "name": name,
        "url": f"{BASE}/{name}",
        "bytes": size,
        "sha256": sha,
        "last_modified": last_modified,
        "recorded": datetime.now(timezone.utc).date().isoformat(),
    })


if __name__ == "__main__":
    main()
