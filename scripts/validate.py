#!/usr/bin/env python3
"""Validate every record in data/ against schemas/ and against the repository's own layout.

Two classes of check, because either can break resolution on its own:

Schema (JSON Schema Draft 2020-12)
    every stig.json against schemas/document.schema.json
    every rules/<V-ID>.json against schemas/rule.schema.json

Consistency (things a schema cannot see)
    - the path is data/control/mil/disa/<slug>/<release>/, and stig.json's slug and
      release match it -- a SecID maps to a path mechanically (ADR-014), so a record
      filed under the wrong directory is unreachable
    - stig.json's secid is exactly secid:control/disa.mil/<slug>@<release>
    - rule_index has no duplicates, rule_count == len(rule_index), and rule_index is
      exactly the set of files in rules/ -- the registry enumerates V-IDs from
      rule_index, so a missing file is a link that 404s
    - each rule's vuln_id matches its filename, and a rule secid, where present, is the
      document secid plus #<vuln_id>
    - indexes/corpus.json agrees with the release directories it names
    - every provenance.source_compilation is recorded in indexes/compilations.json, so
      each record traces back to a compilation whose whole-archive SHA-256 is known

Requires the `jsonschema` package (pip install jsonschema). Exits 1 on any failure.

Usage:
    python3 scripts/validate.py            # validate the repository this script lives in
    python3 scripts/validate.py --root DIR
"""
import argparse, json, os, re, sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit("jsonschema is required: pip install jsonschema")

NAMESPACE = "disa.mil"
SECID_TYPE = "control"
MAX_REPORTED = 200


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    args = ap.parse_args()
    root = Path(args.root)

    errors = []

    def err(path, msg):
        errors.append(f"{path}: {msg}")

    validators = {}
    for name in ("document", "rule"):
        schema = json.loads((root / "schemas" / f"{name}.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema)

    def load(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError) as e:
            err(path.relative_to(root), f"unreadable JSON: {e}")
            return None

    def schema_check(kind, path, obj):
        for e in validators[kind].iter_errors(obj):
            loc = "/".join(map(str, e.absolute_path)) or "(root)"
            err(path.relative_to(root), f"schema: {loc}: {e.message}")

    base = root / "data" / SECID_TYPE / Path(*reversed(NAMESPACE.split(".")))
    if not base.is_dir():
        sys.exit(f"{base} does not exist")

    ledger_path = root / "indexes" / "compilations.json"
    recorded = None
    if ledger_path.is_file():
        ledger = load(ledger_path)
        if ledger is not None:
            recorded = {e.get("name") for e in ledger.get("compilations", [])}

    releases = {}   # (slug, release) -> rule_count
    n_docs = n_rules = 0

    for slug in sorted(os.listdir(base)):
        sdir = base / slug
        if not sdir.is_dir():
            err(sdir.relative_to(root), "unexpected file (expected only <slug>/ directories)")
            continue
        for release in sorted(os.listdir(sdir)):
            rdir = sdir / release
            rel = rdir.relative_to(root)
            if not rdir.is_dir():
                err(rel, "unexpected file (expected only <release>/ directories)")
                continue
            doc_path = rdir / "stig.json"
            if not doc_path.is_file():
                err(rel, "missing stig.json")
                continue
            extra = set(os.listdir(rdir)) - {"stig.json", "rules"}
            if extra:
                err(rel, f"unexpected entries: {sorted(extra)}")

            doc = load(doc_path)
            if doc is None:
                continue
            n_docs += 1
            schema_check("document", doc_path, doc)

            if doc.get("slug") != slug:
                err(rel, f"slug {doc.get('slug')!r} does not match directory {slug!r}")
            if doc.get("release") != release:
                err(rel, f"release {doc.get('release')!r} does not match directory {release!r}")
            doc_secid = f"secid:{SECID_TYPE}/{NAMESPACE}/{slug}@{release}"
            if doc.get("secid") != doc_secid:
                err(rel, f"secid {doc.get('secid')!r}, expected {doc_secid!r}")

            source = (doc.get("provenance") or {}).get("source_compilation")
            if recorded is not None and source not in recorded:
                err(rel, f"source_compilation {source!r} is not recorded in indexes/compilations.json")

            index = doc.get("rule_index") or []
            if len(set(index)) != len(index):
                dupes = sorted({v for v in index if index.count(v) > 1})
                err(rel, f"rule_index has duplicates: {dupes[:10]}")
            if doc.get("rule_count") != len(index):
                err(rel, f"rule_count {doc.get('rule_count')} != len(rule_index) {len(index)}")
            releases[(slug, release)] = doc.get("rule_count")

            rules_dir = rdir / "rules"
            files = set(os.listdir(rules_dir)) if rules_dir.is_dir() else set()
            stems = {f[:-5] for f in files if f.endswith(".json")}
            if files - {f"{s}.json" for s in stems}:
                err(rel, f"non-JSON files in rules/: {sorted(files - {s + '.json' for s in stems})[:10]}")
            missing = set(index) - stems
            orphans = stems - set(index)
            if missing:
                err(rel, f"{len(missing)} rule(s) in rule_index have no file: {sorted(missing)[:10]}")
            if orphans:
                err(rel, f"{len(orphans)} rule file(s) not in rule_index: {sorted(orphans)[:10]}")

            for stem in sorted(stems):
                rpath = rules_dir / f"{stem}.json"
                rule = load(rpath)
                if rule is None:
                    continue
                n_rules += 1
                schema_check("rule", rpath, rule)
                if rule.get("vuln_id") != stem:
                    err(rpath.relative_to(root), f"vuln_id {rule.get('vuln_id')!r} does not match filename")
                if "secid" in rule and rule["secid"] != f"{doc_secid}#{stem}":
                    err(rpath.relative_to(root), f"secid {rule['secid']!r}, expected {doc_secid}#{stem!r}")

    corpus_path = root / "indexes" / "corpus.json"
    if corpus_path.is_file():
        corpus = load(corpus_path)
        if corpus is not None:
            entries = corpus.get("entries", [])
            for e in entries:
                key = (e.get("slug"), e.get("release"))
                if key not in releases:
                    err("indexes/corpus.json", f"entry {key} has no release directory")
                elif releases[key] != e.get("rules"):
                    err("indexes/corpus.json", f"entry {key} says {e.get('rules')} rules, stig.json says {releases[key]}")
            if corpus.get("documents") != len(entries):
                err("indexes/corpus.json", f"documents {corpus.get('documents')} != {len(entries)} entries")
            if corpus.get("rules") != sum(e.get("rules", 0) for e in entries):
                err("indexes/corpus.json", "rules total does not equal the sum of entries")

    print(f"checked {n_docs} documents, {n_rules:,} rules")
    if errors:
        for line in errors[:MAX_REPORTED]:
            print(f"  FAIL {line}")
        if len(errors) > MAX_REPORTED:
            print(f"  ... and {len(errors) - MAX_REPORTED} more")
        print(f"{len(errors)} error(s)")
        sys.exit(1)
    print("all records valid")


if __name__ == "__main__":
    main()
