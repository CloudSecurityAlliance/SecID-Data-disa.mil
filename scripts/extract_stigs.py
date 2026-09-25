#!/usr/bin/env python3
r"""Extract structured STIG/SRG rules from a DISA SRG/STIG Library Compilation.

The compilation is a ZIP of ZIPs: one inner archive per STIG or SRG, each containing a
Manual XCCDF XML plus human-readable PDFs. We stream through it -- inner archives are
read into memory one at a time -- so a ~370 MB compilation never gets fully unpacked
to disk.

Output layout mirrors the SecID registry's reverse-DNS convention, so one path-derivation
algorithm works in every SecID-Data-* repository:

    secid:control/disa.mil/rhel-9@V2R9#V-257505
      -> data/control/mil/disa/rhel-9/V2R9/rules/V-257505.json
         \___/ \_____/ \_____/ \____/ \___/       \__________/
          data   type   domain   name  release      subpath
                     (reverse-DNS)

STIGs and SRGs both live under control/ because that is the SecID type both resolve as;
"SRG" survives as the `kind` field, not as a directory. Structure follows the identifier,
never the publisher's filing cabinet.

Output must stay byte-identical to the committed records when DISA has not changed a
document, or every ingest churns every file and `git diff v2026.04 v2026.07` stops meaning
"what DISA changed". Key order, the `extractor` value and the JSON formatting are therefore
part of the format: change them only in a commit that rewrites the data deliberately.

Usage:
    python3 scripts/extract_stigs.py path/to/U_SRG-STIG_Library_July_2026.zip
    python3 scripts/extract_stigs.py COMPILATION.zip --out /tmp/scratch   # write elsewhere
"""
import argparse, collections, hashlib, io, json, re, sys, zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

NAMESPACE = "disa.mil"      # the authority this repository holds
SECID_TYPE = "control"      # STIGs and SRGs both resolve as secid:control/...

DOC_RE = re.compile(
    r'^U_(?P<prod>.+?)_(?:V(?P<maj>\d+)R(?P<min>\d+)|Y(?P<yy>\d{2})M(?P<mm>\d{2}))_(?P<kind>STIG|SRG)\.zip$')

# DISA escapes a small block of pseudo-XML inside <description>. These are its fields.
DESC_FIELDS = ["VulnDiscussion", "FalsePositives", "FalseNegatives", "Documentable",
               "Mitigations", "SeverityOverrideGuidance", "PotentialImpacts",
               "ThirdPartyTools", "MitigationControl", "Responsibility", "IAControls"]
SEVERITY_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


def ns_of(root):
    return root.tag.split('}')[0].strip('{') if '}' in root.tag else ''


def text(el):
    if el is None:
        return None
    return ''.join(el.itertext()).strip() or None


def parse_description(raw):
    """DISA stuffs escaped pseudo-XML into <description>. Pull the fields out."""
    if not raw:
        return {}, None
    out = {}
    for f in DESC_FIELDS:
        m = re.search(rf'<{f}>(.*?)</{f}>', raw, re.S)
        if m:
            v = m.group(1).strip()
            if v:
                out[f] = v
    leftover = re.sub(r'<(' + '|'.join(DESC_FIELDS) + r')>.*?</\1>', '', raw, flags=re.S).strip()
    return out, (leftover or None)


def parse_xccdf(xml_bytes):
    root = ET.fromstring(xml_bytes)
    ns = ns_of(root)
    q = lambda t: f'{{{ns}}}{t}' if ns else t

    bench = {
        "benchmark_id": root.get('id'),
        "xccdf_namespace": ns,
        "title": text(root.find(q('title'))),
        "version": text(root.find(q('version'))),
        "status": text(root.find(q('status'))),
        "profiles": [],
        "rules": [],
    }
    st = root.find(q('status'))
    if st is not None:
        bench["status_date"] = st.get('date')

    for p in root.findall(q('Profile')):
        bench["profiles"].append({
            "id": p.get('id'),
            "title": text(p.find(q('title'))),
            "selects": len(p.findall(q('select'))),
        })

    rules = []
    for g in root.iter(q('Group')):
        for r in g.findall(q('Rule')):
            desc_fields, desc_rest = parse_description(
                r.find(q('description')).text if r.find(q('description')) is not None else None)
            idents = {}
            for i in r.findall(q('ident')):
                sysname = (i.get('system') or '').rstrip('/').split('/')[-1].lower()
                idents.setdefault(sysname, []).append(i.text)
            chk = r.find(q('check'))
            chk_content = None
            if chk is not None:
                cc = chk.find(q('check-content'))
                chk_content = text(cc)
            sev = r.get('severity')
            rule = {
                "vuln_id": g.get('id'),                 # V-257505  (stable across revisions)
                "rule_id": r.get('id'),                 # SV-257505r960759_rule
                "stig_id": text(r.find(q('version'))),  # CNTR-OS-000010
                "severity": sev,
                "severity_category": SEVERITY_CAT.get(sev),
                "weight": r.get('weight'),
                "title": text(r.find(q('title'))),
                "group_title": text(g.find(q('title'))),
                "idents": idents,                       # {"cci": ["CCI-000068"]}
                "check_id": chk.get('system') if chk is not None else None,
                "check_content": chk_content,
                "fixtext": text(r.find(q('fixtext'))),
                "fix_id": (r.find(q('fix')).get('id') if r.find(q('fix')) is not None else None),
            }
            rule.update({k: v for k, v in desc_fields.items()})
            if desc_rest:
                rule["description_other"] = desc_rest
            rules.append(rule)
    bench["rules"] = rules
    return bench


def dump(obj):
    """The one serialisation used for every record. See the module docstring."""
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def document_record(bench, rules, slug, version, kind, comp_name, archive, inner_sha):
    """Assemble stig.json in the committed key order.

    `secid` leads (the backfill commit put it there and every record has it there); the
    XCCDF-derived fields follow in the order parse_xccdf produces them; provenance and the
    path components come after; the rule list closes the record.
    """
    doc = {"secid": f"secid:{SECID_TYPE}/{NAMESPACE}/{slug}@{version}"}
    doc.update(bench)
    doc["provenance"] = {
        "source_compilation": comp_name,
        "inner_archive": archive,
        "inner_sha256": inner_sha,
        "extractor": "scripts/extract_stigs.py",
    }
    doc["slug"], doc["release"], doc["kind"] = slug, version, kind
    doc["rule_count"] = len(rules)
    doc["rule_index"] = [r["vuln_id"] for r in rules]
    return doc


def main():
    ap = argparse.ArgumentParser(description="Extract STIG/SRG rules from a DISA compilation.")
    ap.add_argument("compilation", help="path to U_SRG-STIG_Library_<Month>_<Year>.zip")
    ap.add_argument("--out", help="write data/ and indexes/ under this directory instead of the repository")
    args = ap.parse_args()
    comp = Path(args.compilation)
    repo = Path(args.out) if args.out else Path(__file__).resolve().parent.parent
    comp_name = comp.name

    stats = {"documents": 0, "rules": 0, "skipped": [], "no_xccdf": []}
    manifest = []

    with zipfile.ZipFile(comp) as outer:
        for info in sorted(outer.infolist(), key=lambda i: i.filename):
            m = DOC_RE.match(Path(info.filename).name)
            if not m:
                if info.filename.lower().endswith('.zip'):
                    stats["skipped"].append(Path(info.filename).name)
                continue
            slug = re.sub(r'[^a-z0-9]+', '-', m['prod'].lower()).strip('-')
            version = f"V{m['maj']}R{m['min']}" if m['maj'] else f"Y{m['yy']}M{m['mm']}"
            kind = m['kind']

            raw = outer.read(info)
            inner_sha = hashlib.sha256(raw).hexdigest()
            xml_bytes = None
            with zipfile.ZipFile(io.BytesIO(raw)) as inner:
                cands = [n for n in inner.namelist()
                         if n.lower().endswith('.xml') and 'xccdf' in n.lower()]
                manual = [n for n in cands if 'manual' in n.lower()] or cands
                if manual:
                    xml_bytes = inner.read(manual[0])
            if not xml_bytes:
                stats["no_xccdf"].append(Path(info.filename).name)
                continue

            bench = parse_xccdf(xml_bytes)
            rules = bench.pop("rules")
            archive = Path(info.filename).name

            # Rules are written one file per vuln_id, so a repeated ID would silently
            # overwrite the earlier rule while rule_index still listed it twice.
            counts = collections.Counter(r["vuln_id"] for r in rules)
            dupes = sorted((v for v, c in counts.items() if c > 1), key=str)
            if dupes:
                sys.exit(f"{archive}: duplicate vuln IDs within one document, refusing to write: "
                         f"{', '.join(map(str, dupes[:10]))}")

            doc = document_record(bench, rules, slug, version, kind, comp_name, archive, inner_sha)

            # reverse-DNS the namespace exactly as registry/<type>/<tld>/<domain> does
            domain_path = Path(*reversed(NAMESPACE.split(".")))
            base = repo / "data" / SECID_TYPE / domain_path / slug / version
            (base / "rules").mkdir(parents=True, exist_ok=True)
            (base / "stig.json").write_text(dump(doc))
            for r in rules:
                (base / "rules" / f'{r["vuln_id"]}.json').write_text(dump(r))

            stats["documents"] += 1
            stats["rules"] += len(rules)
            manifest.append({"slug": slug, "release": version, "kind": kind,
                             "rules": len(rules), "archive": archive})

    (repo / "indexes").mkdir(exist_ok=True)
    (repo / "indexes" / "corpus.json").write_text(json.dumps(
        {"source_compilation": comp_name, "documents": stats["documents"],
         "rules": stats["rules"], "entries": manifest}, indent=2) + "\n")

    print(f"{comp_name}: {stats['documents']} documents, {stats['rules']:,} rules")
    if stats["skipped"]:
        print(f"  skipped (not STIG/SRG): {len(stats['skipped'])} -> {', '.join(stats['skipped'])}")
    if stats["no_xccdf"]:
        print(f"  no XCCDF found: {len(stats['no_xccdf'])} -> {', '.join(stats['no_xccdf'][:5])}")


if __name__ == "__main__":
    main()
