# SecID-Data-disa.mil

Structured DISA STIG and SRG content for [SecID](https://github.com/CloudSecurityAlliance/SecID).

DISA publishes STIGs as XCCDF XML inside per-document ZIPs inside a quarterly compilation.
There is **no per-rule permalink upstream** — you cannot link to `V-257505` anywhere on
cyber.mil. This repository exists so that a SecID for a rule resolves to something.

## Layout

Standard for every `SecID-Data-*` repository, mirroring the registry's reverse-DNS convention
so one path-derivation algorithm works everywhere:

```
data/         extracted content, addressed by SecID
schemas/      JSON Schema for the record formats
scripts/      acquisition and extraction tooling
indexes/      generated cross-references — never hand-edited
docs/         how it works, source quirks, provenance
```

A SecID maps to a path mechanically:

```
secid:control/disa.mil/rhel-9@V2R9#V-257505
   -> data/control/mil/disa/rhel-9/V2R9/rules/V-257505.json
      ────  ───────  ────────  ──────  ────       ──────────
      data    type    domain    name  release      subpath
                  (reverse-DNS)
```

STIGs and SRGs both live under `control/` because that is the SecID type both resolve as.
`kind` distinguishes them as a field, not as a directory — structure follows the identifier,
never the publisher's filing cabinet.

## Identifiers

Each rule carries four, and they are not interchangeable:

| Field | Example | Notes |
|---|---|---|
| `vuln_id` | `V-257505` | Stable across revisions. This is the subpath. |
| `rule_id` | `SV-257505r960759_rule` | Carries a revision counter; changes when the rule changes. |
| `stig_id` | `CNTR-OS-000010` | Human-facing, per-benchmark prefix. |
| `idents.cci` | `CCI-000068` | Maps to NIST SP 800-53. A rule may carry several. |

`idents.legacy` holds superseded V/SV numbers where DISA recorded them, so historical
citations still resolve.

Severity maps to the familiar categories: `high` = CAT I, `medium` = CAT II, `low` = CAT III.

## Versions

Both DISA schemes are present, and DISA is mid-migration between them:

- `V<major>R<minor>` — e.g. `V2R9`
- `Y<yy>M<mm>` — e.g. `Y26M07`

Releases are **retained, not replaced**. Latest-1 matters in practice: SCAP Compliance
Checker ships SCAP content one release behind the manual STIG, so scan results in the field
routinely reference the older release.

## Provenance

Every `stig.json` records the source compilation, the inner archive name, and its SHA-256.
Each quarterly ingest is a single commit, tagged `vYYYY.MM`.

```
git diff v2026.04 v2026.07 -- data/    # what DISA changed last quarter
git log -- data/control/mil/disa/rhel-9/   # every release of one STIG
```

## Refreshing

```
python3 scripts/extract_stigs.py path/to/U_SRG-STIG_Library_October_2026.zip
git add -A && git commit -m "Ingest SRG/STIG Library Compilation October 2026"
git tag v2026.10
```

DISA retains roughly six quarterly compilations; older ones return 404 and cannot be
reconstructed, since per-STIG URLs also 404 once superseded. Ingest promptly.

## Not included

- **SCAP benchmarks** — absent from the compilation; only ~11 exist and they lag the manual STIG.
- **GPOs and SRR tools** — excluded by DISA from the compilation. Classification is an open
  question; see [SecID issue #186](https://github.com/CloudSecurityAlliance/SecID/issues/186).
- **PDFs** — overview, revision history and release memos are ~80% of the payload and carry no
  referenceable content. Originals belong in object storage, not git.

## Licence

DISA STIGs are US Government work in the public domain. Extraction tooling is CC0.
