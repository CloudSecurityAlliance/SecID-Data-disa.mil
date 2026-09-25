# Proposal: versioned resolution for DISA STIG rules

**Status:** Proposal, for discussion. This document changes no data and no code.
**Scope:** This repository, `SecID/scripts/sync-disa-stigs.py`, and one small change in
`SecID-Service/src/resolver.ts`.
**Measured against:** this repository at `v2026.07` (3d51236e), `SecID` `main` at f010a1e and
then 8e77597 (`registry/control/mil/disa.json`, `scripts/sync-disa-stigs.py`), `SecID-Service`
`main` at 8efac89, and the live resolver on 2026-09-24.

## Why

This repository keeps every release (the README's "Releases are retained, not replaced"), because
SCAP Compliance Checker runs one release behind the manual STIG, so scan results in the field
cite the previous release. The registry makes almost none of that history reachable. A SecID
naming an older release either resolves to the wrong record or resolves to nothing, and a
SecID naming a release that never existed is accepted as valid. That breaks the "honest
uncertainty" principle: the resolver claims knowledge it does not have.

## Findings

Each finding below was re-measured for this proposal. The method follows each finding.

### F1. Rule nodes returned no URL (fixed by SecID #196 while this was being written)

At f010a1e, a query for a **current** rule came back `found` but with no URL:

```
$ curl -s '.../api/v1/resolve?secid=secid:control/disa.mil/rhel-9@V2R9%23V-257777'
{"status":"found","results":[{"secid":"...#V-257777","data":{"description":"A single requirement
 within the RHEL 9 STIG, by DISA Vuln ID.","weight":100,"note":"DISA publishes no per-rule ..."}}]}
```

The cause: the sync wrote the rule template into `children[].data.urls[]`, but
`resolveChildUrl()` reads only `child.data.url`. SecID #196 (13e5e9d) fixed that. It moved the
template to `data.url`, added a structured example so SecID-Service tests the template, and
added `scripts/check-url-templates.py` as a guard. The same query now returns
`.../rhel-9/V2R9/rules/V-257777.json`. The finding is kept here because the fix is what makes
F3 below a live, silent wrong answer rather than a harmless one.

### F2. Only the current release of each document is reachable

`build_node()` hardcodes the current release into the rule URL (`rule_url_template()`:
`.../disa/{slug}/{version}/rules/{id}.json`, with `version` filled in by Python), enumerates
only that release's V-IDs, and lists only that release in `versions_available`.

| | count |
|---|---|
| Rule files in this repository | 53,674 |
| Rule files a registry node points at | 14,150 |
| **Rule files unreachable** | **39,524** |
| Distinct V-IDs overall | 18,502 |
| **Distinct V-IDs present only in non-current releases** | **4,352** |
| (slug, V-ID) pairs not in the slug's current release | 4,485 |

The 4,352 are worse than merely unreachable. A citation such as
`secid:control/disa.mil/rhel-9@V2R8#V-XXXXXX` for a rule DISA dropped in V2R9 matches no pattern,
so it gets `related` plus "did not match any known pattern". That reads as "this ID is wrong",
when the ID is valid and the record exists here.

### F3. `@version` is ignored, so any version is accepted

The DISA nodes do not set `version_required`, so `resolveSubpath()` takes the 2-level path and
never looks at `parsed.version`. It then echoes the caller's version back in the returned
SecID. Live:

```
secid:control/disa.mil/rhel-9@V9R99#V-257777   -> status "found", secid "...@V9R99#V-257777"
```

A release that never existed comes back as `found`. Since #196, it also comes back with a URL
pointing at the **V2R9** record. Re-checked live after #196:

```
secid:control/disa.mil/rhel-9@V9R99#V-257777
  -> "found", url ".../rhel-9/V2R9/rules/V-257777.json"
```

That is a silent wrong answer, and it happens for any version string, including real older
releases. `@V2R8#V-257777` gets the V2R9 text.

### F4. 52 documents vanished from the registry

The sync builds document nodes from the **latest compilation's manifest only**. When DISA drops
a document from a compilation, the registry node disappears, even though this repository still
holds every release of it.

- 226 slugs here, 175 document nodes in the registry.
- 52 slugs are in this repository and missing from the registry.
- `epas` is the one registry slug with no data; its archive contains no XCCDF.

Last compilation that still contained each dropped slug:

| Last seen | Slugs |
|---|---|
| April 2025 | 12 |
| July 2025 | 8 |
| October 2025 | 16 |
| January 2026 | 7 |
| April 2026 | 9 |

Examples:
- `apple-macos-26`: V1R1 in January 2026, V1R2 in April 2026, absent from July 2026.
- `ms-windows-server-2019`: V3R4 to V3R8 across five compilations, then absent from July 2026.
- `ms-windows-10`: V3R4 and V3R5.
- `pan`: Y25M04 in five compilations.

Windows Server 2019 is still widely deployed, and its STIG IDs appear in scan results today.

### F5. `provenance.source_compilation` churns on unchanged documents

`v2026.04` to `v2026.07` touches 174 `stig.json` files:
- 67 are new releases (added).
- **107 are modified, and every one of those 107 diffs is only `provenance.source_compilation`**
  changing from April to July. The inner archive's SHA-256 is identical and no other field
  moves.
- No rule file was modified. Rule records carry no provenance.

This matters for three reasons. The quarterly diff overstates what DISA changed. The field's
meaning is "the last compilation this release appeared in", which nobody would guess from its
name. And the first compilation a release appeared in, the fact a citation most needs, can
only be recovered from git history.

### F6. Rule records carry no `secid`, and the schema would not require one

`stig.json` has `secid` (required by `document.schema.json`). Rule records do not, and
`rule.schema.json` does not list it. A rule record fetched on its own, for example by URL,
does not say which SecID it answers. Its release is known only from the path it came from.

### F7. Rule URLs point at `main`, not at a tag

`https://raw.githubusercontent.com/CloudSecurityAlliance/SecID-Data-disa.mil/main/data/...`

Releases are retained, so a release path on `main` does not disappear and in that sense the
URLs are stable. Two real problems remain:
- **Ordering.** If the registry sync merges before this repository's ingest reaches `main`,
  every new rule URL 404s. Merging the registry deploys to the live resolver within about
  1m20s.
- **Mutability.** Content at a cited URL can change after citation. That is harmless for
  corrections like the `secid` backfill, but it is not the immutability a tag gives.

## What the resolver supports today

This is from `SecID-Service/src/resolver.ts` at 8efac89. It constrains every option below.

- **URL template variables** in `resolveChildUrl()`:
  - `{id}`, `{id_lower}` and `{id_upper}`, always set from the subpath
  - `{lang}`, from the `lang` qualifier
  - any variable declared in `child.data.variables`, extracted **from the subpath** by regex
    or lookup

  There is **no `{version}` variable**. `parsed.version` never reaches URL building.
- **`version_required: true`** switches a node to 3-level resolution (`resolveVersioned()`):
  `node → version child (patterns matched against @version) → item grandchildren`. An unknown
  version returns `not_found` with the list of available versions. This works today and is
  used elsewhere in the registry, e.g. OWASP Top 10.
- **`unversioned_behavior` is not implemented.** When a `version_required` node is queried
  without `@version`, the resolver always returns `related` plus "Specify @version". It passes
  `unversioned_behavior` through as data but does not act on it. That contradicts
  `SecID/docs/reference/VERSIONING.md`, which makes `"current"` the default and specifies
  "resolve to current version silently".
- **Unscoped cross-source search** walks `node.children` only. Under a 3-level layout those
  children are version nodes, so a bare `V-257777` search would stop matching STIG rules. That
  arguably finishes what SecID #189 started, since a V-ID alone does not say which STIG it
  belongs to.

## Proposed changes

The changes are ordered so that each one is useful alone, and so that the cheap, urgent fix
does not wait on the design discussion.

### P0. Write `data.url` on rule children (F1). Done in SecID #196.

Nothing left to do. P1 below keeps the `data.url` shape and #196's example-as-fixture pattern
for every per-release child. With all releases enumerated, that means one fixture per release,
about 500, rather than one per document. If that makes SecID-Service tests too slow, emit the
structured example only on the current release's child.

### P1. One node per document, one child per release, all releases enumerated (fixes F2, F3)

Use the 3-level layout the resolver already supports:

```jsonc
{
  "patterns": ["(?i)^rhel-9$"],
  "data": {
    "version_required": true,
    "unversioned_behavior": "current",
    "versions_available": [
      {"version": "V2R9", "status": "current",
       "first_seen": "U_SRG-STIG_Library_July_2026.zip", "last_seen": "U_SRG-STIG_Library_July_2026.zip"},
      {"version": "V2R8", "status": "superseded",
       "first_seen": "U_SRG-STIG_Library_April_2026.zip", "last_seen": "U_SRG-STIG_Library_April_2026.zip"}
      // ...
    ]
  },
  "children": [
    {"patterns": ["^V2R9$"], "description": "RHEL 9 STIG V2R9", "data": {...},
     "children": [{"patterns": ["^V-257777$", ...],
                   "data": {"url": ".../rhel-9/V2R9/rules/{id}.json", ...}}]},
    {"patterns": ["^V2R8$"], ...}
  ]
}
```

- Every release gets its own V-ID enumeration and its own hardcoded release in the URL, so a
  V-ID resolves only against releases that actually contain it. That handles the 4,352
  V-IDs that exist only in older releases, with no extra index needed at resolve time.
- An unknown `@version` returns `not_found` plus "Available: V2R9, V2R8, …". F3 closed.
- **Companion SecID-Service change:** implement `unversioned_behavior: "current"` in
  `resolveVersioned()`. When `@version` is absent, pick the version child whose
  `versions_available` entry has `status: "current"` and continue as if that version had been
  given. Also implement `current_with_history` (the same, plus a note listing other versions).
  This is a generic fix that brings the service into line with VERSIONING.md, not a
  DISA-specific hack. Without it, P1 would regress today's unversioned queries
  (`rhel-9#V-257777`) from `found` to `related`. **P1 must not merge before this does.**

**Why not a `{version}` template variable?** It is the obvious idea and does not work well:

1. The resolver does not support it. It would need a SecID-Service change anyway.
2. It accepts any version string and builds a URL for it, so `@V9R99` becomes a 404 URL rather
   than an honest `not_found`. F3 moves around instead of being fixed.
3. One pattern list per document cannot say which V-IDs exist in which release. Either the
   list is the union across releases, and `@V2R9#<V-ID dropped in V2R9>` builds a 404, or it
   is current-only, and F2 remains.

Per-release children encode existence exactly, and need no service change beyond the
`unversioned_behavior` fix above.

**Cost:**
- `disa.json` is 840 KB today with 14,150 enumerated V-IDs. Enumerating all 53,674 puts it
  near 3.2 MB.
- Recent quarters added 6,386 to 10,374 rule files each, so it grows by roughly 30,000
  patterns a year.
- That is well inside Cloudflare KV's 25 MiB value limit for several years. Resolution cost
  scales with the patterns in one document's release, not with the whole file, because the
  release is selected first.
- If growth becomes a problem, the lever is a retention window: enumerate releases from the
  compilations DISA still serves plus the previous N. Older releases stay in this repository
  and stay listed in `versions_available` with `status: "historical"`. This is not proposed
  now.

### P2. Build the document list from this repository, not from the compilation manifest (fixes F4)

- **This repository.** Generate a new index, `indexes/releases.json`, in `extract_stigs.py`, or
  better in a small `scripts/build_indexes.py` that walks `data/` so it is idempotent and
  independent of any one compilation:

  ```json
  {"rhel-9": {"kind": "STIG", "title": "...",
              "releases": [{"release": "V2R8", "rule_count": 447,
                            "first_seen": "U_SRG-STIG_Library_April_2026.zip",
                            "last_seen": "U_SRG-STIG_Library_April_2026.zip"},
                           {"release": "V2R9", "rule_count": 445,
                            "first_seen": "U_SRG-STIG_Library_July_2026.zip",
                            "last_seen": "U_SRG-STIG_Library_July_2026.zip"}],
              "in_latest": true}}
  ```

  `first_seen` and `last_seen` come from `indexes/compilations.json` plus each ingest. For the
  existing six quarters, backfill them from the `corpus.json` at each tag.
- **`sync-disa-stigs.py`.** Emit a node for every slug in `releases.json`:
  - A slug absent from the latest compilation keeps its node. Its newest release gets
    `status: "historical"` (not `current`), with a note naming the last compilation that
    carried it.
  - Keep reading the compilation manifest, but only as a cross-check: refuse to write if the
    manifest names a document the data repository lacks. That also closes the ordering hole
    in F7, because the sync cannot run ahead of the data.
  - Keep the slug-collision and clean-slug refusals.

### P3. Stop rewriting unchanged documents; record first and last seen (fixes F5)

Make `stig.json` byte-stable when DISA has not changed the document:

- Freeze the compilation field in `stig.json` at first ingest. Rename it
  `provenance.first_seen_compilation`, or keep the name `source_compilation` and document it as
  "first compilation"; the rename is clearer. Keep `inner_archive` and `inner_sha256` as they
  are: they identify the bytes, and the bytes do not change.
- Move "last seen" out of the record into `indexes/releases.json` (P2), where changing it
  every quarter is expected.
- In the extractor: when `data/<slug>/<release>/stig.json` already exists and its
  `inner_sha256` matches, leave the file alone. When it exists and the hash differs, stop:
  DISA republished a release under the same version, and a human should look.

Migration is one deliberate commit rewriting 511 `stig.json` files. Take `first_seen` from
`git log --diff-filter=A --format=%H` on each file mapped to its tag, and confirm it against
`v*/indexes/corpus.json`. After that, the next quarter's diff shows only real changes: in the
April-to-July 2026 case, 67 added releases instead of 174 touched files.

### P4. Rule `secid`: store it, or document the derivation (F6)

Option "store":

- Rule records gain a leading `"secid": "secid:control/disa.mil/<slug>@<release>#<V-ID>"`,
  matching `stig.json`'s leading `secid`.
- `rule.schema.json` adds `secid` to `required`. `document.schema.json` and `rule.schema.json`
  both gain a `pattern`: `^secid:control/disa\.mil/[a-z0-9][a-z0-9-]*@(V\d+R\d+|Y\d{2}M\d{2})(#V-\d+)?$`.
- `scripts/validate.py` (PR #2) already checks a rule `secid` against its path when one is
  present. Once the schema requires it, that check covers everything.

**Trade-off, measured.** Today 53,674 rule files dedupe to 21,364 distinct blobs, because an
unchanged rule is byte-identical across releases. A release-qualified `secid` makes every file
unique. I simulated the migration on a scratch clone (`git gc --aggressive` on both):

| | pack size |
|---|---|
| Today (6 quarters) | 17.72 MiB |
| After one commit adding a versioned `secid` to all 53,674 rules | 44.39 MiB (+26.7 MiB) |

Delta compression did **not** absorb it: roughly 0.5 KB per rewritten file. Going forward,
every rule in a new release becomes a new object instead of reusing the previous release's
blob. ADR-013 measured about 2 MiB per quarter; the likely cost is several times that. A
decade then lands in the low hundreds of MiB instead of about 100 MiB. That is still well
under GitHub's limits, but it undercuts ADR-013's "comfortable" margin and should be decided
explicitly, not slipped in.

Alternatives:

- **Unversioned rule `secid`** (`secid:control/disa.mil/rhel-9#V-257777`). Keeps deduplication,
  but names the wrong thing: the record at `V2R8/rules/V-257777.json` is the V2R8 text, and
  SecID's grammar expresses that as `@V2R8`. Not recommended.
- **No `secid` in rule files; derive it.** The path-to-SecID mapping is mechanical (ADR-014),
  so any consumer holding the path already has the SecID. Keep rule files as they are, and
  have the schema's description and the README state the derivation rule. The resolver
  returns the SecID alongside the URL in any case.

Recommendation: **derive, don't store**, unless a concrete consumer needs self-describing rule
files fetched without their path. F6 is then closed by documentation plus the validator's
existing check (a stored `secid`, if ever present, must match the path), not by a
53,674-file rewrite. If self-describing records are required, take the measured cost above
and do it in one deliberate commit.

### P5. Tags vs `main` in URLs (F7)

Recommendation: **keep `main`**, and make the ordering failure mechanically impossible
instead:

- P2's cross-check makes the sync refuse to write a release that is missing from the data
  repository checkout.
- Also add a pre-flight in `sync-disa-stigs.py`: HEAD the first rule URL of each release it is
  about to write (about 500 requests, or only the releases new since the previous registry
  state). Refuse if any returns 404, because that means the data has not reached `main` on
  GitHub yet.

Tag-pinned URLs, i.e. `.../SecID-Data-disa.mil/<tag>/data/...` with the tag of the ingest that
first contained the release, are rejected for now:
- Releases are retained, so `main` paths are already permanent.
- Pinning would freeze out legitimate record corrections such as the `secid` backfill or P4.
- It adds a second thing, the tag, that must exist before the sync can run.

If citable immutability becomes a requirement, add the tag alongside rather than instead:
record it as `versions_available[].data_tag`, so a client that needs immutability can build
the pinned URL itself.

## Order of work

| Step | Repo | Depends on | Fixes |
|---|---|---|---|
| ~~P0 `data.url` on rule children~~ | SecID | — | F1 (done, #196) |
| `unversioned_behavior` in `resolveVersioned()` | SecID-Service | — | (enables P1) |
| P3 byte-stable `stig.json`, first/last seen | this repo | PR #1 | F5 |
| P2 `indexes/releases.json` | this repo | P3 | F4 (data side) |
| P4 rule `secid`: document the derivation, or rewrite | this repo | decision on the measured cost | F6 |
| P1 + P2 + P5 sync rewrite | SecID | the three above | F2, F3, F4, F7 |

Each data-repository step is its own PR with a stated, deliberate data rewrite. The extractor
must reproduce the post-migration records byte for byte, the same standard PR #1 set.

## Measurement

Reproduce the figures above with:

```
# F2 / F4: compare data/ against registry document nodes (patterns[0] slug, versions_available[0])
# F5:
git diff --name-only --diff-filter=M v2026.04 v2026.07 -- 'data/**/stig.json'   # 107, all provenance-only
git diff --name-only --diff-filter=A v2026.04 v2026.07 -- 'data/**/stig.json'   # 67
# P4 dedup baseline:
git ls-tree -r HEAD data | awk '$4 ~ /\/rules\//{print $3}' | sort -u | wc -l   # 21,364 of 53,674
```

P4 pack simulation: `git clone --no-local` into scratch, prepend
`"secid": "secid:control/disa.mil/<slug>@<release>#<V-ID>"` to every rule file, commit,
`git gc --aggressive --prune=now`, then `git count-objects -vH`. Compare with the same `gc` on
an unmodified clone.
