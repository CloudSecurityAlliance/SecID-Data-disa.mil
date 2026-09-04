# How extraction works

## Source

The quarterly **SRG/STIG Library Compilation** at
`https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SRG-STIG_Library_<Month>_<Year>.zip`
— the same artifact every other STIG consumer ingests.

We deliberately do **not** scrape `public.cyber.mil/stigs/downloads`. That catalogue is a
Salesforce Experience Cloud app: download URLs live in `data-link` attributes on
`button.downloadButton` inside Lightning shadow DOM, served from an undocumented
`/webruntime/api` endpoint. It works today and would break silently.

## Streaming

The compilation is ~370 MB and is never fully unpacked. A ZIP's central directory sits at the
end of the archive, so the manifest is readable with two range requests (~150 KB). Inner
archives are then read into memory one at a time.

## What is parsed

Each inner archive holds a Manual XCCDF XML plus PDFs. Only the XCCDF is extracted.

Structure is `Benchmark → Group → Rule`. The XCCDF namespace is read from the root element
rather than hardcoded, since DISA ships both 1.1 and (increasingly) 1.2.

### The escaped-XML trap

DISA stuffs pseudo-XML into `<description>` as **escaped text**:

```
<VulnDiscussion>...</VulnDiscussion><FalsePositives></FalsePositives>...
```

A naive parser treats this as an opaque string and loses `VulnDiscussion`, which is the
substantive rationale for the rule. The extractor unpacks these fields into the record and
keeps any leftover text as `description_other`.

## Known quirks

- **Two version schemes.** `V<major>R<minor>` and `Y<yy>M<mm>` are both live.
- **Not every archive has an XCCDF.** `U_EPAS_V2R1_STIG.zip` contains none.
- **Five archives are not STIG/SRG documents** and are skipped: `Traditional_Security_Checklist`
  and four `zOS` product/SRR bundles.
- **Document count drifts down while rule count holds** — 190 documents in April 2025 versus
  174 in July 2026, both near 14,000 rules. DISA is consolidating documents, not shrinking coverage.
- **Slugs must stay clean literals.** They become registry `patterns[0]` values; anything that is
  not `[a-z0-9-]+` triggers the description-slug canonical-name defect
  ([SecID #181](https://github.com/CloudSecurityAlliance/SecID/issues/181)). The sync script
  refuses to write if a slug fails that check.
