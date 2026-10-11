# Labelling the held-out set

These 20 cases were picked by a fixed rule (`cveprio holdout-select`, seed in `cases.json`).
**Label them yourself, from the sources, before you run the evaluation or look at the tool's output
for these CVEs.** Otherwise you will be marking the tool's homework with its own answers.

## What to fill in (`labels.csv`; open it in Excel, Numbers or Google Sheets)

| Column | Allowed values | Meaning |
|---|---|---|
| `expected_applicability` | `affected`, `not_affected`, `needs_review`, `no_product_match` | Is THIS software version affected? Use `needs_review` if a careful analyst could not decide from the public sources. For "(none: CVE only)" rows use `no_product_match`. |
| `acceptable_decisions` | one or more of `P1 P2 P3 P4 NEEDS_REVIEW NOT_APPLICABLE NOT_IN_INVENTORY`, separated by spaces | Every outcome you would defend for this system and context. P1 fix now · P2 next patch cycle · P3 schedule · P4 low priority. |
| `rationale` | free text | One or two sentences: which source fact you relied on. |

Tip: decide applicability from NVD's "Known Affected Software Configurations" or the vendor advisory;
decide priority from: is it being attacked (CISA KEV), how severe, and how exposed the system in the
`context` column is. "CVE only" rows have no inventory, so the tool's answer is provisional.

When done, set `review_status` in `cases.json` to `labelled_by_author` and run:

```bash
cveprio evaluate --set holdout
```

## Cases

| ID | CVE | Pool | Software (version) | Context |
|---|---|---|---|---|
| h01 | [CVE-2026-15409](https://nvd.nist.gov/vuln/detail/CVE-2026-15409) | KEV | —  | internet-facing, high importance |
| h02 | [CVE-2026-53266](https://nvd.nist.gov/vuln/detail/CVE-2026-53266) | KEV | linux_kernel 5.5 | internal, medium importance |
| h03 | [CVE-2026-71362](https://nvd.nist.gov/vuln/detail/CVE-2026-71362) | KEV | commerce 2.4.4 | internal, low importance, firewall restricts access |
| h04 | [CVE-2026-72529](https://nvd.nist.gov/vuln/detail/CVE-2026-72529) | KEV | trueconf_server 5.3.9.10013 | no context recorded |
| h05 | [CVE-2026-84869](https://nvd.nist.gov/vuln/detail/CVE-2026-84869) | KEV | screenconnect 26.6.5.9742 | internet-facing, high importance |
| h06 | [CVE-2025-68686](https://nvd.nist.gov/vuln/detail/CVE-2025-68686) | KEV | fortios 7.4.7 | internal, medium importance |
| h07 | [CVE-2026-34486](https://nvd.nist.gov/vuln/detail/CVE-2026-34486) | KEV | tomcat 9.0.116 | internal, low importance, firewall restricts access |
| h08 | [CVE-2026-81963](https://nvd.nist.gov/vuln/detail/CVE-2026-81963) | KEV | windows_11_23h2 10.0.22631.7582 | no context recorded |
| h09 | [CVE-2026-63041](https://nvd.nist.gov/vuln/detail/CVE-2026-63041) | HIGH | apisix 3.11.0 | internet-facing, high importance |
| h10 | [CVE-2026-47896](https://nvd.nist.gov/vuln/detail/CVE-2026-47896) | HIGH | lucene.net 4.8.0 | internal, medium importance |
| h11 | [CVE-2026-58187](https://nvd.nist.gov/vuln/detail/CVE-2026-58187) | HIGH | traffic_server 8.0.0 | internal, low importance, firewall restricts access |
| h12 | [CVE-2026-58036](https://nvd.nist.gov/vuln/detail/CVE-2026-58036) | HIGH | mediawiki 1.46.0 | no context recorded |
| h13 | [CVE-2026-15793](https://nvd.nist.gov/vuln/detail/CVE-2026-15793) | HIGH | buildkit 0.30.0 | internet-facing, high importance |
| h14 | [CVE-2026-100846](https://nvd.nist.gov/vuln/detail/CVE-2026-100846) | HIGH | monai 1.5.2 | internal, medium importance |
| h15 | [CVE-2026-71180](https://nvd.nist.gov/vuln/detail/CVE-2026-71180) | HIGH | update_package_framework 26.07.03 | internal, low importance, firewall restricts access |
| h16 | [CVE-2026-58059](https://nvd.nist.gov/vuln/detail/CVE-2026-58059) | HIGH | bc-java 1.85 | no context recorded |
| h17 | [CVE-2026-85014](https://nvd.nist.gov/vuln/detail/CVE-2026-85014) | PKG (SBOM path) | pkg:npm/undici@7.0.0 7.0.0 | internet-facing, high importance |
| h18 | [CVE-2026-77274](https://nvd.nist.gov/vuln/detail/CVE-2026-77274) | PKG (SBOM path) | pkg:pypi/mcp-atlassian@0.22.0 0.22.0 | internal, medium importance |
| h19 | [CVE-2026-69254](https://nvd.nist.gov/vuln/detail/CVE-2026-69254) | PKG (SBOM path) | pkg:npm/flowise@3.1.3 3.1.3 | internal, low importance, firewall restricts access |
| h20 | [CVE-2025-71390](https://nvd.nist.gov/vuln/detail/CVE-2025-71390) | PKG (SBOM path) | pkg:cargo/SurrealDB@2.1.8 2.1.8 | no context recorded |
