# threat-feed

A daily digest of vulnerabilities that attackers are actively exploiting.

Every morning a GitHub Action pulls the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, scores each entry with [FIRST EPSS](https://www.first.org/epss/) (the estimated probability of exploitation in the next 30 days), and publishes a digest:

- what CISA added since the last run
- which vulnerabilities had the biggest jump in exploit probability
- the ten most likely to be exploited right now
- federal remediation deadlines in the coming week
- my own analyst notes for the day

Digests live in [`digests/`](digests/), organized by year and month.

<!-- digest:start -->
**Latest digest: [2026-11-07](digests/2026/11/2026-11-07.md)** · 1,769 KEV entries · 1 new

Highest EPSS right now:

- [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619) PHP Group PHP · >99.9%
- [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) PHP Group PHP · >99.9%
- [CVE-2025-53770](https://nvd.nist.gov/vuln/detail/CVE-2025-53770) Microsoft SharePoint · >99.9%
- [CVE-2021-26086](https://nvd.nist.gov/vuln/detail/CVE-2021-26086) Atlassian Jira Server and Data Center · >99.9%
- [CVE-2024-7593](https://nvd.nist.gov/vuln/detail/CVE-2024-7593) Ivanti Virtual Traffic Manager · >99.9%
<!-- digest:end -->

## Using it locally

Python 3.9+ and no dependencies.

```bash
python threatfeed.py update          # fetch the latest data and write today's digest
python threatfeed.py latest          # added to KEV in the last 7 days (--days N)
python threatfeed.py search fortinet # search CVE, vendor, product or keyword
python threatfeed.py search vpn --ransomware
python threatfeed.py show CVE-2023-4966
python threatfeed.py top             # highest EPSS scores (-n 20, --ransomware)
python threatfeed.py due             # remediation deadlines in the next 14 days
python threatfeed.py stats           # breakdown by vendor, year and weakness (CWE)
python threatfeed.py note "Citrix Bleed still near the top; worth checking any NetScaler exposure"
```

`note` adds a timestamped line to today's digest. Commit and push it, and the next automated run keeps it.

## How it works

| Piece | What it does |
|---|---|
| `threatfeed.py` | Fetching, scoring, digest writing and the command-line interface (standard library only) |
| `data/kev.json` | Local copy of the catalog with current and previous EPSS scores |
| `digests/YYYY/MM/YYYY-MM-DD.md` | One digest per day |
| `site/latest.json` | Small summary the portfolio at wooshied.github.io loads live |
| `.github/workflows/daily.yml` | Runs tests, then `update`, and commits the result every day at 14:17 UTC |
| `tests/` | Offline unit tests for merging, scoring and digest output |

Run the tests with `python -m unittest discover -s tests`.

Data is public and comes straight from CISA and FIRST; this project adds no information of its own beyond the analyst notes.
