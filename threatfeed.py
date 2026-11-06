#!/usr/bin/env python3
"""threat-feed: a daily digest of actively exploited vulnerabilities.

Pulls the CISA Known Exploited Vulnerabilities (KEV) catalog and FIRST EPSS
exploit-probability scores, keeps a local copy in data/kev.json, and writes a
Markdown digest for each day under digests/.

Run `python threatfeed.py --help` for commands. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "kev.json"
STATE = ROOT / "data" / "state.json"
DIGESTS = ROOT / "digests"
README = ROOT / "README.md"
SITE_JSON = ROOT / "site" / "latest.json"
REPO_URL = "https://github.com/WooShied/threat-feed"
SITE_SCHEMA = 1

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
EPSS_BATCH = 100
USER_AGENT = "threat-feed/1.0 (+https://github.com/WooShied/threat-feed)"

NOTES_HEADING = "## Analyst notes"
README_START = "<!-- digest:start -->"
README_END = "<!-- digest:end -->"


# --------------------------------------------------------------------------- fetching

def fetch_json(url: str, retries: int = 3, timeout: int = 30) -> dict:
    """GET a URL and parse JSON, retrying with backoff on network errors."""
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            time.sleep(2 ** attempt * 2)
    raise RuntimeError(f"Could not fetch {url}: {last}")


def fetch_kev() -> dict:
    return fetch_json(KEV_URL)


def fetch_epss(cves: list[str]) -> tuple[dict[str, tuple[float, float]], str | None]:
    """Return {cve: (epss, percentile)} and the EPSS model date."""
    scores: dict[str, tuple[float, float]] = {}
    model_date = None
    for i in range(0, len(cves), EPSS_BATCH):
        chunk = cves[i : i + EPSS_BATCH]
        body = fetch_json(EPSS_URL + ",".join(chunk) + f"&limit={len(chunk)}")
        for row in body.get("data", []):
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            model_date = row.get("date", model_date)
    return scores, model_date


# --------------------------------------------------------------------------- storage

def load_records() -> dict[str, dict]:
    if not DATA.exists():
        return {}
    return {r["cve"]: r for r in json.loads(DATA.read_text(encoding="utf-8"))}


def save_records(records: dict[str, dict]) -> None:
    DATA.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(records.values(), key=lambda r: (r["added"], r["cve"]), reverse=True)
    DATA.write_text(json.dumps(rows, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def load_state() -> dict:
    return json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}


def save_state(state: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=1) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- core logic

def merge_kev(records: dict[str, dict], kev: dict, today: str) -> list[str]:
    """Merge the KEV catalog into records. Returns CVE IDs first seen today.

    On the very first run nothing is "seen" yet, so each entry's first_seen is
    its CISA dateAdded; otherwise new entries get today's date.
    """
    first_run = not records
    new: list[str] = []
    for v in kev.get("vulnerabilities", []):
        cve = v["cveID"]
        rec = records.get(cve, {})
        if not rec:
            rec["first_seen"] = v["dateAdded"] if first_run else today
        rec.update(
            cve=cve,
            vendor=v.get("vendorProject", ""),
            product=v.get("product", ""),
            name=v.get("vulnerabilityName", ""),
            added=v.get("dateAdded", ""),
            due=v.get("dueDate", ""),
            ransomware=v.get("knownRansomwareCampaignUse", "Unknown") == "Known",
            description=v.get("shortDescription", ""),
            action=v.get("requiredAction", ""),
            cwes=v.get("cwes", []),
            notes=v.get("notes", ""),
        )
        records[cve] = rec
        if rec["first_seen"] == today:
            new.append(cve)
    if first_run:
        # Nothing to diff against yet, so report the past week instead.
        week_ago = (date.fromisoformat(today) - timedelta(days=7)).isoformat()
        new = [c for c, r in records.items() if r["added"] >= week_ago]
    return new


def apply_epss(records: dict[str, dict], scores: dict[str, tuple[float, float]], model_date: str | None) -> None:
    """Store new EPSS scores, keeping the previous day's score for change tracking."""
    for cve, (score, pct) in scores.items():
        rec = records.get(cve)
        if rec is None:
            continue
        if rec.get("epss_date") != model_date:
            rec["epss_prev"] = rec.get("epss")
        rec["epss"], rec["epss_pct"], rec["epss_date"] = score, pct, model_date


def movers(records: dict[str, dict], n: int = 5) -> list[tuple[dict, float]]:
    deltas = [
        (r, r["epss"] - r["epss_prev"])
        for r in records.values()
        if r.get("epss") is not None and r.get("epss_prev") is not None
    ]
    deltas = [d for d in deltas if abs(d[1]) >= 0.001]
    deltas.sort(key=lambda d: d[1], reverse=True)
    return deltas[:n]


def top_epss(records: dict[str, dict], n: int = 10, ransomware: bool = False) -> list[dict]:
    rows = [r for r in records.values() if r.get("epss") is not None and (r["ransomware"] or not ransomware)]
    return sorted(rows, key=lambda r: (r["epss"], r["added"]), reverse=True)[:n]


def due_within(records: dict[str, dict], today: date, days: int) -> list[dict]:
    end = (today + timedelta(days=days)).isoformat()
    start = today.isoformat()
    return sorted((r for r in records.values() if start <= r["due"] <= end), key=lambda r: r["due"])


# --------------------------------------------------------------------------- markdown

def pct(x: float | None) -> str:
    if x is None:
        return "n/a"
    return ">99.9%" if x >= 0.9995 else f"{x * 100:.1f}%"


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def nvd(cve: str) -> str:
    return f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})"


def table(rows: list[dict], extra: tuple[str, callable] | None = None) -> str:
    head = "| CVE | Vendor / product | Vulnerability | Ransomware | EPSS |"
    sep = "|---|---|---|---|---|"
    if extra:
        head += f" {extra[0]} |"
        sep += "---|"
    lines = [head, sep]
    for r in rows:
        line = (
            f"| {nvd(r['cve'])} | {cell(r['vendor'])} / {cell(r['product'])} | {cell(r['name'])} "
            f"| {'Known' if r['ransomware'] else '-'} | {pct(r.get('epss'))} |"
        )
        if extra:
            line += f" {extra[1](r)} |"
        lines.append(line)
    return "\n".join(lines)


def digest_path(day: str) -> Path:
    y, m, _ = day.split("-")
    return DIGESTS / y / m / f"{day}.md"


def existing_notes(path: Path) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    idx = text.find(NOTES_HEADING)
    if idx < 0:
        return ""
    body = text[idx + len(NOTES_HEADING):].partition("\n---\n")[0].strip()
    return "" if body == "_None yet._" else body


def build_digest(records: dict[str, dict], new: list[str], kev_meta: dict, day: date, epss_ok: bool, notes: str) -> str:
    total = len(records)
    ransom = sum(r["ransomware"] for r in records.values())
    new_rows = sorted((records[c] for c in new), key=lambda r: r.get("epss") or 0, reverse=True)
    out = [
        f"# Threat digest · {day.isoformat()}",
        "",
        f"- **{total:,}** vulnerabilities in the CISA KEV catalog "
        f"(version {kev_meta.get('catalogVersion', '?')}), **{ransom:,}** linked to ransomware",
        f"- **{len(new)}** new {'entry' if len(new) == 1 else 'entries'} since the last run",
    ]
    if not epss_ok:
        out.append("- EPSS scores were not refreshed on this run; values below are from the last successful run")
    out += ["", "## New in KEV", ""]
    if new_rows:
        out.append(table(new_rows, ("Fix due", lambda r: r["due"])))
        out.append("")
        for r in new_rows:
            out.append(f"- **{r['cve']}**: {cell(r['description'])}")
    else:
        out.append("No new entries today.")

    mv = movers(records)
    out += ["", "## Biggest EPSS movers", ""]
    if mv:
        out.append(table([r for r, _ in mv], ("Change", lambda r: f"{(r['epss'] - r['epss_prev']) * 100:+.1f} pts")))
    else:
        out.append("No significant changes since the previous scores.")

    out += ["", "## Most likely to be exploited (top 10 by EPSS)", "", table(top_epss(records))]

    due = due_within(records, day, 7)
    out += ["", "## Federal remediation deadlines in the next 7 days", ""]
    out.append(table(due, ("Due", lambda r: r["due"])) if due else "None.")

    out += ["", NOTES_HEADING, "", notes or "_None yet._", ""]
    out += [
        "---",
        "Sources: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · "
        "[FIRST EPSS](https://www.first.org/epss/). EPSS is the estimated probability of "
        "exploitation activity in the next 30 days.",
        "",
    ]
    return "\n".join(out)


def update_readme(day: str, total: int, new_count: int, top: list[dict]) -> None:
    if not README.exists():
        return
    text = README.read_text(encoding="utf-8")
    if README_START not in text or README_END not in text:
        return
    rel = digest_path(day).relative_to(ROOT).as_posix()
    lines = [
        README_START,
        f"**Latest digest: [{day}]({rel})** · {total:,} KEV entries · {new_count} new",
        "",
        "Highest EPSS right now:",
        "",
    ]
    lines += [f"- {nvd(r['cve'])} {cell(r['vendor'])} {cell(r['product'])} · {pct(r['epss'])}" for r in top[:5]]
    lines.append(README_END)
    head, rest = text.split(README_START, 1)
    _, tail = rest.split(README_END, 1)
    README.write_text(head + "\n".join(lines) + tail, encoding="utf-8")


# --------------------------------------------------------------------------- site summary

def recent_notes(limit: int = 6, days: int = 30) -> list[dict]:
    """Analyst notes from the most recent digests, newest first, without timestamps."""
    notes: list[dict] = []
    for path in sorted(DIGESTS.glob("*/*/*.md"), reverse=True)[:days]:
        for line in reversed(existing_notes(path).splitlines()):
            text = line.strip()
            if not text.startswith("- "):
                continue
            text = text[2:]
            if len(text) > 6 and text[2] == ":" and text[:2].isdigit() and text[3:5].isdigit():
                text = text[6:]  # drop the "HH:MM " stamp
            notes.append({"date": path.stem, "text": text.strip()})
            if len(notes) >= limit:
                return notes
    return notes


def compact(r: dict, **extra) -> dict:
    out = {
        "cve": r["cve"], "vendor": r["vendor"], "product": r["product"], "name": r["name"],
        "added": r["added"], "due": r["due"], "ransomware": r["ransomware"],
        "epss": round(r["epss"], 5) if r.get("epss") is not None else None,
    }
    out.update(extra)
    return out


def build_site_summary(records: dict[str, dict], new: list[str], kev_meta: dict, day: date, epss_ok: bool) -> dict:
    """Small JSON for the portfolio site: everything the live panel needs, nothing more."""
    rows = list(records.values())
    start = day - timedelta(days=29)
    per_day = Counter(r["added"] for r in rows if r["added"] >= start.isoformat())
    history = [{"date": (start + timedelta(days=i)).isoformat(),
                "count": per_day.get((start + timedelta(days=i)).isoformat(), 0)} for i in range(30)]
    recent = sorted(rows, key=lambda r: (r["added"], r["cve"]), reverse=True)[:5]
    return {
        "schema": SITE_SCHEMA,
        "date": day.isoformat(),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalogVersion": kev_meta.get("catalogVersion"),
        "total": len(rows),
        "ransomware": sum(r["ransomware"] for r in rows),
        "epssOk": epss_ok,
        "new": [compact(records[c]) for c in sorted(new, key=lambda c: records[c].get("epss") or 0, reverse=True)][:8],
        "recent": [compact(r) for r in recent],
        "movers": [compact(r, delta=round(d, 5)) for r, d in movers(records)],
        "top": [compact(r) for r in top_epss(records, 5)],
        "due": [compact(r) for r in due_within(records, day, 7)][:5],
        "history": history,
        "notes": recent_notes(),
        "digestUrl": f"{REPO_URL}/blob/main/{digest_path(day.isoformat()).relative_to(ROOT).as_posix()}",
        "repoUrl": REPO_URL,
    }


def write_site_summary(summary: dict) -> None:
    SITE_JSON.parent.mkdir(parents=True, exist_ok=True)
    SITE_JSON.write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- commands

def utc_today() -> date:
    return datetime.now(timezone.utc).date()


def cmd_update(args: argparse.Namespace) -> int:
    today = utc_today()
    day = today.isoformat()
    records = load_records()
    print("Fetching CISA KEV catalog...")
    kev = fetch_kev()
    new = merge_kev(records, kev, day)
    print(f"  {len(records):,} entries, {len(new)} new")

    epss_ok = False
    if not args.no_epss:
        print("Fetching EPSS scores...")
        try:
            scores, model_date = fetch_epss(sorted(records))
            apply_epss(records, scores, model_date)
            epss_ok = bool(scores)
            print(f"  {len(scores):,} scores (model date {model_date})")
        except RuntimeError as exc:
            print(f"  EPSS unavailable: {exc}", file=sys.stderr)

    save_records(records)
    path = digest_path(day)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_digest(records, new, kev, today, epss_ok, existing_notes(path)), encoding="utf-8")
    update_readme(day, len(records), len(new), top_epss(records))
    write_site_summary(build_site_summary(records, new, kev, today, epss_ok))
    save_state({"last_run": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "catalog_version": kev.get("catalogVersion"), "count": len(records)})
    print(f"Wrote {path.relative_to(ROOT).as_posix()}")
    return 0


def require_records() -> dict[str, dict]:
    records = load_records()
    if not records:
        sys.exit("No local data yet. Run: python threatfeed.py update")
    return records


def print_rows(rows: list[dict]) -> None:
    if not rows:
        print("No matches.")
        return
    for r in rows:
        flag = " [ransomware]" if r["ransomware"] else ""
        print(f"{r['cve']:<16} {pct(r.get('epss')):>6}  added {r['added']}  {r['vendor']} {r['product']}{flag}")
        print(f"{'':16} {r['name']}")


def cmd_latest(args: argparse.Namespace) -> int:
    records = require_records()
    since = (utc_today() - timedelta(days=args.days)).isoformat()
    print_rows(sorted((r for r in records.values() if r["added"] >= since), key=lambda r: r["added"], reverse=True))
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    records = require_records()
    term = " ".join(args.term).lower()
    fields = ("cve", "vendor", "product", "name", "description")
    rows = [r for r in records.values() if any(term in str(r[f]).lower() for f in fields)]
    if args.ransomware:
        rows = [r for r in rows if r["ransomware"]]
    print_rows(sorted(rows, key=lambda r: r["added"], reverse=True)[: args.limit])
    print(f"\n{len(rows)} match(es)" + (f", showing {args.limit}" if len(rows) > args.limit else ""))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    records = require_records()
    r = records.get(args.cve.upper())
    if not r:
        print(f"{args.cve} is not in the KEV catalog.")
        return 1
    print(f"{r['cve']}  {r['name']}")
    print(f"Vendor / product : {r['vendor']} / {r['product']}")
    print(f"Added to KEV     : {r['added']}   Federal fix due: {r['due']}")
    print(f"Ransomware use   : {'Known' if r['ransomware'] else 'Unknown'}")
    print(f"EPSS             : {pct(r.get('epss'))} (percentile {pct(r.get('epss_pct'))})")
    if r.get("cwes"):
        print(f"CWE              : {', '.join(r['cwes'])}")
    print(f"\n{r['description']}\n\nRequired action: {r['action']}")
    print(f"\nNVD: https://nvd.nist.gov/vuln/detail/{r['cve']}")
    return 0


def cmd_top(args: argparse.Namespace) -> int:
    print_rows(top_epss(require_records(), args.n, args.ransomware))
    return 0


def cmd_due(args: argparse.Namespace) -> int:
    rows = due_within(require_records(), utc_today(), args.days)
    for r in rows:
        print(f"{r['due']}  {r['cve']:<16} {r['vendor']} {r['product']}")
    if not rows:
        print("Nothing due in that window.")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    records = require_records()
    rows = list(records.values())
    print(f"KEV entries     : {len(rows):,}")
    print(f"Ransomware-linked: {sum(r['ransomware'] for r in rows):,}")
    print("\nTop vendors:")
    for vendor, n in Counter(r["vendor"] for r in rows).most_common(args.n):
        print(f"  {n:>4}  {vendor}")
    print("\nAdded per year:")
    for year, n in sorted(Counter(r["added"][:4] for r in rows).items()):
        print(f"  {year}  {'#' * (n // 10)} {n}")
    cwes = Counter(c for r in rows for c in r.get("cwes", []))
    print("\nMost common weaknesses:")
    for cwe, n in cwes.most_common(args.n):
        print(f"  {n:>4}  {cwe}")
    return 0


def cmd_note(args: argparse.Namespace) -> int:
    day = utc_today().isoformat()
    path = digest_path(day)
    if not path.exists():
        print(f"No digest for {day} yet. Run `python threatfeed.py update` first.")
        return 1
    text = path.read_text(encoding="utf-8")
    note = " ".join(args.text).strip()
    stamp = datetime.now().strftime("%H:%M")
    head, _, tail = text.partition(NOTES_HEADING)
    body, sep, footer = tail.partition("\n---\n")
    lines = [ln for ln in body.strip().splitlines() if ln.strip() and ln.strip() != "_None yet._"]
    lines.append(f"- {stamp} {note}")
    path.write_text(head + NOTES_HEADING + "\n\n" + "\n".join(lines) + "\n" + sep + footer, encoding="utf-8")
    # Refresh the notes in the site summary so the portfolio shows them after the next push.
    if SITE_JSON.exists():
        summary = json.loads(SITE_JSON.read_text(encoding="utf-8"))
        summary["notes"] = recent_notes()
        write_site_summary(summary)
    print(f"Added note to {path.relative_to(ROOT).as_posix()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threatfeed", description="Track actively exploited vulnerabilities (CISA KEV + EPSS).")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("update", help="fetch latest data and write today's digest")
    s.add_argument("--no-epss", action="store_true", help="skip EPSS scores (faster)")
    s.set_defaults(func=cmd_update)

    s = sub.add_parser("latest", help="entries added to KEV recently")
    s.add_argument("--days", type=int, default=7)
    s.set_defaults(func=cmd_latest)

    s = sub.add_parser("search", help="search by CVE, vendor, product or keyword")
    s.add_argument("term", nargs="+")
    s.add_argument("--ransomware", action="store_true", help="only ransomware-linked entries")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_search)

    s = sub.add_parser("show", help="full details for one CVE")
    s.add_argument("cve")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("top", help="highest EPSS scores in KEV")
    s.add_argument("-n", type=int, default=10)
    s.add_argument("--ransomware", action="store_true")
    s.set_defaults(func=cmd_top)

    s = sub.add_parser("due", help="federal remediation deadlines coming up")
    s.add_argument("--days", type=int, default=14)
    s.set_defaults(func=cmd_due)

    s = sub.add_parser("stats", help="catalog breakdown by vendor, year and weakness")
    s.add_argument("-n", type=int, default=10)
    s.set_defaults(func=cmd_stats)

    s = sub.add_parser("note", help="add your own note to today's digest")
    s.add_argument("text", nargs="+")
    s.set_defaults(func=cmd_note)
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
