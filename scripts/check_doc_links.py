#!/usr/bin/env python3
"""Verify that every documentation URL objdiff-cli emits actually resolves.

objdiff's analysis output links to pattern docs by project-relative path, so a
URL is only correct with respect to a particular consuming repo. This script
asks the binary what it would emit for a given project identity
(`objdiff-cli doc-links -P <project> -f json`) and checks each URL against that
repo's working tree: the file must exist, and the `#anchor` must match a real
markdown heading (GitHub slug rules).

Usage:
    scripts/check_doc_links.py --dc3 ../dc3-decomp --rb3 ../rb3
    scripts/check_doc_links.py --dc3 ../dc3-decomp          # check one repo

Exits non-zero if any URL fails, if a contract anchor moved, or if a repo
argument is missing entirely (pass --allow-missing to skip absent repos).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

# The first URL in a pattern's list is the only one objdiff renders inline, so
# these are contractual: dc3-decomp docs are written to keep these anchors
# stable. Breaking one silently degrades every diff report in that repo.
DC3_FIRST_URL_CONTRACT = {
    "REGISTER_SWAP": "docs/decomp/patterns/fixable-declarations.md"
    "#pre-compute-references-before-clobbering-calls",
    "OFFSET_SWAP": "docs/decomp/patterns/fixable-declarations.md#offset-swap",
}

# Anchors that must exist in dc3-decomp even though they are not first in a
# pattern list (they are cited from prose and from the research writeup).
DC3_REQUIRED_ANCHORS = [
    "docs/decomp/patterns/PERMUTER_ROI_ANALYSIS.md#instruction-scheduling",
]


def slugify(heading: str) -> str:
    """GitHub's heading -> anchor transformation (close enough for our docs)."""
    s = heading.strip().lower()
    s = re.sub(r"[`*]", "", s)
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"\s+", "-", s)


def headings(path: str) -> set[str]:
    out: set[str] = set()
    fenced = False
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            m = re.match(r"^#{1,6}\s+(.*?)\s*$", line)
            if m:
                out.add(slugify(m.group(1)))
    return out


def check_url(repo: str, url: str) -> str | None:
    """Return an error string, or None if the URL resolves."""
    rel, _, anchor = url.partition("#")
    path = os.path.join(repo, rel)
    if not os.path.isfile(path):
        return f"file does not exist: {rel}"
    if anchor and anchor not in headings(path):
        return f"anchor not found: #{anchor} in {rel}"
    return None


def dump_links(binary: str, project: str) -> dict:
    proc = subprocess.run(
        [binary, "doc-links", "-P", project, "-f", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"{binary} doc-links failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


def check_project(binary: str, project: str, repo: str) -> int:
    data = dump_links(binary, project)
    failures = 0
    seen: set[str] = set()

    for entry in data["links"]:
        url = entry["url"]
        if url is None or url in seen:
            continue
        seen.add(url)
        err = check_url(repo, url)
        if err:
            failures += 1
            print(f"FAIL [{project}] {entry['link']}: {err}")

    for pattern in data["patterns"]:
        for url in pattern["urls"]:
            if url in seen:
                continue
            seen.add(url)
            err = check_url(repo, url)
            if err:
                failures += 1
                print(f"FAIL [{project}] {pattern['pattern']}: {err}")

    if project == "dc3":
        by_pattern = {p["pattern"]: p["urls"] for p in data["patterns"]}
        for pattern, expected in DC3_FIRST_URL_CONTRACT.items():
            actual = (by_pattern.get(pattern) or [None])[0]
            if actual != expected:
                failures += 1
                print(
                    f"FAIL [dc3] anchor contract: {pattern} first URL is\n"
                    f"       {actual}\n     expected\n       {expected}"
                )
        emitted = {u for p in data["patterns"] for u in p["urls"]}
        emitted |= {e["url"] for e in data["links"] if e["url"]}
        for url in DC3_REQUIRED_ANCHORS:
            if url not in emitted:
                failures += 1
                print(f"FAIL [dc3] anchor contract: {url} is no longer emitted")

    print(f"[{project}] checked {len(seen)} unique URLs against {repo}: "
          f"{len(seen) - failures} ok, {failures} failed")
    return failures


def check_unknown(binary: str) -> int:
    """An unrecognised project must never be handed a project-specific link."""
    dc3 = dump_links(binary, "dc3")
    rb3 = dump_links(binary, "rb3")
    unknown = dump_links(binary, "unknown")
    dc3_urls = {e["link"]: e["url"] for e in dc3["links"]}
    rb3_urls = {e["link"]: e["url"] for e in rb3["links"]}
    failures = 0
    for entry in unknown["links"]:
        url = entry["url"]
        if url is None:
            continue
        d, r = dc3_urls[entry["link"]], rb3_urls[entry["link"]]
        if d is None or r is None:
            failures += 1
            print(f"FAIL [unknown] {entry['link']}: emitted {url} but a known "
                  f"project has no such doc")
            continue
        # Must be a prefix of both, i.e. the shared file (and shared anchor
        # only when the two agree).
        if not d.startswith(url) or not r.startswith(url):
            failures += 1
            print(f"FAIL [unknown] {entry['link']}: {url} is not common to "
                  f"dc3 ({d}) and rb3 ({r})")
    n = sum(1 for e in unknown["links"] if e["url"])
    print(f"[unknown] {n} project-independent URLs, {failures} failed")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", default=None, help="path to objdiff-cli")
    ap.add_argument("--dc3", default=None, help="path to dc3-decomp checkout")
    ap.add_argument("--rb3", default=None, help="path to rb3 checkout")
    ap.add_argument("--allow-missing", action="store_true",
                    help="skip repos that are not present instead of failing")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    binary = args.binary or os.path.join(root, "target", "debug", "objdiff-cli")
    if not os.path.isfile(binary):
        binary = os.path.join(root, "target", "release", "objdiff-cli")
    if not os.path.isfile(binary):
        raise SystemExit(f"objdiff-cli not found (looked in {root}/target/*)")

    failures = 0
    checked_any = False
    for project, repo in (("dc3", args.dc3), ("rb3", args.rb3)):
        if repo is None:
            default = os.path.join(os.path.dirname(root),
                                   "dc3-decomp" if project == "dc3" else "rb3")
            repo = default if os.path.isdir(default) else None
        if repo is None or not os.path.isdir(repo):
            msg = f"[{project}] repo not found; skipping"
            if args.allow_missing or repo is None:
                print(msg)
                continue
            print(f"FAIL {msg}")
            failures += 1
            continue
        checked_any = True
        failures += check_project(binary, project, repo)

    failures += check_unknown(binary)

    if not checked_any and not args.allow_missing:
        print("FAIL no repos were checked")
        return 2
    print("OK" if failures == 0 else f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
