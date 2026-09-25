#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UI-only follow-up for smk1367/scan.

Safe scope: index.html only.

1) Restore the original renderDetail() from index.html.requested_changes.bak.
   Keep FULL's complete original tabs. Add exactly one extra tab
   (اطلاعات آنتن) only to the non-FULL/VIEW tab list.
2) Move the existing detail click handler from the radio NAME cell to the IP
   cell, so clicking the IP opens the device detail.

No backend/database/excel files are touched.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

ROOT = Path.cwd()
INDEX = ROOT / "index.html"
BACKUP = ROOT / "index.html.requested_changes.bak"


def fail(msg: str) -> None:
    raise RuntimeError(msg)


def extract_function(text: str, name: str) -> tuple[int, int, str]:
    # Accept optional parameters because the function signature may differ.
    m = re.search(rf"function\s+{re.escape(name)}\s*\([^)]*\)\s*\{{", text)
    if not m:
        fail(f"Could not find {name}()")
    start = m.start()
    brace = text.find("{", m.start())
    depth = 0
    quote = None
    esc = False
    i = brace
    while i < len(text):
        ch = text[i]
        if quote:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
        else:
            if ch in "'\"`":
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return start, i + 1, text[start:i + 1]
        i += 1
    fail(f"Could not parse {name}() braces")


def patch_view_tabs_from_backup(current: str, backup: str) -> str:
    _, _, original = extract_function(backup, "renderDetail")

    # The original UI has a role-specific ternary/branch where VIEW has only
    # general + wireless. Patch only that branch, leaving FULL untouched.
    pair_patterns = [
        (r"(:\s*)\[\s*\['general'\s*,\s*'اصلی'\]\s*,\s*\['wireless'\s*,\s*'Wireless'\]\s*\]",
         "canonical-single"),
        (r"(:\s*)\[\s*\[\"general\"\s*,\s*\"اصلی\"\]\s*,\s*\[\"wireless\"\s*,\s*\"Wireless\"\]\s*\]",
         "canonical-double"),
        (r"(\?\s*\[\s*\[\s*['\"]general['\"]\s*,\s*['\"]اصلی['\"]\s*\]\s*,\s*\[\s*['\"]wireless['\"]\s*,\s*['\"]Wireless['\"]\s*\]\s*:\s*)\[\s*\[\s*['\"]general['\"]\s*,\s*['\"]اصلی['\"]\s*\]\s*,\s*\[\s*['\"]wireless['\"]\s*,\s*['\"]Wireless['\"]\s*\]\s*\]",
         "ternary-fallback"),
    ]

    # First prefer a colon-led VIEW branch. This must not match the FULL list.
    for pat, kind in pair_patterns[:2]:
        ms = list(re.finditer(pat, original, flags=re.S))
        if ms:
            # If multiple matches exist, the last is usually the VIEW fallback.
            m = ms[-1]
            q = "'" if "['general'" in m.group(0) else '"'
            replacement = m.group(1) + f"[[{q}general{q},{q}اصلی{q}],[{q}wireless{q},{q}Wireless{q}],[{q}antenna{q},{q}اطلاعات آنتن{q}]]"
            original = original[:m.start()] + replacement + original[m.end():]
            break
    else:
        # More tolerant fallback: find occurrences of the two-tab array and
        # only patch one that is syntactically in a fallback/else context.
        two_tab = re.compile(
            r"\[\s*\[\s*(['\"])general\1\s*,\s*\1اصلی\1\s*\]\s*,\s*\[\s*\1wireless\1\s*,\s*\1Wireless\1\s*\]\s*\]",
            re.S,
        )
        ms = list(two_tab.finditer(original))
        if len(ms) < 1:
            fail("renderDetail(): could not find the original 2-tab VIEW list in backup")
        target = None
        for m in reversed(ms):
            before = original[max(0, m.start()-120):m.start()]
            if ":" in before or "else" in before or "view" in before.lower():
                target = m
                break
        if target is None:
            target = ms[-1]
        q = target.group(1)
        replacement = f"[{q}general{q},{q}اصلی{q}]"
        replacement = f"[[{q}general{q},{q}اصلی{q}],[{q}wireless{q},{q}Wireless{q}],[{q}antenna{q},{q}اطلاعات آنتن{q}]]"
        original = original[:target.start()] + replacement + original[target.end():]

    # Replace the currently patched renderDetail() in index.html.
    start, end, _ = extract_function(current, "renderDetail")
    return current[:start] + original + current[end:]


def move_ip_click(current: str) -> str:
    # Search row-by-row, independent of the function name. The current UI has
    # an IP cell and a clickable NAME cell in the same <tr>. Move the exact
    # existing onclick attribute from NAME to IP.
    row_rx = re.compile(r"<tr\b[^>]*>.*?</tr>", re.S | re.I)
    rows = list(row_rx.finditer(current))
    changed = 0

    for row in reversed(rows):
        html = row.group(0)
        if not re.search(r"ip_address", html):
            continue
        if not re.search(r"onclick\s*=", html, re.I):
            continue
        if not re.search(r"(?:r|x|d)\.(?:name|hostname)", html):
            continue

        # Find IP <td> containing the row IP expression.
        ip_td = re.search(r"<td(?P<attrs>[^>]*)>[^<]*\$\{[^}]*\.(?:ip_address)[^}]*\}[^<]*</td>", html, re.S | re.I)
        if not ip_td:
            # Common exact form in the app.
            ip_td = re.search(r"<td(?P<attrs>[^>]*)>\s*\$\{h\([^}]*\.ip_address[^}]*\)\}\s*</td>", html, re.S | re.I)
        if not ip_td:
            continue

        # Prefer a NAME td onclick; otherwise accept an anchor onclick inside
        # the NAME td. We extract the exact attribute value.
        name_td = re.search(
            r"<td(?P<attrs>[^>]*)onclick\s*=\s*(?P<q>['\"])(?P<click>.*?)(?P=q)(?P<rest>[^>]*)>.*?(?:\$\{[^}]*\.(?:name|hostname)[^}]*\}).*?</td>",
            html, re.S | re.I,
        )
        name_anchor = None
        if not name_td:
            name_td = re.search(
                r"<td(?P<attrs>[^>]*)>.*?<a[^>]*onclick\s*=\s*(?P<q>['\"])(?P<click>.*?)(?P=q)[^>]*>.*?\$\{[^}]*\.(?:name|hostname)[^}]*\}.*?</a>.*?</td>",
                html, re.S | re.I,
            )
            name_anchor = bool(name_td)
        if not name_td:
            continue

        q = name_td.group("q")
        click = name_td.group("click")
        ip_attrs = ip_td.group("attrs")
        if "onclick=" in ip_attrs.lower():
            return current

        new_ip_attrs = ip_attrs + f" onclick={q}{click}{q}"
        new_ip_td = ip_td.group(0).replace(ip_attrs, new_ip_attrs, 1)
        new_row = html[:ip_td.start()] + new_ip_td + html[ip_td.end():]

        # Remove the existing click from NAME so navigation is now on IP.
        if name_anchor:
            old = re.search(r"\s+onclick\s*=\s*(?P<q>['\"])(?P<click>.*?)(?P=q)", new_row, re.S | re.I)
            # There may be multiple onclicks; target the one immediately inside
            # the anchor that contains the row name expression.
            new_row2 = re.sub(
                r"(<a\b[^>]*?)\s+onclick\s*=\s*(['\"])(?:\\.|(?!\2).)*?\2",
                r"\1",
                new_row,
                count=1,
                flags=re.S | re.I,
            )
            new_row = new_row2
        else:
            # Remove onclick only from the NAME <td> we matched.
            name_match = re.search(
                r"<td(?P<attrs>[^>]*)onclick\s*=\s*(?P<q>['\"])(?P<click>.*?)(?P=q)(?P<rest>[^>]*)>.*?\$\{[^}]*\.(?:name|hostname)[^}]*\}.*?</td>",
                new_row, re.S | re.I,
            )
            if name_match:
                attrs = name_match.group("attrs")
                q2 = name_match.group("q")
                click2 = name_match.group("click")
                new_attrs = re.sub(r"\s+onclick\s*=\s*" + re.escape(q2) + r".*?" + re.escape(q2), "", attrs, count=1, flags=re.S | re.I)
                name_new = name_match.group(0).replace(attrs, new_attrs, 1)
                new_row = new_row[:name_match.start()] + name_new + new_row[name_match.end():]

        current = current[:row.start()] + new_row + current[row.end():]
        changed += 1
        break

    if not changed:
        fail("Could not find the radio/device table row with IP + clickable NAME")
    return current


def validate(updated: str) -> None:
    # Full still has the original extended tabs; VIEW has the requested three.
    _, _, rd = extract_function(updated, "renderDetail")
    if "Registration" not in rd or "Interfaces" not in rd:
        fail("FULL renderDetail tabs do not appear to contain the original extended tab set")
    if "اطلاعات آنتن" not in rd:
        fail("VIEW antenna tab was not added")
    if not re.search(r"\['general'\s*,\s*'اصلی'\].*?\['wireless'\s*,\s*'Wireless'\].*?\['antenna'\s*,\s*'اطلاعات آنتن'\]", rd, re.S):
        fail("Requested VIEW tab sequence not found")
    # Verify an IP cell has onclick and there is still a device name field.
    ok = re.search(r"<td[^>]*onclick\s*=.*?\$\{h\([^}]*\.ip_address[^}]*\)\}", updated, re.S | re.I)
    if not ok:
        ok = re.search(r"<td[^>]*onclick\s*=.*?ip_address", updated, re.S | re.I)
    if not ok:
        fail("IP cell does not contain the detail click handler")


def main() -> int:
    if not INDEX.is_file():
        fail("Run this script from the repository root: index.html not found")
    if not BACKUP.is_file():
        fail("index.html.requested_changes.bak not found")

    current = INDEX.read_text(encoding="utf-8")
    backup = BACKUP.read_text(encoding="utf-8")

    updated = patch_view_tabs_from_backup(current, backup)
    updated = move_ip_click(updated)
    validate(updated)

    out_backup = ROOT / "index.html.ui_followup.bak"
    if not out_backup.exists():
        shutil.copy2(INDEX, out_backup)
    INDEX.write_text(updated, encoding="utf-8")

    print("UI_FOLLOWUP_V2_OK")
    print("Modified: index.html")
    print("Backup: index.html.ui_followup.bak")
    print("FULL: original extended tabs preserved")
    print("VIEW: exactly اصلی / Wireless / اطلاعات آنتن")
    print("Radio IP: detail click moved from NAME to IP")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)
