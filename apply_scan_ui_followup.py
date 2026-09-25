#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Follow-up UI-only fix for smk1367/scan.

Safe scope: index.html only.

1) Restore the original renderDetail() from the .requested_changes.bak made by
   the previous requested-changes script, then change only the VIEW role tab
   list so it has exactly: اصلی / Wireless / اطلاعات آنتن.
   FULL keeps the original complete tab set.
2) Add the same existing detail-navigation click handler used by the radio
   NAME cell to the IP cell, so clicking the IP opens the device details.

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
    token = f"function {name}(){{"
    start = text.find(token)
    if start < 0:
        fail(f"Could not find {name}()")
    brace = text.find("{", start)
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


def patch_render_detail(current: str, backup: str) -> str:
    _, _, original = extract_function(backup, "renderDetail")

    # In the original function the last Wireless entry belongs to the VIEW
    # tab list; append the requested third tab there. FULL remains unchanged.
    needles = ["['wireless','Wireless']", '["wireless","Wireless"]']
    for needle in needles:
        positions = [m.start() for m in re.finditer(re.escape(needle), original)]
        if positions:
            p = positions[-1]
            extra = "['antenna','اطلاعات آنتن']" if needle.startswith("['") else '["antenna","اطلاعات آنتن"]'
            original = original[:p] + needle + "," + extra + original[p + len(needle):]
            break
    else:
        fail("renderDetail(): could not find Wireless tab entry in backup")

    start, end, _ = extract_function(current, "renderDetail")
    return current[:start] + original + current[end:]


def add_ip_click(current: str) -> str:
    start, end, func = extract_function(current, "rowsHtml")

    # Main dashboard radio/device table: the IP cell is immediately followed
    # by a NAME cell that already has the detail onclick. Copy that handler to
    # the IP cell. The name remains clickable too for backward compatibility.
    pat = re.compile(
        r'(?P<ip><td(?P<ipattrs>[^>]*)>\s*\$\{h\(r\.ip_address\)\}\s*</td>)'
        r'(?P<sep>\s*)'
        r'(?P<name><td(?P<nameattrs>[^>]*)onclick=(?P<q>["\'])(?P<click>.*?)(?P=q)(?P<rest>[^>]*)>'
        r'\s*\$\{h\(r\.(?:name|hostname)(?:\|\|r\.(?:name|hostname|ip_address))?\)\}\s*</td>)',
        re.S,
    )
    m = pat.search(func)
    if not m:
        # Fallback where NAME contains a clickable <a>.
        pat2 = re.compile(
            r'(?P<ip><td(?P<ipattrs>[^>]*)>\s*\$\{h\(r\.ip_address\)\}\s*</td>)'
            r'(?P<sep>\s*)'
            r'(?P<name><td(?P<nameattrs>[^>]*)>.*?<a[^>]*onclick=(?P<q>["\'])(?P<click>.*?)(?P=q)[^>]*>'
            r'\s*\$\{h\(r\.(?:name|hostname)(?:\|\|r\.(?:name|hostname|ip_address))?\)\}.*?</a>.*?</td>)',
            re.S,
        )
        m = pat2.search(func)
    if not m:
        fail("rowsHtml(): could not find existing clickable NAME cell next to IP")

    ip_attrs = m.group("ipattrs")
    if "onclick=" in ip_attrs:
        return current
    q = m.group("q")
    click = m.group("click")
    ip_new = f'<td{ip_attrs} onclick={q}{click}{q}>${{h(r.ip_address)}}</td>'
    func_new = func[:m.start("ip")] + ip_new + func[m.end("ip"):]
    return current[:start] + func_new + current[end:]


def main() -> int:
    if not INDEX.is_file():
        fail("Run from repository root: index.html not found")
    if not BACKUP.is_file():
        fail("index.html.requested_changes.bak not found. Keep the backup from the previous apply script.")

    current = INDEX.read_text(encoding="utf-8")
    backup = BACKUP.read_text(encoding="utf-8")

    updated = patch_render_detail(current, backup)
    updated = add_ip_click(updated)

    bak2 = ROOT / "index.html.ui_followup.bak"
    if not bak2.exists():
        shutil.copy2(INDEX, bak2)
    INDEX.write_text(updated, encoding="utf-8")

    _, _, rd = extract_function(updated, "renderDetail")
    if "اصلی" not in rd or "Wireless" not in rd or "اطلاعات آنتن" not in rd:
        fail("renderDetail(): requested tabs were not found after patch")
    _, _, rh = extract_function(updated, "rowsHtml")
    if "r.ip_address" not in rh or "onclick=" not in rh:
        fail("rowsHtml(): IP click handler was not inserted")

    print("UI_FOLLOWUP_OK")
    print("Modified: index.html")
    print("Backup: index.html.ui_followup.bak")
    print("FULL: original complete tabs preserved")
    print("VIEW: exactly اصلی / Wireless / اطلاعات آنتن")
    print("Radio IP: existing detail click handler added to IP cell")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
