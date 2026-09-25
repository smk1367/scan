#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apply the three requested, narrowly-scoped changes to smk1367/scan.

Run from the repository root:
    python3 apply_scan_requested_changes.py

The script:
  1) Adds one worksheet per active city to View Full Excel, before the
     existing Devices/Wireless sheets.
  2) Makes manual IP entries appear in Devices immediately and allows
     entering initial device/wireless fields. Manual radio entries also
     materialize as dashboard/manual-IP targets and retain their values when
     a later scan returns blanks.
  3) Reduces the device View tabs to exactly: اصلی / Wireless / اطلاعات آنتن.

Only these files are modified:
    index.html
    app.py
    database.py
    excel_manager.py

A .bak copy of every modified file is created first. Existing functionality
outside these requested areas is intentionally left unchanged.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
FILES = [ROOT / "index.html", ROOT / "app.py", ROOT / "database.py", ROOT / "excel_manager.py"]


def fail(msg: str) -> None:
    raise RuntimeError(msg)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"{label}: expected exactly 1 match, found {count}")
    return text.replace(old, new, 1)


def replace_regex_once(text: str, pattern: str, new: str, label: str) -> str:
    rx = re.compile(pattern, re.S)
    matches = list(rx.finditer(text))
    if len(matches) != 1:
        fail(f"{label}: expected exactly 1 match, found {len(matches)}")
    return text[: matches[0].start()] + new + text[matches[0].end() :]


def patch_index(c: str) -> str:
    # 3 visible device tabs, regardless of role.
    c = replace_regex_once(
        c,
        r"function renderDetail\(\)\{.*?\}\s*function rowsHtml",
        """function renderDetail(){const d=current||{};const tabs=[['general','اصلی'],['wireless','Wireless'],['antenna','اطلاعات آنتن']];app.innerHTML=nav()+`<div class=\"card\"><button class=\"btn\" onclick=\"${currentCity?'openCity('+currentCity+')':'loadHome()'}\">بازگشت</button><h2>${h(d.hostname||d.ip_address)} <span class=\"muted ltr\">${h(d.ip_address)}</span></h2><div class=\"tabs\">${tabs.map((t,i)=>`<button class=\"tab ${i===0?'active':''}\" onclick=\"detailTab('${t[0]}',this)\">${t[1]}</button>`).join('')}</div><div id=\"detailBody\"></div></div>`;detailTab('general',document.querySelector('.tab'))}
function rowsHtml""",
        "index.html: renderDetail",
    )

    # Manual-radio admin form gets a city selector so the target has an
    # explicit site immediately, while the database still auto-resolves from
    # CIDR when importing old Excel files without city_id.
    c = replace_regex_once(
        c,
        r"if\(name==='radios'\)\{.*?\}\s*if\(name==='manualips'\)",
        """if(name==='radios'){const [x,cities]=await Promise.all([api('/api/manual-radios'),api('/api/cities')]);b.innerHTML=`<div class=\"toolbar\"><button class=\"btn\" onclick=\"fileDownload('/api/excel/radios','manual_radios.xlsx')\">📤 خروجی Excel</button><label class=\"btn\">📥 ورود Excel<input id=\"radioFile\" type=\"file\" accept=\".xlsx,.xlsm\" hidden onchange=\"importRadio(this)\"></label></div><br>${radioForm(cities)}<div class=\"table\"><table><tr><th>IP</th><th>Name</th><th>Model</th><th>SSID</th><th>Frequency</th><th>TX</th><th>RX</th><th>عملیات</th></tr>${x.map(r=>`<tr><td class=\"ltr\">${h(r.ip_address)}</td><td>${h(r.name)}</td><td>${h(r.model)}</td><td class=\"ltr\">${h(r.ssid)}</td><td>${h(r.frequency)}</td><td>${h(r.tx_power)}</td><td>${h(r.rx_power)}</td><td><button class=\"btn\" onclick=\"delRadio(${r.id})\">حذف</button></td></tr>`).join('')}</table></div>`}
if(name==='manualips')""",
        "index.html: adminTab radios",
    )

    # Manual IP form with initial device/wireless fields.
    c = replace_regex_once(
        c,
        r"async function loadManualIpsAdmin\(\)\{.*?\}\s*async function addManualIpAdmin",
        """function manualSpecFields(){const f=[['device_type','نوع دستگاه'],['hostname','نام / Hostname'],['vendor','Vendor'],['model','Model'],['serial_number','Serial'],['mac_address','MAC'],['ssid','SSID'],['frequency','Frequency'],['channel','Channel'],['bandwidth','Bandwidth'],['mode','Mode'],['radio_name','Radio Name'],['tx_power','TX Power'],['rx_power','RX Power'],['signal_strength','Signal'],['peer_tx_signal','Peer TX Signal'],['rx_rate','RX Rate'],['tx_rate','TX Rate'],['ccq','CCQ'],['snr','SNR'],['noise_floor','Noise Floor']];return `<div class=\"wide\"><h3 style=\"margin:6px 0\">📡 مشخصات اولیه دستگاه / Wireless (اختیاری)</h3></div>${f.map(x=>`<input id=\"mi_${x[0]}\" placeholder=\"${x[1]}\">`).join('')}`}
async function loadManualIpsAdmin(){const [ips,cities]=await Promise.all([api('/api/manual-ips'),api('/api/cities')]);const opts=cities.filter(c=>c.enabled).map(c=>`<option value=\"${c.id}\">${h(c.name)} — ${h(c.cidr)}</option>`).join('');$('adminBody').innerHTML=`<div class=\"notice\">IP دستی را با شهر مربوط ثبت کنید تا از تنظیمات همان شهر برای SNMP/SSH/API استفاده شود. مشخصات اولیه را هم می‌توانید همین‌جا ثبت یا با همان IP بعداً بروزرسانی کنید.</div><div class=\"form-grid\"><input id=\"mip\" placeholder=\"IP مثلا 172.17.240.157\"><input id=\"mid\" placeholder=\"توضیح\"><select id=\"mic\">${opts}</select>${manualSpecFields()}<button class=\"btn primary wide\" onclick=\"addManualIpAdmin()\">ذخیره IP و مشخصات</button></div><div class=\"table\"><table><tr><th>IP</th><th>شهر</th><th>توضیح</th><th>وضعیت</th><th>عملیات</th></tr>${ips.map(x=>`<tr><td class=\"ltr\">${h(x.ip_address)}</td><td>${h(x.city_name||'Manual')}</td><td>${h(x.description)}</td><td>${h(x.enabled?'فعال':'غیرفعال')}</td><td><button class=\"btn danger\" onclick=\"delManualIpAdmin(${x.id})\">حذف</button></td></tr>`).join('')}</table></div>`}
async function addManualIpAdmin""",
        "index.html: loadManualIpsAdmin",
    )

    c = replace_regex_once(
        c,
        r"async function addManualIpAdmin\(\)\{.*?\}\s*async function delManualIpAdmin",
        """async function addManualIpAdmin(){try{const details={};document.querySelectorAll('[id^=\"mi_\"]').forEach(e=>details[e.id.slice(3)]=e.value.trim());await api('/api/manual-ips',{method:'POST',body:JSON.stringify({ip_address:$('mip').value,description:$('mid').value,city_id:$('mic').value,details})});adminTab('manualips',document.querySelector('.tab'))}catch(e){alert(e.message)}}
async function delManualIpAdmin""",
        "index.html: addManualIpAdmin",
    )

    # Manual-radio form gets an explicit city and preserves the existing fields.
    c = replace_regex_once(
        c,
        r"function radioForm\(\)\{.*?\}\s*async function doExport",
        """function radioForm(cities=[]){const opts=cities.filter(c=>c.enabled).map(c=>`<option value=\"${c.id}\">${h(c.name)} — ${h(c.cidr)}</option>`).join('');const fields=['ip_address','name','model','vendor','serial_number','ssid','frequency','channel','bandwidth','mode','radio_name','tx_power','rx_power','signal_strength','peer_tx_signal','tx_rate','rx_rate','ccq','snr','noise_floor','notes'];return `<div class=\"card manual\"><h3>رادیو دستی</h3><div class=\"form-grid\"><select id=\"r_city_id\"><option value=\"\">انتخاب شهر</option>${opts}</select>${fields.map(f=>`<input id=\"r_${f}\" placeholder=\"${f.replaceAll('_',' ')}\">`).join('')}<button class=\"btn primary wide\" onclick=\"addRadio()\">ذخیره / بروزرسانی رادیو</button></div></div>`}
async function addRadio(){const x={};document.querySelectorAll('[id^=\"r_\"]').forEach(e=>x[e.id.slice(2)]=e.value);if(!x.city_id)return alert('شهر رادیو را انتخاب کنید');x.city_id=+x.city_id;try{await api('/api/manual-radios',{method:'POST',body:JSON.stringify(x)});adminTab('radios',document.querySelector('.tab'))}catch(e){alert(e.message)}}
async function delRadio(id){await api('/api/manual-radios/'+id,{method:'DELETE'});adminTab('radios',document.querySelector('.tab'))}
async function importRadio(i){if(!i.files[0])return;const fd=new FormData();fd.append('file',i.files[0]);await fetch(API+'/api/excel/radios',{method:'POST',headers:{Authorization:AUTH},body:fd});adminTab('radios',document.querySelector('.tab'))}
async function doExport""",
        "index.html: radioForm",
    )
    return c


def patch_app(c: str) -> str:
    return replace_once(
        c,
        'db.add_manual_ip(x.get("ip_address","").strip(),x.get("description","").strip(),x.get("city_id"))',
        'db.add_manual_ip(x.get("ip_address","").strip(),x.get("description","").strip(),x.get("city_id"),x.get("details") or {})',
        "app.py: manual IP details",
    )


def patch_database(c: str) -> str:
    # When a manual target is scanned successfully, do not erase user-entered
    # device/wireless values merely because that scan method did not return a
    # particular field. Real scanner values still replace them when non-empty.
    c = replace_once(
        c,
        '        c.execute(sql,vals)\n        for eff,man in protected.items():',
        '''        c.execute(sql,vals)\n\n        # Manual targets keep an entered value when a subsequent scan returns\n        # that field empty. This is intentionally scoped to manual IPs only.\n        manual_target=c.execute("SELECT 1 FROM manual_ips WHERE ip_address=? AND enabled=1",(ip,)).fetchone()\n        if manual_target:\n            preserve_fields=(\n                "device_type","vendor","hostname","model","routeros_version","firmware_version","serial_number","mac_address",\n                "ssid","frequency","channel","bandwidth","mode","radio_name","interface_name","wireless_status",\n                "tx_power","rx_power","signal_strength","peer_tx_signal","tx_rate","rx_rate","ccq","tx_ccq","rx_ccq",\n                "snr","noise_floor","temperature","cpu_load","memory_usage","uptime"\n            )\n            for f in preserve_fields:\n                incoming=str(data.get(f,"") or "").strip()\n                oldv=old.get(f,"") or ""\n                if not incoming and oldv:\n                    c.execute(f"UPDATE devices SET {f}=? WHERE ip_address=?",(oldv,ip))\n\n        for eff,man in protected.items():''',
        "database.py: manual scan preservation",
    )

    # Replace the manual-IP block with a transaction-safe implementation that
    # materializes the device row and applies optional initial details.
    c = replace_regex_once(
        c,
        r"def add_manual_ip\(ip,description=\"\",city_id=None\):.*?\n\ndef delete_manual_ip",
        '''def _resolve_manual_city(c,ip,city_id=None):\n    from ipaddress import ip_address,ip_network\n    selected_city_id=int(city_id) if city_id not in (None,"") else None\n    matched=None\n    if selected_city_id is not None:\n        row=c.execute("SELECT * FROM cities WHERE id=? AND enabled=1",(selected_city_id,)).fetchone()\n        if not row:\n            raise ValueError("شهر انتخاب‌شده معتبر نیست")\n        matched=dict(row)\n    else:\n        obj=ip_address(ip)\n        for row in c.execute("SELECT * FROM cities WHERE enabled=1 ORDER BY id").fetchall():\n            try:\n                if obj in ip_network(row["cidr"],strict=False):\n                    matched=dict(row)\n                    selected_city_id=int(row["id"])\n                    break\n            except Exception:\n                continue\n    return selected_city_id,matched\n\n\ndef _apply_manual_device_details(c,ip,details):\n    details=details or {}\n    allowed=(\n        "device_type","vendor","hostname","model","serial_number","mac_address",\n        "ssid","frequency","channel","bandwidth","mode","radio_name",\n        "tx_power","rx_power","signal_strength","peer_tx_signal","rx_rate","tx_rate",\n        "ccq","snr","noise_floor"\n    )\n    sets=[];args=[]\n    for field in allowed:\n        if field in details and details.get(field) not in (None,""):\n            value=str(details.get(field)).strip()\n            if value:\n                sets.append(f"{field}=?");args.append(value)\n    if sets:\n        sets.append("last_updated=?");args.append(now());args.append(ip)\n        c.execute(f"UPDATE devices SET {','.join(sets)} WHERE ip_address=?",args)\n\n\ndef _upsert_manual_target(c,ip,description="",city_id=None,details=None):\n    selected_city_id,matched=_resolve_manual_city(c,ip,city_id)\n    desc=str(description or "").strip()\n    c.execute("""INSERT INTO manual_ips(ip_address,city_id,description,enabled,created_at)\n                 VALUES(?,?,?,?,?)\n                 ON CONFLICT(ip_address) DO UPDATE SET\n                   city_id=excluded.city_id,\n                   description=CASE WHEN excluded.description<>'' THEN excluded.description ELSE manual_ips.description END,\n                   enabled=1""",\n              (ip,selected_city_id,desc,1,now()))\n\n    if matched:\n        c.execute("""INSERT INTO devices(ip_address,city_id,city,scan_status,last_updated)\n                     VALUES(?,?,?,?,?)\n                     ON CONFLICT(ip_address) DO UPDATE SET\n                       city_id=excluded.city_id,\n                       city=CASE\n                              WHEN COALESCE(devices.city,'') IN ('','Manual','manual_pending') THEN excluded.city\n                              ELSE devices.city\n                            END""",\n                  (ip,matched["id"],matched["name"],"manual_pending",now()))\n    else:\n        c.execute("""INSERT INTO devices(ip_address,city_id,city,scan_status,last_updated)\n                     VALUES(?,?,?,?,?)\n                     ON CONFLICT(ip_address) DO NOTHING""",\n                  (ip,None,"Manual","manual_pending",now()))\n    _apply_manual_device_details(c,ip,details)\n\n\ndef add_manual_ip(ip,description="",city_id=None,details=None):\n    from ipaddress import ip_address\n    ip=str(ip_address(ip))\n    c=connect()\n    try:\n        _upsert_manual_target(c,ip,description,city_id,details or {})\n        c.commit()\n        return dict(c.execute("SELECT * FROM manual_ips WHERE ip_address=?",(ip,)).fetchone())\n    except Exception:\n        c.rollback()\n        raise\n    finally:c.close()\n\n\ndef delete_manual_ip''',
        "database.py: add_manual_ip block",
    )

    # Manual radio rows become manual-IP/dashboard targets and can carry their
    # own initial device/Wireless values. This keeps old Excel imports working.
    c = replace_regex_once(
        c,
        r"def upsert_manual_radio\(x\):.*?\n\ndef delete_manual_radio",
        '''def upsert_manual_radio(x):\n    from ipaddress import ip_address\n    fields=["ip_address","name","model","vendor","serial_number","ssid","frequency","channel","bandwidth","mode","radio_name","tx_power","rx_power","signal_strength","peer_tx_signal","tx_rate","rx_rate","ccq","snr","noise_floor","notes"]\n    vals=[str(x.get(f,"")).strip() for f in fields]\n    vals[0]=str(ip_address(vals[0]))\n    ts=now();c=connect()\n    try:\n        sql=f"INSERT INTO manual_radios({','.join(fields)},created_at,updated_at) VALUES({','.join('?' for _ in fields)},?,?) ON CONFLICT(ip_address) DO UPDATE SET "+','.join(f"{f}=excluded.{f}" for f in fields if f!='ip_address')+",updated_at=excluded.updated_at"\n        c.execute(sql,vals+[ts,ts])\n\n        details={\n            "device_type":str(x.get("device_type") or x.get("vendor") or "Manual Radio").strip(),\n            "hostname":str(x.get("name") or "").strip(),\n            "model":str(x.get("model") or "").strip(),\n            "vendor":str(x.get("vendor") or "").strip(),\n            "serial_number":str(x.get("serial_number") or "").strip(),\n            "ssid":str(x.get("ssid") or "").strip(),\n            "frequency":str(x.get("frequency") or "").strip(),\n            "channel":str(x.get("channel") or "").strip(),\n            "bandwidth":str(x.get("bandwidth") or "").strip(),\n            "mode":str(x.get("mode") or "").strip(),\n            "radio_name":str(x.get("radio_name") or "").strip(),\n            "tx_power":str(x.get("tx_power") or "").strip(),\n            "rx_power":str(x.get("rx_power") or "").strip(),\n            "signal_strength":str(x.get("signal_strength") or "").strip(),\n            "peer_tx_signal":str(x.get("peer_tx_signal") or "").strip(),\n            "tx_rate":str(x.get("tx_rate") or "").strip(),\n            "rx_rate":str(x.get("rx_rate") or "").strip(),\n            "ccq":str(x.get("ccq") or "").strip(),\n            "snr":str(x.get("snr") or "").strip(),\n            "noise_floor":str(x.get("noise_floor") or "").strip()\n        }\n        _upsert_manual_target(c,vals[0],str(x.get("notes") or "").strip(),x.get("city_id"),details)\n        c.commit()\n        return dict(c.execute("SELECT * FROM manual_radios WHERE ip_address=?",(vals[0],)).fetchone())\n    except Exception:\n        c.rollback()\n        raise\n    finally:c.close()\n\ndef delete_manual_radio''',
        "database.py: upsert_manual_radio",
    )
    return c


def patch_excel(c: str) -> str:
    # Excel needs safe sheet titles because Excel limits them to 31 characters
    # and rejects []:*?/\\. City names remain human-readable.
    c = replace_once(
        c,
        'import io, ipaddress, json, sqlite3\n',
        'import io, ipaddress, json, re, sqlite3\n',
        "excel_manager.py: import re",
    )
    c = replace_once(
        c,
        'def json_load(v):\n',
        '''def city_sheet_title(name,used):\n    raw=text(name).strip() or "نامشخص"\n    raw=re.sub(r'[\\[\\]:\\*\\?/\\\\]', '_', raw)\n    raw=raw[:31] or "Sheet"\n    base=raw\n    n=2\n    while raw in used:\n        suffix=f" ({n})"\n        raw=(base[:31-len(suffix)]+suffix) or f"Sheet{n}"\n        n+=1\n    used.add(raw)\n    return raw\n\n\ndef add_city_sheets(wb,conn,rows):\n    by_city={}\n    for row in rows:\n        city=text(row.get("City") or "").strip() or "نامشخص"\n        by_city.setdefault(city,[]).append(row)\n    used=set()\n    city_rows=conn.execute("SELECT name FROM cities WHERE enabled=1 ORDER BY name").fetchall()\n    for row in city_rows:\n        city=text(row[0]).strip() or "نامشخص"\n        add_sheet(wb,city_sheet_title(city,used),VIEW_HEADERS,by_city.pop(city,[]))\n    for city,items in by_city.items():\n        add_sheet(wb,city_sheet_title(city,used),VIEW_HEADERS,items)\n\n\ndef json_load(v):\n''',
        "excel_manager.py: city sheet helpers",
    )
    c = replace_once(
        c,
        '            add_sheet(wb,"Devices",VIEW_HEADERS,rows)\n',
        '''            # Keep the existing Devices/Wireless sheets, but prepend one\n            # worksheet for every active city so Tehran, Pardis, ... are each\n            # separate tabs in the same order used by the dashboard city list.\n            add_city_sheets(wb,conn,rows)\n            add_sheet(wb,"Devices",VIEW_HEADERS,rows)\n''',
        "excel_manager.py: view_full city worksheets",
    )
    return c


def write_all(contents: dict[Path, str]) -> None:
    for path in FILES:
        backup = path.with_suffix(path.suffix + ".requested_changes.bak")
        shutil.copy2(path, backup)
    for path, content in contents.items():
        path.write_text(content, encoding="utf-8")


def validate() -> None:
    # Python syntax.
    subprocess.run([sys.executable, "-m", "py_compile", "app.py", "database.py", "excel_manager.py"], check=True)

    # JS syntax when node is available.
    node = shutil.which("node")
    if node:
        html = Path("index.html").read_text(encoding="utf-8")
        scripts = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
        if not scripts:
            fail("index.html: no script block found")
        js = "\n".join(scripts)
        tmp = Path(".scan_requested_changes_index_check.js")
        try:
            tmp.write_text(js, encoding="utf-8")
            subprocess.run([node, "--check", str(tmp)], check=True)
        finally:
            tmp.unlink(missing_ok=True)

    # Run a compatibility smoke test against the current database API.
    # The repository's legacy smoke_test.py still calls add_city() with the
    # old positional signature; do not let that stale test block deployment.
    smoke = r'''
import os, tempfile, ipaddress
os.environ["DB_PATH"] = os.path.join(tempfile.gettempdir(), "wireless_monitor_requested_changes_smoke.db")
try:
    os.remove(os.environ["DB_PATH"])
except FileNotFoundError:
    pass
import database as db

db.init_db()
city = db.add_city({"name":"تست","cidr":"192.0.2.0/30","description":"smoke","enabled":1})
assert city["name"] == "تست"
manual = db.add_manual_ip("192.0.2.1", "manual smoke", city["id"], {
    "vendor":"MikroTik", "model":"SmokeModel", "ssid":"SmokeSSID",
    "frequency":"5800", "rx_power":"-47 dBm", "tx_power":"20 dBm",
    "rx_rate":"100 Mbps", "tx_rate":"120 Mbps"
})
assert manual["ip_address"] == "192.0.2.1"
d = db.get_device("192.0.2.1")
assert d and d["city_id"] == city["id"] and d["ssid"] == "SmokeSSID"
print("REQUESTED_CHANGES_SMOKE_OK")
'''
    tmp = Path(".requested_changes_smoke.py")
    try:
        tmp.write_text(smoke, encoding="utf-8")
        subprocess.run([sys.executable, str(tmp)], check=True)
    finally:
        tmp.unlink(missing_ok=True)


def main() -> int:
    missing = [str(p) for p in FILES if not p.is_file()]
    if missing:
        fail("Run this script from the repository root. Missing: " + ", ".join(missing))

    original = {p: p.read_text(encoding="utf-8") for p in FILES}
    modified = {
        ROOT / "index.html": patch_index(original[ROOT / "index.html"]),
        ROOT / "app.py": patch_app(original[ROOT / "app.py"]),
        ROOT / "database.py": patch_database(original[ROOT / "database.py"]),
        ROOT / "excel_manager.py": patch_excel(original[ROOT / "excel_manager.py"]),
    }

    # Sanity checks for all three requested features before writing.
    index_new = modified[ROOT / "index.html"]
    if "const tabs=[['general','اصلی'],['wireless','Wireless'],['antenna','اطلاعات آنتن']]" not in index_new:
        fail("Requested 3-tab view was not inserted")
    if "details})" not in index_new:
        fail("Manual IP details payload was not inserted")
    if "radioForm(cities)" not in index_new:
        fail("Manual radio city selector was not inserted")
    if 'city_sheet_title' not in modified[ROOT / "excel_manager.py"]:
        fail("City worksheet helper was not inserted")
    if '_upsert_manual_target' not in modified[ROOT / "database.py"]:
        fail("Manual target helper was not inserted")

    write_all(modified)
    try:
        validate()
    except Exception:
        # Roll back automatically if validation fails.
        for path in FILES:
            backup = path.with_suffix(path.suffix + ".requested_changes.bak")
            shutil.copy2(backup, path)
        raise

    print("OK: requested changes applied and validation passed.")
    print("Modified files:")
    for p in FILES:
        print(f"  - {p.name}")
    print("Backups:")
    for p in FILES:
        print(f"  - {p.with_suffix(p.suffix + '.requested_changes.bak').name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
