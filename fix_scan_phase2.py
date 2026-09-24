#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wireless Monitor phase-2 fixes.

Additive fixes; no existing feature is removed.

1. Mimosa SNMP proprietary MIB data (chains, RX/TX power, noise, SNR, freq).
2. RACOM RipEX SNMP proprietary MIB data (name/model/serial/freq/RF power/RSS).
3. Install net-snmp tools so the existing IF-MIB walk actually works in Docker.
4. Allow every authenticated role to export only the Wireless sheet they can see.
5. Make city/province counts robust to legacy records with city text/manual data.
6. Make newly-added manual IPs appear in the device dashboard immediately as
   manual_pending targets, without overwriting an existing live device.
7. Add Wireless Excel export buttons to the city/device Wireless UI.

Each changed file gets a .phase2.bak backup once. Python files are syntax checked.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def backup(p: Path) -> None:
    b = p.with_suffix(p.suffix + ".phase2.bak")
    if not b.exists():
        shutil.copy2(p, b)

def replace_once(c: str, old: str, new: str, label: str) -> str:
    n = c.count(old)
    if n != 1:
        raise RuntimeError(f"{label}: expected 1 match, found {n}")
    return c.replace(old, new, 1)

def patch_dockerfile() -> None:
    p = ROOT / "Dockerfile"
    c = p.read_text(encoding="utf-8")
    old = "        openssh-client \\\n        sshpass \\\n        iputils-ping \\\n"
    new = "        openssh-client \\\n        sshpass \\\n        iputils-ping \\\n        snmp \\\n"
    c = replace_once(c, old, new, "Dockerfile net-snmp")
    backup(p); p.write_text(c, encoding="utf-8")

def patch_scanner() -> None:
    p = ROOT / "scanner.py"
    c = p.read_text(encoding="utf-8")

    anchor = '''IF_OIDS = {\n    "name": "1.3.6.1.2.1.31.1.1.1.1",\n    "descr": "1.3.6.1.2.1.2.2.1.2",\n    "oper": "1.3.6.1.2.1.2.2.1.8",\n    "admin": "1.3.6.1.2.1.2.2.1.7",\n    "in_octets": "1.3.6.1.2.1.31.1.1.1.6",\n    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",\n    "in_errors": "1.3.6.1.2.1.2.2.1.14",\n    "out_errors": "1.3.6.1.2.1.2.2.1.20",\n}\n'''
    insert = anchor + '''\n# Proprietary vendor roots used only after standard SNMP identifies the device.\nMIMOSA_ROOT = "1.3.6.1.4.1.43356.2.1.2"\nMIMOSA_CHAIN_ROOT = "1.3.6.1.4.1.43356.2.1.2.6.1.1"\nRACOM_ROOT = "1.3.6.1.4.1.33555.2"\nRACOM_DEVICE_ROOT = "1.3.6.1.4.1.33555.2.1.1"\nRACOM_RADIO_ROOT = "1.3.6.1.4.1.33555.2.2.1"\nRACOM_WATCHED_ROOT = "1.3.6.1.4.1.33555.2.4"\n'''
    c = replace_once(c, anchor, insert, "scanner vendor roots")

    helper_anchor = '''def tcp_open(ip: str, port: int, timeout: float = 1.0) -> bool:\n    try:\n        with socket.create_connection((ip, int(port)), timeout=float(timeout)):\n            return True\n    except Exception:\n        return False\n'''
    helper_new = helper_anchor + '''\n\ndef snmpbulkwalk_numeric(ip: str, community: str, root: str, city: dict[str, Any]) -> dict[str, str]:\n    """Read a vendor MIB subtree numerically without requiring MIB files."""\n    if not community or not shutil.which("snmpbulkwalk"):\n        return {}\n    cmd = [\n        "snmpbulkwalk", "-v2c", "-c", community, "-On",\n        "-t", str(float(city["snmp_timeout"])),\n        "-r", str(int(city["snmp_retries"])),\n        ip, root,\n    ]\n    try:\n        proc = subprocess.run(\n            cmd, capture_output=True, text=True,\n            timeout=max(8, int(float(city["snmp_timeout"])) * 8 + 4),\n        )\n    except Exception as exc:\n        LOG.debug("Vendor SNMP walk %s/%s failed: %s", ip, root, exc)\n        return {}\n    if proc.returncode != 0:\n        return {}\n    out = {}\n    for line in proc.stdout.splitlines():\n        m = re.match(r"^([^ ]+)\\s*=\\s*(.*)$", line.strip())\n        if not m:\n            continue\n        oid, raw = m.group(1), m.group(2)\n        value = raw.split(":", 1)[1].strip() if ":" in raw else raw.strip()\n        out[oid.lstrip(".")] = value\n    return out\n\n\ndef numeric_value(raw: Any) -> float | None:\n    text = s(raw)\n    if not text:\n        return None\n    m = re.search(r"-?\\d+(?:\\.\\d+)?", text)\n    if not m:\n        return None\n    try:\n        return float(m.group(0))\n    except Exception:\n        return None\n\n\ndef avg_values(rows: list[float]) -> float | None:\n    rows = [x for x in rows if x is not None]\n    return (sum(rows) / len(rows)) if rows else None\n\n\ndef parse_mimosa_vendor(data: dict[str, str]) -> dict[str, Any]:\n    out: dict[str, Any] = {"mimosa_chains": []}\n    chain_tx=[]; chain_rx=[]; chain_noise=[]; chain_snr=[]; chain_freq=[]; chain_pol=[]\n    for oid, raw in data.items():\n        p = oid.split(".")\n        # suffix after ...43356.2.1.2.6.1.1 is column then chain index.\n        marker = ["6", "1", "1"]\n        try:\n            i = next(i for i in range(len(p)-2) if p[i:i+3] == marker)\n            col = int(p[i+3]); idx = int(p[i+4]) if len(p) > i+4 else 0\n        except Exception:\n            continue\n        v=numeric_value(raw)\n        # Mimosa dBm1 values are reported in tenths of a dB in the SNMP MIB.\n        # Keep frequency unchanged; scale power/noise/SNR to real dashboard units.\n        if v is not None and col in {2,3,4,5}:\n            v = v / 10.0\n        row={"index":idx}\n        if col==2 and v is not None: row["tx_power"]=f"{v:g} dBm"; chain_tx.append(v)\n        elif col==3 and v is not None: row["rx_power"]=f"{v:g} dBm"; chain_rx.append(v)\n        elif col==4 and v is not None: row["noise_floor"]=f"{v:g} dBm"; chain_noise.append(v)\n        elif col==5 and v is not None: row["snr"]=f"{v:g} dB"; chain_snr.append(v)\n        elif col==6 and v is not None: row["frequency"]=f"{v:g} MHz"; chain_freq.append(v)\n        elif col==7 and s(raw): row["polarization"]=s(raw)\n        if len(row)>1:\n            old=next((x for x in out["mimosa_chains"] if x["index"]==idx),None)\n            if old: old.update(row)\n            else: out["mimosa_chains"].append(row)\n    tx=avg_values(chain_tx);rx=avg_values(chain_rx);nf=avg_values(chain_noise);snr=avg_values(chain_snr);freq=avg_values(chain_freq)\n    if tx is not None: out["tx_power"]=f"{tx:g} dBm"\n    if rx is not None: out["rx_power"]=f"{rx:g} dBm";out["signal_strength"]=out["rx_power"]\n    if nf is not None: out["noise_floor"]=f"{nf:g} dBm"\n    if snr is not None: out["snr"]=f"{snr:g} dB"\n    if freq is not None: out["frequency"]=f"{freq:g} MHz"\n    if out["mimosa_chains"]:\n        out["antenna_count"]=len(out["mimosa_chains"])\n    return out\n\n\ndef parse_racom_vendor(data: dict[str, str]) -> dict[str, Any]:\n    out: dict[str, Any] = {"racom_snmp": data}\n    prefixes = {\n        "station_name":"33555.2.1.1.1", "device_type_code":"33555.2.1.1.2",\n        "serial_number":"33555.2.1.1.4", "device_mode":"33555.2.1.1.5",\n        "sw_version":"33555.2.1.1.7.1",\n        "rx_frequency":"33555.2.2.1.1", "tx_frequency":"33555.2.2.1.2",\n        "rf_power":"33555.2.2.1.3",\n    }\n    for key,prefix in prefixes.items():\n        for oid,raw in data.items():\n            if oid == prefix or oid.startswith(prefix+"."):\n                out[key]=s(raw);break\n    name=s(out.get("station_name"));serial=s(out.get("serial_number"));sw=s(out.get("sw_version"));\n    if name: out["hostname"]=name\n    if serial: out["serial_number"]=serial\n    if sw: out["routeros_version"]=sw;out["firmware_version"]=sw\n    rf=numeric_value(out.get("rf_power"))\n    if rf is not None: out["tx_power"]=f"{rf:g} W"\n    rxf=numeric_value(out.get("rx_frequency"));txf=numeric_value(out.get("tx_frequency"))\n    if rxf is not None: out["frequency"]=f"{rxf/1_000_000:g} MHz"\n    elif txf is not None: out["frequency"]=f"{txf/1_000_000:g} MHz"\n\n    rss=[]\n    for oid,raw in data.items():\n        # wvRemRssLast is 33555.2.4.3.1.4.X\n        if oid.startswith("33555.2.4.3.1.4."):\n            v=numeric_value(raw)\n            if v is not None:rss.append(v)\n    if not rss:\n        for oid,raw in data.items():\n            if oid.startswith("33555.2.4.3.1.5."):\n                v=numeric_value(raw)\n                if v is not None:\n                    # average RSS is hundredths of dBm in the documented MIB.\n                    rss.append(v/100.0)\n    rv=avg_values(rss)\n    if rv is not None: out["rx_power"]=f"{rv:g} dBm";out["signal_strength"]=out["rx_power"]\n    return out\n\n\ndef snmp_vendor_collect(ip: str, city: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:\n    community=s(base.get("snmp_community"))\n    vendor=s(base.get("vendor"))\n    if not community or not vendor:\n        return {}\n    try:\n        if vendor == "Mimosa":\n            raw=snmpbulkwalk_numeric(ip,community,MIMOSA_CHAIN_ROOT,city)\n            return parse_mimosa_vendor(raw) if raw else {}\n        if vendor == "Racom":\n            raw={}\n            for root in (RACOM_DEVICE_ROOT,RACOM_RADIO_ROOT,RACOM_WATCHED_ROOT):\n                raw.update(snmpbulkwalk_numeric(ip,community,root,city))\n            return parse_racom_vendor(raw) if raw else {}\n    except Exception as exc:\n        LOG.debug("Vendor SNMP normalize %s failed: %s", ip, exc)\n    return {}\n'''
    c = replace_once(c, helper_anchor, helper_new, "scanner vendor helpers")

    old = '''    out.update({"hostname": s(by.get("sysName")), "firmware_version": descr, "uptime": s(by.get("sysUpTime"))})\n\n    cpu = s(by.get("hrProcessorLoad"))\n'''
    new = '''    out.update({"hostname": s(by.get("sysName")), "firmware_version": descr, "uptime": s(by.get("sysUpTime"))})\n\n    vendor_data=snmp_vendor_collect(ip,city,out)\n    if vendor_data:\n        merge_nonempty(out,vendor_data,preserve={"mimosa_chains","racom_snmp"})\n        out["snmp_vendor_raw"]=vendor_data.get("mimosa_chains") or vendor_data.get("racom_snmp") or vendor_data\n\n    cpu = s(by.get("hrProcessorLoad"))\n'''
    c = replace_once(c, old, new, "scanner vendor collect")

    old = '''    data["raw_data"]=json.dumps({"snmp":sn,"api":api_data,"ssh":ssh_data},ensure_ascii=False,default=str)\n'''
    new = '''    data["raw_data"]=json.dumps({"snmp":sn,"api":api_data,"ssh":ssh_data},ensure_ascii=False,default=str)\n'''
    c = replace_once(c, old, new, "scanner raw data anchor")

    backup(p); p.write_text(c, encoding="utf-8")

def patch_database() -> None:
    p=ROOT/"database.py"; c=p.read_text(encoding="utf-8")

    old='''        rows=c.execute(f"SELECT d.* FROM devices d WHERE {' AND '.join(where)} ORDER BY d.ip_address",args).fetchall()\n        return [dict(r) for r in rows]\n'''
    new='''        rows=c.execute(f"SELECT d.* FROM devices d WHERE {' AND '.join(where)} ORDER BY d.ip_address",args).fetchall()\n        result=[dict(r) for r in rows]\n        # Manual IP targets are materialized in devices by add_manual_ip(); the\n        # query above therefore remains the single source for the dashboard.\n        return result\n'''
    c=replace_once(c,old,new,"database get_devices comment")

    old='''def add_manual_ip(ip,description=""):\n    from ipaddress import ip_address;ip_address(ip);c=connect()\n    try:cur=c.execute("INSERT INTO manual_ips(ip_address,description,created_at) VALUES(?,?,?)",(ip.strip(),description.strip(),now()));c.commit();return dict(c.execute("SELECT * FROM manual_ips WHERE id=?",(cur.lastrowid,)).fetchone())\n    finally:c.close()\n'''
    new='''def add_manual_ip(ip,description=""):\n    from ipaddress import ip_address,ip_network\n    ip=str(ip_address(ip));c=connect()\n    try:\n        cur=c.execute("INSERT INTO manual_ips(ip_address,description,created_at) VALUES(?,?,?)",(ip,description.strip(),now()))\n        # Resolve a matching configured city so the manual target appears\n        # under that city immediately, even before its first scan.\n        matched=None\n        for city in c.execute("SELECT * FROM cities WHERE enabled=1 ORDER BY id").fetchall():\n            try:\n                if ip_address(ip) in ip_network(city["cidr"],strict=False):\n                    matched=dict(city);break\n            except Exception:\n                continue\n        if matched:\n            c.execute("""INSERT INTO devices(ip_address,city_id,city,scan_status,last_updated) VALUES(?,?,?,?,?)\n                        ON CONFLICT(ip_address) DO NOTHING""",(ip,matched["id"],matched["name"],"manual_pending",now()))\n        else:\n            c.execute("""INSERT INTO devices(ip_address,city_id,city,scan_status,last_updated) VALUES(?,?,?,?,?)\n                        ON CONFLICT(ip_address) DO NOTHING""",(ip,None,"Manual","manual_pending",now()))\n        c.commit();return dict(c.execute("SELECT * FROM manual_ips WHERE id=?",(cur.lastrowid,)).fetchone())\n    finally:c.close()\n'''
    c=replace_once(c,old,new,"database manual ip materialization")

    old='''        cities=[dict(x) for x in c.execute("SELECT c.id,c.name,c.cidr,COUNT(d.id) total,SUM(CASE WHEN d.scan_status='success' THEN 1 ELSE 0 END) online FROM cities c LEFT JOIN devices d ON d.city_id=c.id GROUP BY c.id ORDER BY c.name")]\n        last=c.execute('SELECT * FROM scan_logs ORDER BY id DESC LIMIT 1').fetchone()\n        return {'total_devices':total,'online_devices':online,'cities':cities,'last_scan':dict(last) if last else None}\n'''
    new='''        cities=[dict(x) for x in c.execute("""\n            SELECT c.id,c.name,c.cidr,\n                   COUNT(DISTINCT d.id) total,\n                   COUNT(DISTINCT CASE WHEN d.scan_status='success' THEN d.id END) online\n            FROM cities c\n            LEFT JOIN devices d\n              ON (d.city_id=c.id OR d.city=c.name OR d.manual_city=c.name)\n             AND NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)\n            GROUP BY c.id ORDER BY c.name\n        """)]\n        province_rows=c.execute("""\n            SELECT COALESCE(NULLIF(d.manual_province,''),NULLIF(d.province,''),NULLIF(d.city,''),'نامشخص') province,\n                   COUNT(DISTINCT d.id) total,\n                   COUNT(DISTINCT CASE WHEN d.scan_status='success' THEN d.id END) online\n            FROM devices d\n            WHERE NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)\n            GROUP BY COALESCE(NULLIF(d.manual_province,''),NULLIF(d.province,''),NULLIF(d.city,''),'نامشخص')\n            ORDER BY province\n        """).fetchall()\n        last=c.execute('SELECT * FROM scan_logs ORDER BY id DESC LIMIT 1').fetchone()\n        return {'total_devices':total,'online_devices':online,'cities':cities,'provinces':[dict(x) for x in province_rows],'last_scan':dict(last) if last else None}\n'''
    c=replace_once(c,old,new,"database robust city/province stats")

    backup(p);p.write_text(c,encoding="utf-8")

def patch_excel() -> None:
    p=ROOT/"excel_manager.py";c=p.read_text(encoding="utf-8")
    c=replace_once(c,'RADIO_HEADERS=["IP","Name","Model","Vendor","Serial","SSID","Frequency","Channel","Bandwidth","Mode","Radio Name","TX Power","RX Power","Signal","Peer TX Signal","TX Rate","RX Rate","CCQ","SNR","Noise Floor","Notes"]\n', 'RADIO_HEADERS=["IP","Name","Model","Vendor","Serial","SSID","Frequency","Channel","Bandwidth","Mode","Radio Name","TX Power","RX Power","Signal","Peer TX Signal","TX Rate","RX Rate","CCQ","SNR","Noise Floor","Notes"]\nWIRELESS_HEADERS=["IP","City","Vendor","Type","Hostname","Model","SSID","Frequency","Channel","Bandwidth","Mode","Radio","TX Power","RX Power","Signal","Peer TX Signal","TX Rate","RX Rate","CCQ","TX CCQ","RX CCQ","SNR","Noise Floor","Status","Last Seen"]\n',"excel wireless headers")

    c=replace_once(c,'def export_excel(db_path, hours=None, mode="full"):\n', 'def export_excel(db_path, hours=None, mode="full", city_id=None, ip_address=None):\n',"excel export signature")

    anchor='''        if mode=="blacklist":\n            rows=[dict(r) for r in conn.execute("SELECT entry,description,enabled FROM blacklist ORDER BY entry")];add_sheet(wb,"Blacklist",BLACK_HEADERS,rows)\n        elif mode=="radios":\n'''
    insert='''        if mode=="blacklist":\n            rows=[dict(r) for r in conn.execute("SELECT entry,description,enabled FROM blacklist ORDER BY entry")];add_sheet(wb,"Blacklist",BLACK_HEADERS,rows)\n        elif mode=="wireless":\n            where=["d.scan_status='success'", "NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)"]\n            args=[]\n            if city_id is not None:\n                where.append("d.city_id=?");args.append(int(city_id))\n            if ip_address:\n                where.append("d.ip_address=?");args.append(str(ip_address))\n            if hours is not None and int(hours)>0:\n                cutoff=(datetime.now()-timedelta(hours=int(hours))).strftime("%Y-%m-%d %H:%M:%S")\n                where.append("d.last_seen>=?");args.append(cutoff)\n            rows=[dict(r) for r in conn.execute("""\n                SELECT d.ip_address IP,d.city City,d.vendor Vendor,d.device_type Type,d.hostname Hostname,d.model Model,\n                       d.ssid SSID,d.frequency Frequency,d.channel Channel,d.bandwidth Bandwidth,d.mode Mode,d.radio_name Radio,\n                       d.tx_power 'TX Power',d.rx_power 'RX Power',d.signal_strength Signal,d.peer_tx_signal 'Peer TX Signal',\n                       d.tx_rate 'TX Rate',d.rx_rate 'RX Rate',d.ccq CCQ,d.tx_ccq 'TX CCQ',d.rx_ccq 'RX CCQ',d.snr SNR,\n                       d.noise_floor 'Noise Floor',d.scan_status Status,d.last_seen 'Last Seen'\n                FROM devices d WHERE %s ORDER BY d.city,d.ip_address\n            """ % " AND ".join(where),args)]\n            add_sheet(wb,"Wireless",WIRELESS_HEADERS,rows)\n        elif mode=="radios":\n'''
    c=replace_once(c,anchor,insert,"excel wireless mode")

    backup(p);p.write_text(c,encoding="utf-8")

def patch_app() -> None:
    p=ROOT/"app.py";c=p.read_text(encoding="utf-8")

    anchor='''@app.get("/api/excel/export")\n@auth\n@full\ndef excel_export():\n'''
    new='''@app.get("/api/excel/wireless")\n@auth\ndef excel_wireless_export():\n    hours=request.args.get("hours","all")\n    try: hours=None if hours=="all" else int(hours)\n    except: hours=None\n    city_id=request.args.get("city_id")\n    try: city_id=int(city_id) if city_id not in (None,"") else None\n    except: city_id=None\n    ip=request.args.get("ip"," ").strip() or None\n    # View users can export only the successful Wireless data they are allowed to see.\n    if request.current_user["role"]!="full" and ip:\n        d=db.get_device(ip)\n        if not d or d.get("scan_status")!="success":\n            return jsonify(error="device_offline"),403\n    data=export_excel(DB_PATH,hours=hours,mode="wireless",city_id=city_id,ip_address=ip)\n    suffix=(f"{city_id}" if city_id is not None else (ip.replace('.','_') if ip else "all"))\n    return send_file(data,as_attachment=True,download_name=f"wireless_{suffix}_{hours or 'all'}h.xlsx",mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")\n\n@app.get("/api/excel/export")\n@auth\n@full\ndef excel_export():\n'''
    c=replace_once(c,anchor,new,"app wireless export endpoint")
    backup(p);p.write_text(c,encoding="utf-8")

def patch_index() -> None:
    p=ROOT/"index.html";c=p.read_text(encoding="utf-8")

    # City page: Wireless export for every role, using only that city.
    old='''<div class="toolbar"><input id="citySearch" placeholder="جستجو نام / SSID / مدل / IP"><button class="btn" onclick="filterCity()">جستجو</button></div>'''
    new='''<div class="toolbar"><input id="citySearch" placeholder="جستجو نام / SSID / مدل / IP"><button class="btn" onclick="filterCity()">جستجو</button><select id="cityWirelessHours"><option value="12">۱۲ ساعت</option><option value="24" selected>۲۴ ساعت</option><option value="36">۳۶ ساعت</option><option value="all">همه</option></select><button class="btn" onclick="exportWirelessCity(currentCity)">📤 خروجی Wireless Excel</button></div>'''
    if old in c:c=c.replace(old,new,1)

    anchor='''async function filterCity(){const q=$('citySearch')?.value||'';const rows=await api('/api/devices?city_id='+currentCity+'&q='+encodeURIComponent(q));renderDevices(rows,'cityTable')}\n'''
    add='''async function filterCity(){const q=$('citySearch')?.value||'';const rows=await api('/api/devices?city_id='+currentCity+'&q='+encodeURIComponent(q));renderDevices(rows,'cityTable')}\nasync function exportWirelessCity(cityId){const hours=$('cityWirelessHours')?.value||'all';await fileDownload('/api/excel/wireless?city_id='+encodeURIComponent(cityId)+'&hours='+encodeURIComponent(hours),'wireless_city_'+cityId+'_'+hours+'.xlsx')}\nasync function exportWirelessDevice(ip){const hours=$('wirelessDeviceHours')?.value||'all';await fileDownload('/api/excel/wireless?ip='+encodeURIComponent(ip)+'&hours='+encodeURIComponent(hours),'wireless_'+ip.replaceAll('.','_')+'_'+hours+'.xlsx')}\n'''
    c=replace_once(c,anchor,add,"index export wireless functions")

    # Wireless detail tab: export button for view and full roles; keep Radio Scan for full.
    old='''if(name==='wireless')rows=[['SSID',d.ssid],['Frequency',d.frequency],['Channel',d.channel],['Bandwidth',d.bandwidth],['Mode',d.mode],['Radio',d.radio_name],['Interface',d.interface_name],['Wireless Status',d.wireless_status],['TX Power',d.tx_power],['RX Power',d.rx_power||d.signal_strength],['Signal',d.signal_strength],['Peer TX Signal',d.peer_tx_signal],['TX Rate',d.tx_rate],['RX Rate',d.rx_rate],['CCQ',d.ccq],['TX CCQ',d.tx_ccq],['RX CCQ',d.rx_ccq],['SNR',d.snr],['Noise Floor',d.noise_floor]];'''
    new='''if(name==='wireless')rows=[['SSID',d.ssid],['Frequency',d.frequency],['Channel',d.channel],['Bandwidth',d.bandwidth],['Mode',d.mode],['Radio',d.radio_name],['Interface',d.interface_name],['Wireless Status',d.wireless_status],['TX Power',d.tx_power],['RX Power',d.rx_power||d.signal_strength],['Signal',d.signal_strength],['Peer TX Signal',d.peer_tx_signal],['TX Rate',d.tx_rate],['RX Rate',d.rx_rate],['CCQ',d.ccq],['TX CCQ',d.tx_ccq],['RX CCQ',d.rx_ccq],['SNR',d.snr],['Noise Floor',d.noise_floor]];'''
    c=replace_once(c,old,new,"index wireless detail rows")

    old='''$('detailBody').innerHTML=rowsHtml(rows)+ (name==='wireless'&&ME.role==='full'?`<div class="toolbar"><button class="btn" onclick="radioScan('${encodeURIComponent(d.ip_address)}')">📡 اجرای Radio Scan دستی</button></div>`:'')}'''
    new='''$('detailBody').innerHTML=rowsHtml(rows)+ (name==='wireless'?`<div class="toolbar"><select id="wirelessDeviceHours"><option value="12">۱۲ ساعت</option><option value="24" selected>۲۴ ساعت</option><option value="36">۳۶ ساعت</option><option value="all">همه</option></select><button class="btn" onclick="exportWirelessDevice('${encodeURIComponent(d.ip_address)}')">📤 خروجی Wireless Excel</button>${ME.role==='full'?`<button class="btn" onclick="radioScan('${encodeURIComponent(d.ip_address)}')">📡 اجرای Radio Scan دستی</button>`:''}</div>`:'')}'''
    c=replace_once(c,old,new,"index wireless export toolbar")
    backup(p);p.write_text(c,encoding="utf-8")

def main():
    needed=["scanner.py","database.py","excel_manager.py","app.py","index.html","Dockerfile"]
    for x in needed:
        if not (ROOT/x).exists(): raise SystemExit(f"Missing {x}")
    patch_dockerfile();patch_scanner();patch_database();patch_excel();patch_app();patch_index()
    r=subprocess.run(["python3","-m","py_compile","scanner.py","routeros_api.py","database.py","excel_manager.py","app.py"],cwd=ROOT,text=True,capture_output=True)
    if r.returncode:
        print(r.stdout);print(r.stderr);raise SystemExit("Syntax check failed")
    print("PHASE-2 FIX APPLIED SUCCESSFULLY")
    print("Backups: *.phase2.bak")
    print("Validated: scanner.py routeros_api.py database.py excel_manager.py app.py")
    print("Next commands:")
    print("  git diff --check")
    print("  docker compose build --no-cache")
    print("  docker compose up -d")

if __name__ == "__main__": main()
