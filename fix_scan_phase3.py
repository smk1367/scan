#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wireless Monitor phase-3 patch.

Additive fixes; preserves existing features.

Fixes:
- City cards show real total/online counts from /api/stats.
- City/device table shows IP as a separate column.
- Mimosa is collected by SNMP only using the Mimosa BFIVE MIB numeric tree.
- Mimosa chain/RF/performance/location/general data is exposed in the record.
- Manual IPs can be explicitly assigned to a city and then use that city's
  SNMP/SSH/API ports, timeouts and credentials.
- Manual IPs appear immediately in the dashboard as manual_pending.
- Antenna/site fields are editable per device and import/export by city via Excel.
- View users get an Excel dashboard tab containing all data they can see,
  without credentials or management-only sheets.

Backups are created once per file as *.phase3.bak.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def backup(p: Path) -> None:
    b = p.with_suffix(p.suffix + ".phase3.bak")
    if not b.exists():
        shutil.copy2(p, b)


def repl_once(c: str, old: str, new: str, label: str) -> str:
    n = c.count(old)
    if n != 1:
        raise RuntimeError(f"{label}: expected 1 match, found {n}")
    return c.replace(old, new, 1)


def repl_if(c: str, old: str, new: str, label: str) -> str:
    if old in c:
        return repl_once(c, old, new, label)
    return c


def patch_dockerfile() -> None:
    p = ROOT / "Dockerfile"
    c = p.read_text(encoding="utf-8")
    if re.search(r"\bsnmp\s+\\", c) is None:
        old = "        openssh-client \\\n        sshpass \\\n        iputils-ping \\\n"
        new = "        openssh-client \\\n        sshpass \\\n        iputils-ping \\\n        snmp \\\n"
        c = repl_once(c, old, new, "Dockerfile snmp package")
        backup(p)
        p.write_text(c, encoding="utf-8")


def patch_database() -> None:
    p = ROOT / "database.py"
    c = p.read_text(encoding="utf-8")

    # Add explicit city to manual_ips.
    marker = '''CREATE TABLE IF NOT EXISTS manual_ips (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    ip_address TEXT UNIQUE NOT NULL,\n    description TEXT DEFAULT '',\n    enabled INTEGER DEFAULT 1,\n    created_at TEXT NOT NULL\n);'''
    if marker in c and "    city_id INTEGER,\n" not in c[c.find(marker):c.find(marker)+250]:
        c = repl_once(
            c,
            marker,
            '''CREATE TABLE IF NOT EXISTS manual_ips (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    ip_address TEXT UNIQUE NOT NULL,\n    city_id INTEGER,\n    description TEXT DEFAULT '',\n    enabled INTEGER DEFAULT 1,\n    created_at TEXT NOT NULL\n);''',
            "manual_ips schema",
        )

    # Legacy DB migration.
    if '_ensure_columns(c, "manual_ips", {"city_id": "INTEGER"})' not in c:
        anchor = '''        _ensure_columns(c, "cities", {\n'''
        if anchor in c:
            c = repl_once(
                c,
                anchor,
                '''        _ensure_columns(c, "manual_ips", {"city_id": "INTEGER"})\n        _ensure_columns(c, "cities", {\n''',
                "manual_ips city migration",
            )

    # add_manual_ip(): city-aware and immediately materialized.
    start = c.find("def add_manual_ip(")
    end = c.find("\n\ndef delete_manual_ip", start)
    if start < 0 or end < 0:
        raise RuntimeError("add_manual_ip() not found")
    new_func = '''def add_manual_ip(ip,description="",city_id=None):
    from ipaddress import ip_address,ip_network
    ip=str(ip_address(ip));c=connect()
    try:
        selected_city_id=int(city_id) if city_id not in (None,"") else None
        matched=None
        if selected_city_id is not None:
            row=c.execute("SELECT * FROM cities WHERE id=? AND enabled=1",(selected_city_id,)).fetchone()
            if not row:
                raise ValueError("شهر انتخاب‌شده معتبر نیست")
            matched=dict(row)
        else:
            for row in c.execute("SELECT * FROM cities WHERE enabled=1 ORDER BY id").fetchall():
                try:
                    if ip_address(ip) in ip_network(row["cidr"],strict=False):
                        matched=dict(row)
                        selected_city_id=int(row["id"])
                        break
                except Exception:
                    continue

        cur=c.execute("""INSERT INTO manual_ips(ip_address,city_id,description,enabled,created_at)
                        VALUES(?,?,?,?,?)
                        ON CONFLICT(ip_address) DO UPDATE SET
                          city_id=excluded.city_id,
                          description=excluded.description,
                          enabled=1""",
                       (ip,selected_city_id,description.strip(),1,now()))

        if matched:
            c.execute("""INSERT INTO devices(ip_address,city_id,city,scan_status,last_updated)
                        VALUES(?,?,?,?,?)
                        ON CONFLICT(ip_address) DO UPDATE SET
                          city_id=excluded.city_id,
                          city=CASE
                                 WHEN COALESCE(devices.city,'') IN ('','Manual') THEN excluded.city
                                 ELSE devices.city
                               END""",
                       (ip,matched["id"],matched["name"],"manual_pending",now()))
        else:
            c.execute("""INSERT INTO devices(ip_address,city_id,city,scan_status,last_updated)
                        VALUES(?,?,?,?,?)
                        ON CONFLICT(ip_address) DO NOTHING""",
                       (ip,None,"Manual","manual_pending",now()))
        c.commit()
        return dict(c.execute("SELECT * FROM manual_ips WHERE ip_address=?",(ip,)).fetchone())
    finally:c.close()
'''
    c = c[:start] + new_func + c[end:]

    # list_manual_ips() includes city data.
    start = c.find("def list_manual_ips():")
    end = c.find("\n\ndef add_manual_ip", start)
    if start >= 0 and end >= 0:
        func = '''def list_manual_ips():
    c=connect()
    try:
        rows=c.execute("""SELECT m.*,c.name AS city_name,c.cidr AS city_cidr
                         FROM manual_ips m LEFT JOIN cities c ON c.id=m.city_id
                         ORDER BY m.ip_address""").fetchall()
        return [dict(x) for x in rows]
    finally:c.close()
'''
        c = c[:start] + func + c[end:]

    # Add a direct city-count helper for callers that need only active cities.
    if "def get_city_counts(" not in c:
        anchor = "\ndef get_stats():"
        helper = '''\ndef get_city_counts():
    c=connect()
    try:
        rows=c.execute("""SELECT c.id,c.name,c.cidr,
                COUNT(DISTINCT d.id) AS total,
                COUNT(DISTINCT CASE WHEN d.scan_status='success' THEN d.id END) AS online
            FROM cities c
            LEFT JOIN devices d ON d.city_id=c.id
            WHERE c.enabled=1
              AND NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)
            GROUP BY c.id,c.name,c.cidr ORDER BY c.name""").fetchall()
        return [dict(x) for x in rows]
    finally:c.close()
'''
        c = c.replace(anchor, helper + anchor, 1)

    backup(p)
    p.write_text(c, encoding="utf-8")


def patch_scanner() -> None:
    p = ROOT / "scanner.py"
    c = p.read_text(encoding="utf-8")

    # Complete Mimosa roots.
    if "MIMOSA_GENERAL_ROOT =" not in c:
        anchor = '''IF_OIDS = {\n    "name": "1.3.6.1.2.1.31.1.1.1.1",\n    "descr": "1.3.6.1.2.1.2.2.1.2",\n    "oper": "1.3.6.1.2.1.2.2.1.8",\n    "admin": "1.3.6.1.2.1.2.2.1.7",\n    "in_octets": "1.3.6.1.2.1.31.1.1.1.6",\n    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",\n    "in_errors": "1.3.6.1.2.1.2.2.1.14",\n    "out_errors": "1.3.6.1.2.1.2.2.1.20",\n}\n'''
        if anchor not in c:
            raise RuntimeError("IF_OIDS anchor missing")
        ins = anchor + '''\nMIMOSA_ROOT = "1.3.6.1.4.1.43356"\nMIMOSA_GENERAL_ROOT = "1.3.6.1.4.1.43356.2.1.2.1"\nMIMOSA_LOC_ROOT = "1.3.6.1.4.1.43356.2.1.2.2"\nMIMOSA_RF_ROOT = "1.3.6.1.4.1.43356.2.1.2.6"\nMIMOSA_CHAIN_ROOT = "1.3.6.1.4.1.43356.2.1.2.6.1.1"\nMIMOSA_PERF_ROOT = "1.3.6.1.4.1.43356.2.1.2.7"\n'''
        c = repl_once(c, anchor, ins, "Mimosa roots")

    # Numeric SNMP walk helper.
    if "def snmpbulkwalk_numeric(" not in c:
        anchor = '''def tcp_open(ip: str, port: int, timeout: float = 1.0) -> bool:\n    try:\n        with socket.create_connection((ip, int(port)), timeout=float(timeout)):\n            return True\n    except Exception:\n        return False\n'''
        helper = r'''\n\ndef snmpbulkwalk_numeric(ip: str, community: str, root: str, city: dict[str, Any]) -> dict[str, str]:
    if not community or not shutil.which("snmpbulkwalk"):
        return {}
    cmd=["snmpbulkwalk","-v2c","-c",community,"-On","-t",str(float(city["snmp_timeout"])),"-r",str(int(city["snmp_retries"])),ip,root]
    try:
        proc=subprocess.run(cmd,capture_output=True,text=True,timeout=max(10,int(float(city["snmp_timeout"]))*10+5))
    except Exception as exc:
        LOG.debug("SNMP vendor walk %s %s failed: %s",ip,root,exc)
        return {}
    if proc.returncode!=0:
        return {}
    out={}
    for line in proc.stdout.splitlines():
        m=re.match(r"^([^ ]+)\s*=\s*(.*)$",line.strip())
        if not m: continue
        oid,raw=m.group(1),m.group(2)
        val=raw.split(":",1)[1].strip() if ":" in raw else raw.strip()
        out[oid.lstrip(".")]=val
    return out
\n\ndef numeric_value(raw: Any) -> float | None:
    m=re.search(r"-?\d+(?:\.\d+)?",s(raw))
    if not m: return None
    try:return float(m.group(0))
    except Exception:return None
\n\ndef mimosa_decimal_one(raw: Any) -> float | None:
    v=numeric_value(raw)
    return None if v is None else v/10.0
\n\ndef mimosa_decimal_two(raw: Any) -> float | None:
    v=numeric_value(raw)
    return None if v is None else v/100.0
\n\ndef mimosa_decimal_five(raw: Any) -> float | None:
    v=numeric_value(raw)
    return None if v is None else v/100000.0
'''
        if anchor in c:
            c = repl_once(c, anchor, anchor + helper, "vendor SNMP helper")

    # Replace Mimosa parser with a full parser.
    ms = c.find("def parse_mimosa_vendor(")
    me = c.find("\n\ndef parse_racom_vendor", ms)
    if ms < 0 or me < 0:
        raise RuntimeError("parse_mimosa_vendor() missing")
    parser = r'''def parse_mimosa_vendor(data: dict[str, str]) -> dict[str, Any]:
    out={"mimosa_snmp":data,"mimosa_chains":[]}
    general=MIMOSA_GENERAL_ROOT.lstrip(".")
    loc=MIMOSA_LOC_ROOT.lstrip(".")
    rf=MIMOSA_RF_ROOT.lstrip(".")
    chain=MIMOSA_CHAIN_ROOT.lstrip(".")
    perf=MIMOSA_PERF_ROOT.lstrip(".")

    def val(root,suffix):
        return data.get(root+"."+suffix)

    v=val(general,"1");
    if s(v): out["mimosa_device_name"]=s(v);out["hostname"]=s(v)
    v=val(general,"2");
    if s(v): out["serial_number"]=s(v)
    v=val(general,"3");
    if s(v): out["firmware_version"]=s(v)
    v=val(general,"4");
    if s(v): out["firmware_build_date"]=s(v)
    v=val(general,"5");
    if s(v): out["last_reboot_time"]=s(v)
    v=mimosa_decimal_one(val(general,"8"));
    if v is not None: out["temperature"]=f"{v:g} C"

    v=mimosa_decimal_five(val(loc,"1"));
    if v is not None: out["longitude"]=f"{v:g}"
    v=mimosa_decimal_five(val(loc,"2"));
    if v is not None: out["latitude"]=f"{v:g}"
    v=numeric_value(val(loc,"3"));
    if v is not None: out["altitude"]=f"{v:g} m"
    v=mimosa_decimal_one(val(loc,"4"));
    if v is not None: out["gps_snr"]=f"{v:g} dB"
    v=numeric_value(val(loc,"6"));
    if v is not None: out["gps_satellites"]=f"{v:g}"
    v=numeric_value(val(loc,"7"));
    if v is not None: out["glonass_satellites"]=f"{v:g}"

    v=numeric_value(val(rf,"4"));
    if v is not None: out["antenna_gain"]=f"{v:g} dBi"
    v=mimosa_decimal_one(val(rf,"5"));
    if v is not None: out["total_tx_power"]=f"{v:g} dBm"
    v=mimosa_decimal_one(val(rf,"6"));
    if v is not None: out["total_rx_power"]=f"{v:g} dBm"
    v=numeric_value(val(rf,"7"));
    if v is not None: out["target_signal_strength"]=f"{v:g} dB"

    tx=[];rx=[];noise=[];snr=[];freq=[];pol=[]
    for oid,raw in data.items():
        if not oid.startswith(chain+"."): continue
        parts=oid[len(chain)+1:].split(".")
        if len(parts)<2: continue
        try:col=int(parts[0]);idx=int(parts[1])
        except Exception:continue
        row=next((x for x in out["mimosa_chains"] if x.get("index")==idx),None)
        if row is None:
            row={"index":idx};out["mimosa_chains"].append(row)
        v=numeric_value(raw)
        if col==1: row["chain"]=s(raw)
        elif col==2 and v is not None:
            v/=10;row["tx_power"]=f"{v:g} dBm";tx.append(v)
        elif col==3 and v is not None:
            v/=10;row["rx_power"]=f"{v:g} dBm";rx.append(v)
        elif col==4 and v is not None:
            v/=10;row["noise_floor"]=f"{v:g} dBm";noise.append(v)
        elif col==5 and v is not None:
            v/=10;row["snr"]=f"{v:g} dB";snr.append(v)
        elif col==6 and v is not None:
            row["frequency"]=f"{v:g} MHz";freq.append(v)
        elif col==7 and s(raw):
            row["polarization"]=s(raw);pol.append(s(raw))

    if tx:out["tx_power"]=f"{sum(tx)/len(tx):g} dBm"
    if rx:out["rx_power"]=f"{sum(rx)/len(rx):g} dBm";out["signal_strength"]=out["rx_power"]
    if noise:out["noise_floor"]=f"{sum(noise)/len(noise):g} dBm"
    if snr:out["snr"]=f"{sum(snr)/len(snr):g} dB"
    if freq:out["frequency"]=f"{sum(freq)/len(freq):g} MHz"
    if pol:out["polarization"]=pol[0]

    v=numeric_value(val(perf,"1"));
    if v is not None:out["tx_rate"]=f"{v/1000:g} Mbps"
    v=numeric_value(val(perf,"2"));
    if v is not None:out["rx_rate"]=f"{v/1000:g} Mbps"
    v=mimosa_decimal_two(val(perf,"3"));
    if v is not None:out["tx_per"]=f"{v:g}%"
    v=mimosa_decimal_two(val(perf,"4"));
    if v is not None:out["rx_per"]=f"{v:g}%"

    if out["mimosa_chains"]:
        out["antenna_count"]=len(out["mimosa_chains"])
        out["chain_summary"]=json.dumps(out["mimosa_chains"],ensure_ascii=False)
    return out
'''
    c=c[:ms]+parser+c[me:]

    # Ensure vendor collection can discover Mimosa directly even if standard
    # sysOID/sysDescr is incomplete.
    vs=c.find("def snmp_vendor_collect(")
    ve=c.find("\n\ndef scan_one",vs)
    if vs<0 or ve<0:
        raise RuntimeError("snmp_vendor_collect() missing")
    vendor_func=r'''def snmp_vendor_collect(ip: str, city: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    community=s(base.get("snmp_community"))
    vendor=s(base.get("vendor"))
    if not community:return {}
    try:
        if vendor=="Mimosa" or not vendor:
            raw=snmpbulkwalk_numeric(ip,community,MIMOSA_ROOT,city)
            if raw:
                parsed=parse_mimosa_vendor(raw)
                if parsed:
                    parsed["vendor"]="Mimosa"
                    parsed["device_type"]="Mimosa"
                    return parsed
        if vendor=="Racom":
            raw={}
            for root in (RACOM_DEVICE_ROOT,RACOM_RADIO_ROOT,RACOM_WATCHED_ROOT):
                raw.update(snmpbulkwalk_numeric(ip,community,root,city))
            return parse_racom_vendor(raw) if raw else {}
    except Exception as exc:
        LOG.debug("Vendor SNMP normalize %s failed: %s",ip,exc)
    return {}
'''
    c=c[:vs]+vendor_func+c[ve:]

    # Detect vendor after standard SNMP and skip API/SSH for Mimosa/Racom.
    old='''    sn=snmp_collect(ip,city);merge_nonempty(data,{k:v for k,v in sn.items() if k not in {"snmp_raw","snmp_community"}})\n    api_data={}\n'''
    if old in c:
        new='''    sn=snmp_collect(ip,city)\n    merge_nonempty(data,{k:v for k,v in sn.items() if k not in {"snmp_raw","snmp_community","snmp_vendor_raw"}})\n    if not data.get("device_type"):\n        try:\n            direct_vendor=snmp_vendor_collect(ip,city,{"snmp_community":sn.get("snmp_community")})\n        except Exception:\n            direct_vendor={}\n        if direct_vendor:\n            merge_nonempty(data,direct_vendor,preserve={"mimosa_snmp","mimosa_chains","racom_snmp"})\n            data["device_type"]=direct_vendor.get("device_type") or direct_vendor.get("vendor")\n            data["vendor"]=direct_vendor.get("vendor") or data.get("device_type")\n            data["snmp_vendor_raw"]=direct_vendor.get("mimosa_snmp") or direct_vendor.get("racom_snmp") or direct_vendor\n    snmp_only_vendor=data.get("device_type") in {"Mimosa","Racom"} or data.get("vendor") in {"Mimosa","Racom"}\n    api_data={}\n'''
        c=repl_once(c,old,new,"scanner SNMP-first block")

    old='''    # Try plain RouterOS API when enabled. A successful API login can\n    # identify MikroTik even when SNMP is unavailable. API-SSL is never used.\n    if int(city.get("api_enabled",1)) and int(city.get("api_ssl_enabled",0))==0:\n'''
    if old in c:
        c=repl_once(c,old,'''    # RouterOS API is for MikroTik; Mimosa/Racom are SNMP-only.\n    if (not snmp_only_vendor) and int(city.get("api_enabled",1)) and int(city.get("api_ssl_enabled",0))==0:\n''',"scanner skip vendor API")

    old='''    ssh_data={}\n    try:\n        c,method=ssh_connect(ip,city)\n'''
    if old in c:
        c=repl_once(c,old,'''    ssh_data={}\n    if snmp_only_vendor:\n        data["api_status"]="not_used_snmp_only"\n        data["ssh_status"]="not_used_snmp_only"\n    try:\n        if snmp_only_vendor:\n            raise RuntimeError("SNMP-only vendor")\n        c,method=ssh_connect(ip,city)\n''',"scanner skip vendor SSH")

    old='''    protocol_ok = sn.get("snmp_status") == "success" or data.get("api_status") == "success" or data.get("ssh_status") == "success"\n'''
    if old in c:
        c=repl_once(c,old,'''    protocol_ok = (\n        sn.get("snmp_status") == "success"\n        or bool(data.get("snmp_vendor_raw"))\n        or data.get("device_type") in {"Mimosa","Racom"}\n        or data.get("api_status") == "success"\n        or data.get("ssh_status") == "success"\n    )\n''',"scanner vendor success")

    # Manual IP targets must use the city's actual configuration.
    ts=c.find("def targets(")
    te=c.find("\n\ndef run_scan",ts)
    if ts<0 or te<0:raise RuntimeError("targets() missing")
    targets_func=r'''def targets(city_ids: list[int] | None=None):
    cities=[c for c in list_cities() if c["enabled"]]
    selected=set(city_ids or [])
    if selected:
        cities=[c for c in cities if c["id"] in selected]
    out=[];seen=set();city_map={int(c["id"]):c for c in cities}
    all_city_map={int(c["id"]):c for c in list_cities()}
    for city in cities:
        try:
            for ip in ipaddress.ip_network(city["cidr"],strict=False).hosts():
                sip=str(ip)
                if sip not in seen:
                    seen.add(sip);out.append({"ip_address":sip,"city":city})
        except Exception:
            continue

    # Manual IPs: explicit city assignment wins; otherwise resolve by CIDR.
    for m in list_manual_ips():
        if not m["enabled"] or m["ip_address"] in seen:
            continue
        assigned=all_city_map.get(int(m["city_id"])) if m.get("city_id") not in (None,"") else None
        if assigned is None:
            try:
                obj=ipaddress.ip_address(m["ip_address"])
                for city in cities:
                    if obj in ipaddress.ip_network(city["cidr"],strict=False):
                        assigned=city;break
                if assigned is None:
                    for city in list_cities():
                        if obj in ipaddress.ip_network(city["cidr"],strict=False):
                            assigned=city;break
            except Exception:
                assigned=None
        if assigned is not None:
            out.append({"ip_address":m["ip_address"],"city":assigned});seen.add(m["ip_address"])
        else:
            out.append({"ip_address":m["ip_address"],"city":{"id":None,"name":"Manual","enabled":1,
                "ssh_port":int(os.getenv("SSH_PORT","22")),"snmp_port":int(os.getenv("SNMP_PORT","161")),
                "api_port":int(os.getenv("API_PORT","8728")),"api_enabled":1,"api_ssl_enabled":0,
                "api_timeout":float(os.getenv("API_TIMEOUT","4")),"snmp_timeout":float(os.getenv("SNMP_TIMEOUT","2.5")),
                "snmp_retries":int(os.getenv("SNMP_RETRIES","1")),"ssh_timeout":float(os.getenv("SSH_TIMEOUT","6")),
                "ssh_credentials_json":os.getenv("SSH_CREDENTIALS_JSON","[]"),
                "snmp_communities_json":json.dumps([os.getenv("SNMP_COMMUNITY","ngstehwl")])}})
            seen.add(m["ip_address"])
    return out
'''
    c=c[:ts]+targets_func+c[te:]

    backup(p);p.write_text(c,encoding="utf-8")


def patch_excel() -> None:
    p=ROOT/"excel_manager.py";c=p.read_text(encoding="utf-8")
    if "ANTENNA_HEADERS=" not in c:
        anchor='RADIO_HEADERS='
        pos=c.find(anchor)
        if pos<0:raise RuntimeError("Excel headers anchor missing")
        end=c.find("\n",pos)
        c=c[:end+1]+'ANTENNA_HEADERS=["IP","Scan City","Latitude","Longitude","Province","City","Antenna Gain","Polarization","Capacity"]\nVIEW_HEADERS=["IP","City","Vendor","Type","Hostname","Model","RouterOS Version","Firmware","MAC","SSID","Frequency","Channel","Bandwidth","Mode","Radio","Interface","TX Power","RX Power","Signal","Peer TX Signal","TX Rate","RX Rate","CCQ","TX CCQ","RX CCQ","SNR","Noise Floor","Temperature","CPU Load","Memory Usage","Uptime","SNMP","API","SSH","Last Seen","Status"]\n'+c[end+1:]
    if 'def export_excel(db_path, hours=None, mode="full"):' in c:
        c=c.replace('def export_excel(db_path, hours=None, mode="full"):', 'def export_excel(db_path, hours=None, mode="full", city_id=None, ip_address=None):',1)

    if 'elif mode=="antenna":' not in c:
        anchor='        elif mode=="wireless":\n'
        if anchor not in c:
            anchor='        elif mode=="radios":\n'
        antenna='''        elif mode=="antenna":\n            where=["NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)"]\n            args=[]\n            if city_id is not None:\n                where.append("d.city_id=?");args.append(int(city_id))\n            if ip_address:\n                where.append("d.ip_address=?");args.append(str(ip_address))\n            rows=[dict(r) for r in conn.execute("""\n                SELECT d.ip_address AS IP,d.city AS 'Scan City',\n                       COALESCE(NULLIF(d.manual_latitude,''),d.latitude,'') AS Latitude,\n                       COALESCE(NULLIF(d.manual_longitude,''),d.longitude,'') AS Longitude,\n                       COALESCE(NULLIF(d.manual_province,''),d.province,'') AS Province,\n                       COALESCE(d.manual_city,'') AS City,\n                       COALESCE(NULLIF(d.manual_antenna_gain,''),d.antenna_gain,'') AS 'Antenna Gain',\n                       COALESCE(NULLIF(d.manual_polarization,''),d.polarization,'') AS Polarization,\n                       COALESCE(NULLIF(d.manual_capacity,''),d.capacity,'') AS Capacity\n                FROM devices d WHERE %s ORDER BY d.city,d.ip_address\n            """ % " AND ".join(where),args)]\n            add_sheet(wb,"Antenna",ANTENNA_HEADERS,rows)\n'''
        c=repl_once(c,anchor,antenna+anchor,"Excel antenna export mode")

    if 'elif mode=="view_full":' not in c:
        anchor='        else:\n            device_rows='
        view='''        elif mode=="view_full":\n            where=["d.scan_status='success'","NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)"]\n            args=[]\n            if hours is not None and int(hours)>0:\n                cutoff=(datetime.now()-timedelta(hours=int(hours))).strftime("%Y-%m-%d %H:%M:%S")\n                where.append("d.last_seen>=?");args.append(cutoff)\n            rows=[dict(r) for r in conn.execute("""\n                SELECT d.ip_address AS IP,d.city AS City,d.vendor AS Vendor,d.device_type AS Type,d.hostname AS Hostname,\n                       d.model AS Model,d.routeros_version AS 'RouterOS Version',d.firmware_version AS Firmware,\n                       d.mac_address AS MAC,d.ssid AS SSID,d.frequency AS Frequency,d.channel AS Channel,d.bandwidth AS Bandwidth,\n                       d.mode AS Mode,d.radio_name AS Radio,d.interface_name AS Interface,d.tx_power AS 'TX Power',\n                       d.rx_power AS 'RX Power',d.signal_strength AS Signal,d.peer_tx_signal AS 'Peer TX Signal',\n                       d.tx_rate AS 'TX Rate',d.rx_rate AS 'RX Rate',d.ccq AS CCQ,d.tx_ccq AS 'TX CCQ',d.rx_ccq AS 'RX CCQ',\n                       d.snr AS SNR,d.noise_floor AS 'Noise Floor',d.temperature AS Temperature,d.cpu_load AS 'CPU Load',\n                       d.memory_usage AS 'Memory Usage',d.uptime AS Uptime,d.snmp_status AS SNMP,d.api_status AS API,\n                       d.ssh_status AS SSH,d.last_seen AS 'Last Seen',d.scan_status AS Status\n                FROM devices d WHERE %s ORDER BY d.city,d.ip_address\n            """ % " AND ".join(where),args)]\n            add_sheet(wb,"Devices",VIEW_HEADERS,rows)\n            wireless=[dict(r) for r in conn.execute("""\n                SELECT d.ip_address AS IP,d.city AS City,d.vendor AS Vendor,d.device_type AS Type,d.hostname AS Hostname,\n                       d.model AS Model,d.ssid AS SSID,d.frequency AS Frequency,d.channel AS Channel,d.bandwidth AS Bandwidth,\n                       d.mode AS Mode,d.radio_name AS Radio,d.interface_name AS Interface,d.tx_power AS 'TX Power',\n                       d.rx_power AS 'RX Power',d.signal_strength AS Signal,d.peer_tx_signal AS 'Peer TX Signal',\n                       d.tx_rate AS 'TX Rate',d.rx_rate AS 'RX Rate',d.ccq AS CCQ,d.tx_ccq AS 'TX CCQ',d.rx_ccq AS 'RX CCQ',\n                       d.snr AS SNR,d.noise_floor AS 'Noise Floor',d.scan_status AS Status,d.last_seen AS 'Last Seen'\n                FROM devices d WHERE %s ORDER BY d.city,d.ip_address\n            """ % " AND ".join(where),args)]\n            add_sheet(wb,"Wireless",["IP","City","Vendor","Type","Hostname","Model","SSID","Frequency","Channel","Bandwidth","Mode","Radio","Interface","TX Power","RX Power","Signal","Peer TX Signal","TX Rate","RX Rate","CCQ","TX CCQ","RX CCQ","SNR","Noise Floor","Status","Last Seen"],wireless)\n'''
        c=repl_once(c,anchor,view+anchor,"Excel view full mode")

    # Antenna import in import_excel().
    if 'if mode=="antenna":' not in c[c.find("def import_excel"):c.find("def template_excel")]:
        anchor='''        try:\n            if mode=="blacklist":\n'''
        block='''        try:\n            if mode=="antenna":\n                aliases={"ip":"ip","ip address":"ip","scan city":"scan_city","latitude":"latitude","longitude":"longitude","province":"province","city":"city","antenna gain":"antenna_gain","gain":"antenna_gain","polarization":"polarization","capacity":"capacity"}\n                mp={aliases.get(h,h):i for h,i in pos.items()}\n                if "ip" not in mp: raise ValueError("ستون IP در Excel وجود ندارد")\n                mapping={"latitude":"manual_latitude","longitude":"manual_longitude","province":"manual_province","city":"manual_city","antenna_gain":"manual_antenna_gain","polarization":"manual_polarization","capacity":"manual_capacity"}\n                count=0;not_found=[]\n                for row in ws.iter_rows(min_row=2,values_only=True):\n                    ip=text(row[mp["ip"]]).strip()\n                    if not ip: continue\n                    ip=str(ipaddress.ip_address(ip))\n                    if not conn.execute("SELECT 1 FROM devices WHERE ip_address=?",(ip,)).fetchone():\n                        not_found.append(ip);continue\n                    sets=[];args=[]\n                    for eff,man in mapping.items():\n                        if eff in mp and row[mp[eff]] not in (None,""):\n                            value=text(row[mp[eff]])\n                            sets += [f"{man}=?",f"{eff}=?"];args += [value,value]\n                    if sets:\n                        sets.append("last_updated=?");args += [datetime.now().strftime("%Y-%m-%d %H:%M:%S"),ip]\n                        conn.execute(f"UPDATE devices SET {','.join(sets)} WHERE ip_address=?",args);count+=1\n                conn.commit();return {"status":"ok","updated":count,"not_found":len(not_found),"not_found_ips":not_found}\n\n'''
        c=repl_once(c,anchor,block+anchor,"Excel antenna import")

    backup(p);p.write_text(c,encoding="utf-8")


def patch_app() -> None:
    p=ROOT/"app.py";c=p.read_text(encoding="utf-8")

    if '@app.get("/api/excel/view-full")' not in c:
        anchor='@app.get("/api/excel/export")\n'
        endpoint='''@app.get("/api/excel/view-full")\n@auth\ndef excel_view_full():\n    hours=request.args.get("hours","all")\n    try: hours=None if hours=="all" else int(hours)\n    except: hours=None\n    data=export_excel(DB_PATH,hours=hours,mode="view_full")\n    return send_file(data,as_attachment=True,download_name=f"wireless_monitor_view_{hours or 'all'}h.xlsx",mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")\n\n'''
        c=repl_once(c,anchor,endpoint+anchor,"app view export")

    if '@app.get("/api/excel/antenna")' not in c:
        anchor='@app.get("/api/excel/wireless")\n'
        if anchor not in c: anchor='@app.get("/api/excel/export")\n'
        endpoint='''@app.get("/api/excel/antenna")\n@auth\n@full\ndef excel_antenna_export():\n    city_id=request.args.get("city_id")\n    try: city_id=int(city_id) if city_id not in (None,"") else None\n    except: city_id=None\n    data=export_excel(DB_PATH,mode="antenna",city_id=city_id)\n    suffix=f"city_{city_id}" if city_id is not None else "all_cities"\n    return send_file(data,as_attachment=True,download_name=f"antenna_{suffix}.xlsx",mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")\n\n@app.post("/api/excel/antenna")\n@auth\n@full\ndef excel_antenna_import():\n    f=request.files.get("file")\n    if not f:return jsonify(error="file_required"),400\n    try:return jsonify(import_excel(f.stream,DB_PATH,"antenna"))\n    except Exception as e:return jsonify(error="antenna_excel_failed",message=str(e)),400\n\n'''
        c=repl_once(c,anchor,endpoint+anchor,"app antenna endpoints")

    # Manual IP POST accepts city_id. 
    old='''def mi_add():\n    x=request.get_json(silent=True) or {}\n    try:return jsonify(db.add_manual_ip(x.get("ip_address","").strip(),x.get("description","").strip())),201\n    except Exception as e:return jsonify(error="invalid_ip",message=str(e)),400\n'''
    new='''def mi_add():\n    x=request.get_json(silent=True) or {}\n    try:return jsonify(db.add_manual_ip(x.get("ip_address","").strip(),x.get("description","").strip(),x.get("city_id"))),201\n    except Exception as e:return jsonify(error="invalid_ip",message=str(e)),400\n'''
    c=repl_if(c,old,new,"app manual IP city")

    # /api/cities returns stats too, so every caller sees the same numbers.
    start=c.find('@app.get("/api/cities")')
    end=c.find('\n@app.post("/api/cities")',start)
    if start>=0 and end>=0:
        route='''@app.get("/api/cities")\n@auth\ndef cities():\n    rows=db.list_cities();stats={str(x["id"]):x for x in db.get_city_counts()}\n    for row in rows:\n        row.update(stats.get(str(row["id"]),{"total":0,"online":0}))\n    return jsonify(rows)\n'''
        c=c[:start]+route+c[end:]

    backup(p);p.write_text(c,encoding="utf-8")


def patch_index() -> None:
    p=ROOT/"index.html";c=p.read_text(encoding="utf-8")

    # View Excel tab for all roles.
    if 'function nav(){' in c and 'openViewExcel' not in c:
        m=re.search(r"function nav\(\)\{.*?\n",c)
        if m:
            old=m.group(0)
            # Simpler exact replacement of the nav function used by this project.
            known='''function nav(){return `<div class="card"><div class="top-actions"><button class="btn" onclick="loadHome()">🏠 داشبورد</button>${ME.role==='full'?`<button class="btn" onclick="openAdmin()">⚙ مدیریت</button><button class="btn" onclick="openScanIPs(lastScanId)">📋 IPهای اسکن شده</button>`:''}<button class="btn" onclick="loadHome()">🔄 بروزرسانی</button><button class="btn danger" onclick="logout()">خروج</button></div></div>`}\n'''
            newer='''function nav(){return `<div class="card"><div class="top-actions"><button class="btn" onclick="loadHome()">🏠 داشبورد</button><button class="btn" onclick="openViewExcel()">📊 Excel</button>${ME.role==='full'?`<button class="btn" onclick="openAdmin()">⚙ مدیریت</button><button class="btn" onclick="openScanIPs(lastScanId)">📋 IPهای اسکن شده</button>`:''}<button class="btn" onclick="loadHome()">🔄 بروزرسانی</button><button class="btn danger" onclick="logout()">خروج</button></div></div>`}\n'''
            if known in c:c=c.replace(known,newer,1)

    if 'async function openViewExcel()' not in c:
        anchor='function openAdmin(){'
        fn='''async function openViewExcel(){app.innerHTML=nav()+`<div class="card"><h2>📊 خروجی Excel</h2><div class="notice">این خروجی شامل اطلاعات قابل مشاهده برای کاربر فعلی است و شامل رمزها یا تنظیمات مدیریتی نیست.</div><div class="toolbar"><select id="viewFullHours"><option value="12">۱۲ ساعت</option><option value="24" selected>۲۴ ساعت</option><option value="36">۳۶ ساعت</option><option value="all">همه</option></select><button class="btn primary" onclick="downloadViewFullExcel()">📥 دریافت Full Excel</button></div></div>`}\nasync function downloadViewFullExcel(){const hours=$('viewFullHours')?.value||'all';await fileDownload('/api/excel/view-full?hours='+encodeURIComponent(hours),'wireless_monitor_view_'+hours+'h.xlsx')}\n'''
        if anchor in c:c=c.replace(anchor,fn+anchor,1)

    # City stats merge in case /api/cities from an old running container lacks stats.
    if 'const cityStats=new Map' not in c:
        old='lastScanId=st.last_scan?.id||null;app.innerHTML=nav()+'
        if old in c:
            c=c.replace(old,"lastScanId=st.last_scan?.id||null;cities=cities.map(c=>Object.assign({},c,(st.cities||[]).find(x=>String(x.id)===String(c.id))||{}));app.innerHTML=nav()+'",1)

    # Device table IP column.
    if '<th>IP</th><th>نام</th><th>Type</th>' not in c:
        c=c.replace('<th>نام</th><th>Type</th><th>SSID</th>', '<th>IP</th><th>نام</th><th>Type</th><th>SSID</th>',1)
        old='''<tr><td class="link ltr" onclick="detail('${encodeURIComponent(d.ip_address)}')">${h(d.hostname||d.ip_address)}</td><td>${h(d.device_type)}</td>'''
        new='''<tr><td class="ltr">${h(d.ip_address)}</td><td class="link ltr" onclick="detail('${encodeURIComponent(d.ip_address)}')">${h(d.hostname||d.ip_address)}</td><td>${h(d.device_type)}</td>'''
        if old in c:c=c.replace(old,new,1)

    # Province statistics section.
    if '🏞 آمار استان‌ها' not in c:
        anchor='<div class="card"><div class="section-title"><h3>🏙 شهرها</h3>'
        section='''<div class="card"><div class="section-title"><h3>🏞 آمار استان‌ها</h3><span class="muted">تعداد آنتن‌های ثبت‌شده و آنلاین</span></div><div class="grid">${(st.provinces||[]).map(p=>`<div class="card"><h3>${h(p.province||'نامشخص')}</h3><div>کل آنتن: <b>${p.total||0}</b> &nbsp; آنلاین: <b class="ok">${p.online||0}</b></div></div>`).join('')}</div></div>'''
        if anchor in c:c=c.replace(anchor,section+anchor,1)

    # Admin tabs: manual IP + antenna Excel.
    if "adminTab('manualips'" not in c:
        anchor='''<button class="tab" onclick="adminTab('radios',this)">رادیو دستی</button>'''
        ins=anchor+'''<button class="tab" onclick="adminTab('manualips',this)">IPهای دستی</button><button class="tab" onclick="adminTab('antenna',this)">اطلاعات آنتن</button>'''
        if anchor in c:c=c.replace(anchor,ins,1)

        anchor='function cityForm(){'
        funcs='''async function loadManualIpsAdmin(){const [ips,cities]=await Promise.all([api('/api/manual-ips'),api('/api/cities')]);const opts=cities.filter(c=>c.enabled).map(c=>`<option value="${c.id}">${h(c.name)} — ${h(c.cidr)}</option>`).join('');$('adminBody').innerHTML=`<div class="notice">IP دستی را با شهر مربوط ثبت کنید تا از تنظیمات همان شهر برای SNMP/SSH/API استفاده شود.</div><div class="form-grid"><input id="mip" placeholder="IP مثلا 172.17.240.157"><input id="mid" placeholder="توضیح"><select id="mic">${opts}</select><button class="btn primary" onclick="addManualIpAdmin()">افزودن IP</button></div><div class="table"><table><tr><th>IP</th><th>شهر</th><th>توضیح</th><th>وضعیت</th><th>عملیات</th></tr>${ips.map(x=>`<tr><td class="ltr">${h(x.ip_address)}</td><td>${h(x.city_name||'Manual')}</td><td>${h(x.description)}</td><td>${h(x.enabled?'فعال':'غیرفعال')}</td><td><button class="btn danger" onclick="delManualIpAdmin(${x.id})">حذف</button></td></tr>`).join('')}</table></div>`}\nasync function addManualIpAdmin(){try{await api('/api/manual-ips',{method:'POST',body:JSON.stringify({ip_address:$('mip').value,description:$('mid').value,city_id:$('mic').value})});adminTab('manualips',document.querySelector('.tab'))}catch(e){alert(e.message)}}\nasync function delManualIpAdmin(id){await api('/api/manual-ips/'+id,{method:'DELETE'});adminTab('manualips',document.querySelector('.tab'))}\nasync function loadAntennaAdmin(){const cities=await api('/api/cities');const opts=cities.filter(c=>c.enabled).map(c=>`<option value="${c.id}">${h(c.name)} — ${h(c.cidr)}</option>`).join('');$('adminBody').innerHTML=`<div class="notice">شهر را انتخاب کنید، Excel شامل IPهای همان شهر را بگیرید، ستون‌های اطلاعات آنتن را پر کنید و سپس دوباره وارد کنید.</div><div class="toolbar"><select id="antCity">${opts}</select><button class="btn" onclick="exportAntennaAdmin()">📤 خروجی IPهای شهر</button><label class="btn">📥 ورود Excel<input id="antFile" type="file" accept=".xlsx,.xlsm" hidden onchange="importAntennaAdmin(this)"></label></div><div class="notice" style="margin-top:10px"><b>ستون‌ها:</b> IP | Scan City | Latitude | Longitude | Province | City | Antenna Gain | Polarization | Capacity</div>`}\nasync function exportAntennaAdmin(){const city=$('antCity')?.value||'';await fileDownload('/api/excel/antenna?city_id='+encodeURIComponent(city),'antenna_city_'+city+'.xlsx')}\nasync function importAntennaAdmin(i){if(!i.files[0])return;const fd=new FormData();fd.append('file',i.files[0]);const r=await fetch(API+'/api/excel/antenna',{method:'POST',headers:{Authorization:AUTH},body:fd});let j={};try{j=await r.json()}catch{}if(!r.ok)throw new Error(j.message||j.error||'Excel import failed');alert('اطلاعات آنتن وارد شد ✅');adminTab('antenna',document.querySelector('.tab'))}\n\n'''
        if anchor in c:c=c.replace(anchor,funcs+anchor,1)
        anchor="if(name==='backup'){"
        branches="if(name==='manualips'){await loadManualIpsAdmin()}if(name==='antenna'){await loadAntennaAdmin()}"
        if anchor in c:c=c.replace(anchor,branches+anchor,1)

    # Antenna tab in device detail for Full users.
    if "['antenna','اطلاعات آنتن']" not in c:
        old="const tabs=ME.role==='full'?[['general','اصلی'],['wireless','Wireless'],"
        new="const tabs=ME.role==='full'?[['general','اصلی'],['wireless','Wireless'],['antenna','اطلاعات آنتن'],"
        if old in c:c=c.replace(old,new,1)
    if "if(name==='antenna'){rows=" not in c:
        marker="if(name==='general')rows="
        m=re.search(r"(if\(name==='general'\)rows=.*?;)",c)
        if m:
            branch="if(name==='antenna'){rows=[['Latitude',d.manual_latitude||d.latitude],['Longitude',d.manual_longitude||d.longitude],['Province',d.manual_province||d.province],['City',d.manual_city],['Antenna Gain',d.manual_antenna_gain||d.antenna_gain],['Polarization',d.manual_polarization||d.polarization],['Capacity',d.manual_capacity||d.capacity]]}"
            c=c[:m.end()]+branch+c[m.end():]

    backup(p);p.write_text(c,encoding="utf-8")


def main() -> None:
    for name in ["scanner.py","database.py","excel_manager.py","app.py","index.html","Dockerfile"]:
        if not (ROOT/name).exists():
            raise SystemExit(f"Missing required file: {name}")
    patch_database()
    patch_scanner()
    patch_excel()
    patch_app()
    patch_index()
    patch_dockerfile()
    r=subprocess.run(["python3","-m","py_compile","scanner.py","routeros_api.py","database.py","excel_manager.py","app.py"],cwd=ROOT,text=True,capture_output=True)
    if r.returncode:
        print(r.stdout);print(r.stderr)
        raise SystemExit("Syntax validation failed")
    print("PHASE-3 FIX APPLIED SUCCESSFULLY")
    print("Backups: *.phase3.bak")
    print("Python syntax: OK")
    print("Next:")
    print("  git diff --check")
    print("  git diff --stat")
    print("  docker compose down")
    print("  docker compose build --no-cache")
    print("  docker compose up -d")
    print("  docker logs --tail 200 wireless-monitor")

if __name__ == "__main__":
    main()
