#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Repair excel_manager.py after a malformed phase-3 patch.
Restores the phase-3 backup, then reapplies the Excel additions cleanly.
Preserves the pre-phase3 file (including phase2 changes).
"""
from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGET = ROOT / "excel_manager.py"
BACKUP = ROOT / "excel_manager.py.phase3.bak"


def once(c: str, old: str, new: str, label: str) -> str:
    n = c.count(old)
    if n != 1:
        raise RuntimeError(f"{label}: expected 1 match, found {n}")
    return c.replace(old, new, 1)


def add_headers(c: str) -> str:
    if "ANTENNA_HEADERS=" not in c:
        anchor = "RADIO_HEADERS="
        pos = c.find(anchor)
        if pos < 0:
            raise RuntimeError("RADIO_HEADERS anchor missing")
        end = c.find("\n", pos)
        extra = (
            'ANTENNA_HEADERS=["IP","Scan City","Latitude","Longitude","Province","City","Antenna Gain","Polarization","Capacity"]\n'
            'VIEW_HEADERS=["IP","City","Vendor","Type","Hostname","Model","RouterOS Version","Firmware","MAC","SSID","Frequency","Channel","Bandwidth","Mode","Radio","Interface","TX Power","RX Power","Signal","Peer TX Signal","TX Rate","RX Rate","CCQ","TX CCQ","RX CCQ","SNR","Noise Floor","Temperature","CPU Load","Memory Usage","Uptime","SNMP","API","SSH","Last Seen","Status"]\n'
        )
        c = c[:end+1] + extra + c[end+1:]
    return c


def fix_signature(c: str) -> str:
    old = 'def export_excel(db_path, hours=None, mode="full"):'
    if old in c:
        c = once(c, old, 'def export_excel(db_path, hours=None, mode="full", city_id=None, ip_address=None):', "export_excel signature")
    return c


def add_export_modes(c: str) -> str:
    # Add antenna branch immediately before an existing wireless/radios branch.
    if 'elif mode=="antenna":' not in c:
        anchor = '        elif mode=="wireless":\n'
        if anchor not in c:
            anchor = '        elif mode=="radios":\n'
        if anchor not in c:
            raise RuntimeError("export branch anchor missing")
        block = '''        elif mode=="antenna":
            where=["NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)"]
            args=[]
            if city_id is not None:
                where.append("d.city_id=?");args.append(int(city_id))
            if ip_address:
                where.append("d.ip_address=?");args.append(str(ip_address))
            rows=[dict(r) for r in conn.execute("""
                SELECT d.ip_address AS IP,d.city AS 'Scan City',
                       COALESCE(NULLIF(d.manual_latitude,''),d.latitude,'') AS Latitude,
                       COALESCE(NULLIF(d.manual_longitude,''),d.longitude,'') AS Longitude,
                       COALESCE(NULLIF(d.manual_province,''),d.province,'') AS Province,
                       COALESCE(d.manual_city,'') AS City,
                       COALESCE(NULLIF(d.manual_antenna_gain,''),d.antenna_gain,'') AS 'Antenna Gain',
                       COALESCE(NULLIF(d.manual_polarization,''),d.polarization,'') AS Polarization,
                       COALESCE(NULLIF(d.manual_capacity,''),d.capacity,'') AS Capacity
                FROM devices d WHERE %s ORDER BY d.city,d.ip_address
            """ % " AND ".join(where),args)]
            add_sheet(wb,"Antenna",ANTENNA_HEADERS,rows)
'''
        c = once(c, anchor, block + anchor, "antenna export branch")

    if 'elif mode=="view_full":' not in c:
        anchor = '        else:\n            device_rows='
        if anchor not in c:
            raise RuntimeError("final export else anchor missing")
        block = '''        elif mode=="view_full":
            where=["d.scan_status='success'","NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)"]
            args=[]
            if hours is not None and int(hours)>0:
                cutoff=(datetime.now()-timedelta(hours=int(hours))).strftime("%Y-%m-%d %H:%M:%S")
                where.append("d.last_seen>=?");args.append(cutoff)
            rows=[dict(r) for r in conn.execute("""
                SELECT d.ip_address AS IP,d.city AS City,d.vendor AS Vendor,d.device_type AS Type,d.hostname AS Hostname,
                       d.model AS Model,d.routeros_version AS 'RouterOS Version',d.firmware_version AS Firmware,
                       d.mac_address AS MAC,d.ssid AS SSID,d.frequency AS Frequency,d.channel AS Channel,d.bandwidth AS Bandwidth,
                       d.mode AS Mode,d.radio_name AS Radio,d.interface_name AS Interface,d.tx_power AS 'TX Power',
                       d.rx_power AS 'RX Power',d.signal_strength AS Signal,d.peer_tx_signal AS 'Peer TX Signal',
                       d.tx_rate AS 'TX Rate',d.rx_rate AS 'RX Rate',d.ccq AS CCQ,d.tx_ccq AS 'TX CCQ',d.rx_ccq AS 'RX CCQ',
                       d.snr AS SNR,d.noise_floor AS 'Noise Floor',d.temperature AS Temperature,d.cpu_load AS 'CPU Load',
                       d.memory_usage AS 'Memory Usage',d.uptime AS Uptime,d.snmp_status AS SNMP,d.api_status AS API,
                       d.ssh_status AS SSH,d.last_seen AS 'Last Seen',d.scan_status AS Status
                FROM devices d WHERE %s ORDER BY d.city,d.ip_address
            """ % " AND ".join(where),args)]
            add_sheet(wb,"Devices",VIEW_HEADERS,rows)
            wireless=[dict(r) for r in conn.execute("""
                SELECT d.ip_address AS IP,d.city AS City,d.vendor AS Vendor,d.device_type AS Type,d.hostname AS Hostname,
                       d.model AS Model,d.ssid AS SSID,d.frequency AS Frequency,d.channel AS Channel,d.bandwidth AS Bandwidth,
                       d.mode AS Mode,d.radio_name AS Radio,d.interface_name AS Interface,d.tx_power AS 'TX Power',
                       d.rx_power AS 'RX Power',d.signal_strength AS Signal,d.peer_tx_signal AS 'Peer TX Signal',
                       d.tx_rate AS 'TX Rate',d.rx_rate AS 'RX Rate',d.ccq AS CCQ,d.tx_ccq AS 'TX CCQ',d.rx_ccq AS 'RX CCQ',
                       d.snr AS SNR,d.noise_floor AS 'Noise Floor',d.scan_status AS Status,d.last_seen AS 'Last Seen'
                FROM devices d WHERE %s ORDER BY d.city,d.ip_address
            """ % " AND ".join(where),args)]
            add_sheet(wb,"Wireless",["IP","City","Vendor","Type","Hostname","Model","SSID","Frequency","Channel","Bandwidth","Mode","Radio","Interface","TX Power","RX Power","Signal","Peer TX Signal","TX Rate","RX Rate","CCQ","TX CCQ","RX CCQ","SNR","Noise Floor","Status","Last Seen"],wireless)
'''
        c = once(c, anchor, block + anchor, "view full export branch")
    return c


def add_antenna_import(c: str) -> str:
    section_start = c.find("def import_excel")
    section_end = c.find("\ndef template_excel", section_start)
    if section_start < 0 or section_end < 0:
        raise RuntimeError("import_excel section not found")
    section = c[section_start:section_end]
    if 'if mode=="antenna":' in section:
        return c
    anchor = '''            if mode=="blacklist":\n'''
    if anchor not in section:
        raise RuntimeError("import_excel blacklist anchor missing")
    block = '''            if mode=="antenna":
                aliases={"ip":"ip","ip address":"ip","scan city":"scan_city","latitude":"latitude","longitude":"longitude","province":"province","city":"city","antenna gain":"antenna_gain","gain":"antenna_gain","polarization":"polarization","capacity":"capacity"}
                mp={aliases.get(h,h):i for h,i in pos.items()}
                if "ip" not in mp: raise ValueError("ستون IP در Excel وجود ندارد")
                mapping={"latitude":"manual_latitude","longitude":"manual_longitude","province":"manual_province","city":"manual_city","antenna_gain":"manual_antenna_gain","polarization":"manual_polarization","capacity":"manual_capacity"}
                count=0;not_found=[]
                for row in ws.iter_rows(min_row=2,values_only=True):
                    ip=text(row[mp["ip"]]).strip()
                    if not ip: continue
                    ip=str(ipaddress.ip_address(ip))
                    if not conn.execute("SELECT 1 FROM devices WHERE ip_address=?",(ip,)).fetchone():
                        not_found.append(ip);continue
                    sets=[];args=[]
                    for eff,man in mapping.items():
                        if eff in mp and row[mp[eff]] not in (None,""):
                            value=text(row[mp[eff]])
                            sets += [f"{man}=?",f"{eff}=?"];args += [value,value]
                    if sets:
                        sets.append("last_updated=?");args += [datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
                        args.append(ip)
                        conn.execute(f"UPDATE devices SET {','.join(sets)} WHERE ip_address=?",args);count+=1
                conn.commit();return {"status":"ok","updated":count,"not_found":len(not_found),"not_found_ips":not_found}
'''
    new_section = section.replace(anchor, block + anchor, 1)
    return c[:section_start] + new_section + c[section_end:]


def main() -> None:
    if not TARGET.exists():
        raise SystemExit(f"Missing: {TARGET}")
    if not BACKUP.exists():
        raise SystemExit(f"Missing backup: {BACKUP} -- do not run destructive repair without the phase3 backup")

    # Preserve the current broken file for investigation before restore.
    broken = TARGET.with_suffix(TARGET.suffix + ".broken.bak")
    if not broken.exists():
        shutil.copy2(TARGET, broken)

    shutil.copy2(BACKUP, TARGET)
    c = TARGET.read_text(encoding="utf-8")
    c = add_headers(c)
    c = fix_signature(c)
    c = add_export_modes(c)
    c = add_antenna_import(c)
    TARGET.write_text(c, encoding="utf-8")

    import py_compile
    py_compile.compile(str(TARGET), doraise=True)
    print("EXCEL MANAGER REPAIRED SUCCESSFULLY")
    print(f"Restored from: {BACKUP.name}")
    print(f"Broken copy kept as: {broken.name}")
    print("Python syntax: OK")
    print("Run next:")
    print("  python3 -m py_compile scanner.py routeros_api.py database.py excel_manager.py app.py")
    print("  git diff --check")
    print("  git diff --stat")


if __name__ == "__main__":
    main()
