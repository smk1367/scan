#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

DB_PATH = os.getenv("DB_PATH", "/app/data/data.db")
TZ = ZoneInfo("Asia/Tehran")

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    city_id INTEGER,
    city TEXT,
    device_type TEXT,
    vendor TEXT,
    hostname TEXT,
    model TEXT,
    routeros_version TEXT,
    firmware_version TEXT,
    serial_number TEXT,
    mac_address TEXT,
    ssid TEXT,
    frequency TEXT,
    channel TEXT,
    bandwidth TEXT,
    mode TEXT,
    radio_name TEXT,
    wireless_status TEXT,
    tx_power TEXT,
    rx_power TEXT,
    signal_strength TEXT,
    peer_tx_signal TEXT,
    tx_rate TEXT,
    rx_rate TEXT,
    ccq TEXT,
    tx_ccq TEXT,
    rx_ccq TEXT,
    snr TEXT,
    noise_floor TEXT,
    temperature TEXT,
    cpu_load TEXT,
    memory_usage TEXT,
    uptime TEXT,
    interfaces TEXT,
    wireless_registration TEXT,
    queues TEXT,
    firewall_counters TEXT,
    pppoe_vpn TEXT,
    ip_routes TEXT,
    bridges TEXT,
    raw_data TEXT,
    snmp_status TEXT,
    api_status TEXT,
    ssh_status TEXT,
    credential_id TEXT,
    last_seen TEXT,
    last_updated TEXT,
    scan_status TEXT DEFAULT 'unknown',
    manual_latitude TEXT DEFAULT '',
    manual_longitude TEXT DEFAULT '',
    manual_province TEXT DEFAULT '',
    manual_city TEXT DEFAULT '',
    manual_antenna_gain TEXT DEFAULT '',
    manual_polarization TEXT DEFAULT '',
    manual_capacity TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS cities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    cidr TEXT NOT NULL,
    description TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    ssh_port INTEGER DEFAULT 22,
    snmp_port INTEGER DEFAULT 161,
    api_port INTEGER DEFAULT 8728,
    api_enabled INTEGER DEFAULT 1,
    api_ssl_enabled INTEGER DEFAULT 0,
    api_timeout REAL DEFAULT 4,
    snmp_timeout REAL DEFAULT 2.5,
    snmp_retries INTEGER DEFAULT 1,
    ssh_timeout REAL DEFAULT 6,
    ssh_credentials_json TEXT DEFAULT '[]',
    snmp_communities_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time TEXT NOT NULL,
    started_by TEXT,
    selection_json TEXT,
    total_ips_scanned INTEGER DEFAULT 0,
    devices_found INTEGER DEFAULT 0,
    devices_success INTEGER DEFAULT 0,
    devices_failed INTEGER DEFAULT 0,
    devices_skipped INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    device_id INTEGER,
    city_id INTEGER,
    city_name TEXT,
    status TEXT,
    stage TEXT,
    reason TEXT,
    snapshot_json TEXT,
    scanned_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scan_logs(id) ON DELETE CASCADE,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip_address);

CREATE TABLE IF NOT EXISTS device_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    field_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scan_logs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_changes_ip ON device_changes(ip_address, changed_at);

CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manual_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manual_radios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    name TEXT DEFAULT '', model TEXT DEFAULT '', vendor TEXT DEFAULT '',
    serial_number TEXT DEFAULT '', ssid TEXT DEFAULT '', frequency TEXT DEFAULT '',
    channel TEXT DEFAULT '', bandwidth TEXT DEFAULT '', mode TEXT DEFAULT '', radio_name TEXT DEFAULT '',
    tx_power TEXT DEFAULT '', rx_power TEXT DEFAULT '', signal_strength TEXT DEFAULT '',
    peer_tx_signal TEXT DEFAULT '', tx_rate TEXT DEFAULT '', rx_rate TEXT DEFAULT '',
    ccq TEXT DEFAULT '', snr TEXT DEFAULT '', noise_floor TEXT DEFAULT '', notes TEXT DEFAULT '',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'view',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

TRACKED_FIELDS = (
    "city_id", "device_type", "hostname", "model", "routeros_version", "ssid", "frequency",
    "channel", "bandwidth", "mode", "radio_name", "wireless_status", "tx_power", "rx_power",
    "signal_strength", "peer_tx_signal", "tx_rate", "rx_rate", "ccq", "tx_ccq", "rx_ccq", "snr",
    "noise_floor", "temperature", "cpu_load", "memory_usage", "uptime", "scan_status"
)


def now() -> str:
    return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")


def connect() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=60)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=60000")
    return c


def _ensure_columns(c: sqlite3.Connection, table: str, wanted: dict[str, str]) -> None:
    have = {r[1] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, typ in wanted.items():
        if name not in have:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ}")


def init_db() -> None:
    c = connect()
    try:
        c.executescript(SCHEMA)
        _ensure_columns(c, "devices", {name: "TEXT" for name in (
            "city_id", "city", "device_type", "vendor", "hostname", "model", "routeros_version",
            "firmware_version", "serial_number", "mac_address", "ssid", "frequency", "channel",
            "bandwidth", "mode", "radio_name", "wireless_status", "tx_power", "rx_power",
            "signal_strength", "peer_tx_signal", "tx_rate", "rx_rate", "ccq", "tx_ccq", "rx_ccq",
            "snr", "noise_floor", "temperature", "cpu_load", "memory_usage", "uptime", "interfaces",
            "wireless_registration", "queues", "firewall_counters", "pppoe_vpn", "ip_routes", "bridges",
            "raw_data", "snmp_status", "api_status", "ssh_status", "credential_id", "last_seen",
            "last_updated", "scan_status", "latitude", "longitude", "province", "antenna_gain",
            "polarization", "capacity", "manual_latitude", "manual_longitude", "manual_province",
            "manual_city", "manual_antenna_gain", "manual_polarization", "manual_capacity"
        )})
        _ensure_columns(c, "cities", {
            "ssh_port": "INTEGER DEFAULT 22", "snmp_port": "INTEGER DEFAULT 161", "api_port": "INTEGER DEFAULT 8728",
            "api_enabled": "INTEGER DEFAULT 1", "api_ssl_enabled": "INTEGER DEFAULT 0", "api_timeout": "REAL DEFAULT 4",
            "snmp_timeout": "REAL DEFAULT 2.5", "snmp_retries": "INTEGER DEFAULT 1", "ssh_timeout": "REAL DEFAULT 6",
            "ssh_credentials_json": "TEXT DEFAULT '[]'", "snmp_communities_json": "TEXT DEFAULT '[]'"
        })
        if not c.execute("SELECT 1 FROM app_settings WHERE key='retention_hours'").fetchone():
            c.execute("INSERT INTO app_settings(key,value) VALUES('retention_hours',?)", (os.getenv("RETENTION_HOURS", "24"),))
        if not c.execute("SELECT 1 FROM app_settings WHERE key='backup_interval_hours'").fetchone():
            c.execute("INSERT INTO app_settings(key,value) VALUES('backup_interval_hours',?)", (os.getenv("BACKUP_INTERVAL_HOURS", "24"),))
        if not c.execute("SELECT 1 FROM cities LIMIT 1").fetchone():
            c.execute(
                """INSERT INTO cities(name,cidr,description,enabled,ssh_port,snmp_port,api_port,api_enabled,api_ssl_enabled,
                   api_timeout,snmp_timeout,snmp_retries,ssh_timeout,ssh_credentials_json,snmp_communities_json,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "شهر اول", os.getenv("SCAN_NETWORK", "172.17.240.0/20"), "شبکه پیش‌فرض پروژه", 1,
                    int(os.getenv("SSH_PORT", "22")), int(os.getenv("SNMP_PORT", "161")), int(os.getenv("API_PORT", "8728")),
                    1, 0, float(os.getenv("API_TIMEOUT", "4")), float(os.getenv("SNMP_TIMEOUT", "2.5")),
                    int(os.getenv("SNMP_RETRIES", "1")), float(os.getenv("SSH_TIMEOUT", "6")),
                    os.getenv("SSH_CREDENTIALS_JSON", "[]"), json.dumps([os.getenv("SNMP_COMMUNITY", "ngstehwl")]), now(), now()
                )
            )
        c.commit()
    finally:
        c.close()


def j(v: Any) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, default=str)
    return "" if v is None else str(v)


def get_device(ip: str) -> dict[str, Any] | None:
    init_db(); c = connect()
    try:
        r = c.execute("SELECT * FROM devices WHERE ip_address=?", (ip,)).fetchone()
        return dict(r) if r else None
    finally: c.close()


def get_devices(search: str = "", city_id: int | None = None, online_only: bool = False) -> list[dict[str, Any]]:
    init_db(); c = connect()
    try:
        where=["1=1"]; args=[]
        if online_only: where.append("d.scan_status='success'")
        if city_id is not None: where.append("d.city_id=?"); args.append(city_id)
        if search:
            q=f"%{search}%"; where.append("(d.ip_address LIKE ? OR d.hostname LIKE ? OR d.ssid LIKE ? OR d.model LIKE ? OR d.vendor LIKE ? OR d.device_type LIKE ?)"); args += [q]*6
        where.append("NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)")
        rows=c.execute(f"SELECT d.* FROM devices d WHERE {' AND '.join(where)} ORDER BY d.ip_address",args).fetchall()
        return [dict(r) for r in rows]
    finally:c.close()


def upsert_device(data: dict[str, Any]) -> dict[str, Any]:
    init_db(); ip=str(data.get("ip_address","")).strip()
    if not ip: raise ValueError("ip_address is required")
    c=connect()
    try:
        old=c.execute("SELECT * FROM devices WHERE ip_address=?",(ip,)).fetchone(); old=dict(old) if old else {}
        data=dict(data); data["last_updated"]=now()
        if data.get("scan_status")=="success":data["last_seen"]=data["last_updated"]
        protected={"latitude":"manual_latitude","longitude":"manual_longitude","province":"manual_province","city":"manual_city","antenna_gain":"manual_antenna_gain","polarization":"manual_polarization","capacity":"manual_capacity"}
        fields=[
            "ip_address","city_id","city","device_type","vendor","hostname","model","routeros_version","firmware_version","serial_number","mac_address",
            "ssid","frequency","channel","bandwidth","mode","radio_name","wireless_status","tx_power","rx_power","signal_strength","peer_tx_signal",
            "tx_rate","rx_rate","ccq","tx_ccq","rx_ccq","snr","noise_floor","temperature","cpu_load","memory_usage","uptime","interfaces",
            "wireless_registration","queues","firewall_counters","pppoe_vpn","ip_routes","bridges","raw_data","snmp_status","api_status","ssh_status",
            "credential_id","last_seen","last_updated","scan_status"
        ]
        vals=[j(data.get(f,"")) for f in fields]
        sql=f"INSERT INTO devices({','.join(fields)}) VALUES({','.join('?' for _ in fields)}) ON CONFLICT(ip_address) DO UPDATE SET "+','.join(f"{f}=excluded.{f}" for f in fields if f!='ip_address')
        c.execute(sql,vals)
        for eff,man in protected.items():
            oldv=old.get(man,"") or ""
            c.execute(f"UPDATE devices SET {man}=?, {eff}=? WHERE ip_address=?",(oldv,oldv if oldv else data.get(eff,""),ip))
        c.commit()
        return dict(c.execute("SELECT * FROM devices WHERE ip_address=?",(ip,)).fetchone())
    finally:c.close()


def create_scan(selection: dict[str,Any], started_by: str, total: int) -> int:
    c=connect()
    try:
        cur=c.execute("INSERT INTO scan_logs(scan_time,started_by,selection_json,total_ips_scanned) VALUES(?,?,?,?)",(now(),started_by,json.dumps(selection,ensure_ascii=False),total));c.commit();return int(cur.lastrowid)
    finally:c.close()


def add_scan_result(scan_id:int, result:dict[str,Any])->None:
    c=connect()
    try:
        d=c.execute("SELECT id FROM devices WHERE ip_address=?",(result["ip_address"],)).fetchone()
        c.execute("INSERT INTO scan_results(scan_id,ip_address,device_id,city_id,city_name,status,stage,reason,snapshot_json,scanned_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(
            scan_id,result["ip_address"],d[0] if d else None,result.get("city_id"),result.get("city_name"),result.get("status"),result.get("stage"),result.get("reason",""),j(result.get("snapshot",{})),now()))
        c.commit()
    finally:c.close()


def finish_scan(scan_id:int,stats:dict[str,int],duration:float)->None:
    c=connect();c.execute("UPDATE scan_logs SET devices_found=?,devices_success=?,devices_failed=?,devices_skipped=?,duration_seconds=? WHERE id=?",(stats["found"],stats["success"],stats["failed"],stats["skipped"],duration,scan_id));c.commit();c.close()


def record_changes(scan_id:int,ip:str,before:dict|None,after:dict|None)->None:
    if not after:return
    c=connect()
    try:
        for f in TRACKED_FIELDS:
            old=j((before or {}).get(f,""));new=j(after.get(f,""))
            if old!=new:c.execute("INSERT INTO device_changes(scan_id,ip_address,field_name,old_value,new_value,changed_at) VALUES(?,?,?,?,?,?)",(scan_id,ip,f,old,new,now()))
        c.commit()
    finally:c.close()


def get_scan_history(limit=200):
    c=connect(); rows=c.execute("SELECT * FROM scan_logs ORDER BY id DESC LIMIT ?",(max(1,min(int(limit),1000)),)).fetchall();c.close();return [dict(r) for r in rows]


def get_scan_detail(scan_id:int):
    c=connect()
    try:
        s=c.execute("SELECT * FROM scan_logs WHERE id=?",(scan_id,)).fetchone()
        if not s:return None
        rows=[dict(r) for r in c.execute("SELECT * FROM scan_results WHERE scan_id=? ORDER BY city_name,ip_address",(scan_id,)).fetchall()]
        changes=[dict(r) for r in c.execute("SELECT * FROM device_changes WHERE scan_id=? ORDER BY ip_address,field_name",(scan_id,)).fetchall()]
        for r in rows:
            try:r["snapshot"]=json.loads(r.get("snapshot_json") or "{}")
            except:r["snapshot"]={}
        return {"scan":dict(s),"results":rows,"changes":changes}
    finally:c.close()


def list_cities():
    c=connect(); rows=c.execute("SELECT * FROM cities ORDER BY name").fetchall();c.close();return [dict(r) for r in rows]

def add_city(x):
    from ipaddress import ip_network; ip_network(x["cidr"],strict=False);c=connect()
    try:
        ts=now();cur=c.execute("""INSERT INTO cities(name,cidr,description,enabled,ssh_port,snmp_port,api_port,api_enabled,api_ssl_enabled,api_timeout,snmp_timeout,snmp_retries,ssh_timeout,ssh_credentials_json,snmp_communities_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(
            x["name"].strip(),x["cidr"].strip(),x.get("description","").strip(),int(x.get("enabled",1)),int(x.get("ssh_port",22)),int(x.get("snmp_port",161)),int(x.get("api_port",8728)),int(x.get("api_enabled",1)),0,float(x.get("api_timeout",4)),float(x.get("snmp_timeout",2.5)),int(x.get("snmp_retries",1)),float(x.get("ssh_timeout",6)),json.dumps(x.get("ssh_credentials",[]),ensure_ascii=False),json.dumps(x.get("snmp_communities",[]),ensure_ascii=False),ts,ts));c.commit();return dict(c.execute("SELECT * FROM cities WHERE id=?",(cur.lastrowid,)).fetchone())
    finally:c.close()

def update_city(cid,x):
    from ipaddress import ip_network; ip_network(x["cidr"],strict=False);c=connect()
    try:
        c.execute("""UPDATE cities SET name=?,cidr=?,description=?,enabled=?,ssh_port=?,snmp_port=?,api_port=?,api_enabled=?,api_ssl_enabled=0,api_timeout=?,snmp_timeout=?,snmp_retries=?,ssh_timeout=?,ssh_credentials_json=?,snmp_communities_json=?,updated_at=? WHERE id=?""",(
            x["name"].strip(),x["cidr"].strip(),x.get("description","").strip(),int(x.get("enabled",1)),int(x.get("ssh_port",22)),int(x.get("snmp_port",161)),int(x.get("api_port",8728)),int(x.get("api_enabled",1)),float(x.get("api_timeout",4)),float(x.get("snmp_timeout",2.5)),int(x.get("snmp_retries",1)),float(x.get("ssh_timeout",6)),json.dumps(x.get("ssh_credentials",[]),ensure_ascii=False),json.dumps(x.get("snmp_communities",[]),ensure_ascii=False),now(),cid));c.commit();r=c.execute("SELECT * FROM cities WHERE id=?",(cid,)).fetchone();return dict(r) if r else None
    finally:c.close()

def delete_city(cid):
    c=connect();x=c.execute("DELETE FROM cities WHERE id=?",(cid,)).rowcount;c.commit();c.close();return bool(x)

def list_blacklist():
    c=connect();r=[dict(x) for x in c.execute("SELECT * FROM blacklist ORDER BY entry")];c.close();return r

def add_blacklist(entry,description=""):
    from ipaddress import ip_network;ip_network(entry,strict=False);c=connect()
    try:cur=c.execute("INSERT INTO blacklist(entry,description,created_at) VALUES(?,?,?)",(entry.strip(),description.strip(),now()));c.commit();return dict(c.execute("SELECT * FROM blacklist WHERE id=?",(cur.lastrowid,)).fetchone())
    finally:c.close()

def delete_blacklist(i):
    c=connect();n=c.execute("DELETE FROM blacklist WHERE id=?",(i,)).rowcount;c.commit();c.close();return bool(n)

def is_blacklisted(ip):
    from ipaddress import ip_address,ip_network
    obj=ip_address(ip)
    for r in list_blacklist():
        try:
            if obj in ip_network(r["entry"],strict=False):return True
        except:pass
    return False

def list_manual_ips():
    c=connect();r=[dict(x) for x in c.execute("SELECT * FROM manual_ips ORDER BY ip_address")];c.close();return r

def add_manual_ip(ip,description=""):
    from ipaddress import ip_address;ip_address(ip);c=connect()
    try:cur=c.execute("INSERT INTO manual_ips(ip_address,description,created_at) VALUES(?,?,?)",(ip.strip(),description.strip(),now()));c.commit();return dict(c.execute("SELECT * FROM manual_ips WHERE id=?",(cur.lastrowid,)).fetchone())
    finally:c.close()

def delete_manual_ip(i):
    c=connect();n=c.execute("DELETE FROM manual_ips WHERE id=?",(i,)).rowcount;c.commit();c.close();return bool(n)

def list_manual_radios():
    c=connect();r=[dict(x) for x in c.execute("SELECT * FROM manual_radios ORDER BY ip_address")];c.close();return r

def get_manual_radio(ip):
    c=connect();r=c.execute("SELECT * FROM manual_radios WHERE ip_address=?",(ip,)).fetchone();c.close();return dict(r) if r else None

def upsert_manual_radio(x):
    fields=["ip_address","name","model","vendor","serial_number","ssid","frequency","channel","bandwidth","mode","radio_name","tx_power","rx_power","signal_strength","peer_tx_signal","tx_rate","rx_rate","ccq","snr","noise_floor","notes"]
    vals=[str(x.get(f,"")).strip() for f in fields];ts=now();c=connect()
    try:
        sql=f"INSERT INTO manual_radios({','.join(fields)},created_at,updated_at) VALUES({','.join('?' for _ in fields)},?,?) ON CONFLICT(ip_address) DO UPDATE SET "+','.join(f"{f}=excluded.{f}" for f in fields if f!='ip_address')+",updated_at=excluded.updated_at"
        c.execute(sql,vals+[ts,ts]);c.commit();return dict(c.execute("SELECT * FROM manual_radios WHERE ip_address=?",(vals[0],)).fetchone())
    finally:c.close()

def delete_manual_radio(i):
    c=connect();n=c.execute("DELETE FROM manual_radios WHERE id=?",(i,)).rowcount;c.commit();c.close();return bool(n)

def update_manual(ip,v):
    c=connect();
    try:
        if not c.execute("SELECT 1 FROM devices WHERE ip_address=?",(ip,)).fetchone():return None
        mp={"latitude":"manual_latitude","longitude":"manual_longitude","province":"manual_province","city":"manual_city","antenna_gain":"manual_antenna_gain","polarization":"manual_polarization","capacity":"manual_capacity"};sets=[];args=[]
        for eff,man in mp.items():
            if eff in v:sets += [f"{man}=?",f"{eff}=?"];args += [str(v[eff]).strip(),str(v[eff]).strip()]
        if sets:sets.append("last_updated=?");args += [now(),ip];c.execute(f"UPDATE devices SET {','.join(sets)} WHERE ip_address=?",args);c.commit()
        return dict(c.execute("SELECT * FROM devices WHERE ip_address=?",(ip,)).fetchone())
    finally:c.close()

def get_changes(limit=1000):
    c=connect();r=[dict(x) for x in c.execute("SELECT * FROM device_changes ORDER BY changed_at DESC LIMIT ?",(max(1,min(int(limit),5000)),))];c.close();return r

def cleanup_retention(hours=None):
    h=int(hours or get_setting('retention_hours',os.getenv('RETENTION_HOURS','24')));cut=(datetime.now(TZ)-timedelta(hours=h)).strftime('%Y-%m-%d %H:%M:%S');c=connect()
    try:
        ids=[x[0] for x in c.execute('SELECT id FROM scan_logs WHERE scan_time<?',(cut,)).fetchall()]
        if ids:
            q=','.join('?'*len(ids));c.execute(f'DELETE FROM scan_results WHERE scan_id IN ({q})',ids);c.execute(f'DELETE FROM device_changes WHERE scan_id IN ({q})',ids);c.execute(f'DELETE FROM scan_logs WHERE id IN ({q})',ids)
        c.commit();return len(ids)
    finally:c.close()

def delete_history_before(before):
    c=connect();
    try:
        ids=[x[0] for x in c.execute('SELECT id FROM scan_logs WHERE scan_time<?',(before,)).fetchall()]
        if ids:
            q=','.join('?'*len(ids));c.execute(f'DELETE FROM scan_results WHERE scan_id IN ({q})',ids);c.execute(f'DELETE FROM device_changes WHERE scan_id IN ({q})',ids);c.execute(f'DELETE FROM scan_logs WHERE id IN ({q})',ids)
        c.commit();return len(ids)
    finally:c.close()

def get_setting(key,default=''):
    c=connect();r=c.execute('SELECT value FROM app_settings WHERE key=?',(key,)).fetchone();c.close();return r[0] if r else default

def set_setting(key,value):
    c=connect();c.execute('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(key,str(value)));c.commit();c.close()

def get_stats():
    c=connect()
    try:
        total=c.execute("SELECT COUNT(*) FROM devices d WHERE NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)").fetchone()[0]
        online=c.execute("SELECT COUNT(*) FROM devices d WHERE d.scan_status='success' AND NOT EXISTS(SELECT 1 FROM blacklist b WHERE b.enabled=1 AND b.entry=d.ip_address)").fetchone()[0]
        cities=[dict(x) for x in c.execute("SELECT c.id,c.name,c.cidr,COUNT(d.id) total,SUM(CASE WHEN d.scan_status='success' THEN 1 ELSE 0 END) online FROM cities c LEFT JOIN devices d ON d.city_id=c.id GROUP BY c.id ORDER BY c.name")]
        last=c.execute('SELECT * FROM scan_logs ORDER BY id DESC LIMIT 1').fetchone()
        return {'total_devices':total,'online_devices':online,'cities':cities,'last_scan':dict(last) if last else None}
    finally:c.close()

def list_users():
    c=connect();r=[dict(x) for x in c.execute('SELECT id,username,role,enabled,created_at FROM users ORDER BY username')];c.close();return r

def get_user(username):
    c=connect();r=c.execute('SELECT * FROM users WHERE username=? AND enabled=1',(username,)).fetchone();c.close();return dict(r) if r else None

def insert_user(username,password_hash,role):
    c=connect();cur=c.execute('INSERT INTO users(username,password_hash,role,created_at,enabled) VALUES(?,?,?,?,1)',(username,password_hash,role,now()));c.commit();r=dict(c.execute('SELECT id,username,role,enabled,created_at FROM users WHERE id=?',(cur.lastrowid,)).fetchone());c.close();return r

def delete_user(uid):
    c=connect();n=c.execute('DELETE FROM users WHERE id=?',(uid,)).rowcount;c.commit();c.close();return bool(n)
