#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multi-city SNMP + RouterOS API + SSH scanner.

Rules:
- Each city has its own CIDR, SSH/SNMP/API ports, SSH credentials and SNMP communities.
- RouterOS API is always plain TCP only (8728 by default). API-SSL is deliberately disabled.
- SNMP owns system/health/interfaces; RouterOS API owns wireless/topology; SSH is fallback.
- MikroTik wireless RX/TX fields are never simulated.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
from typing import Any

import paramiko

from database import (
    add_scan_result,
    cleanup_retention,
    create_scan,
    finish_scan,
    get_device,
    init_db,
    is_blacklisted,
    list_cities,
    list_manual_ips,
    record_changes,
    upsert_device,
)
from routeros_api import RouterOSAPI, collect_mikrotik_api

try:
    from pysnmp.hlapi.v1arch.asyncio import SnmpDispatcher, CommunityData, UdpTransportTarget, get_cmd
except Exception:
    SnmpDispatcher = CommunityData = UdpTransportTarget = get_cmd = None

LOG = logging.getLogger(__name__)

STANDARD_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2.1",
    "memTotalReal": "1.3.6.1.4.1.2021.4.5.0",
    "memAvailReal": "1.3.6.1.4.1.2021.4.6.0",
    "mtTemperature": "1.3.6.1.4.1.14988.1.1.3.10.0",
    "mtCpuTemperature": "1.3.6.1.4.1.14988.1.1.3.11.0",
}

IF_OIDS = {
    "name": "1.3.6.1.2.1.31.1.1.1.1",
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "oper": "1.3.6.1.2.1.2.2.1.8",
    "admin": "1.3.6.1.2.1.2.2.1.7",
    "in_octets": "1.3.6.1.2.1.31.1.1.1.6",
    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    "in_errors": "1.3.6.1.2.1.2.2.1.14",
    "out_errors": "1.3.6.1.2.1.2.2.1.20",
}


def s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def normdbm(v: Any) -> str:
    text = s(v)
    if not text:
        return ""
    m = re.search(r"-?\d+(?:\.\d+)?", text)
    return f"{m.group(0)} dBm" if m else text


def city_credentials(city: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    try:
        ssh = json.loads(city.get("ssh_credentials_json") or "[]")
    except Exception:
        ssh = []
    if not ssh:
        try:
            ssh = json.loads(os.getenv("SSH_CREDENTIALS_JSON", "[]") or "[]")
        except Exception:
            ssh = []
    if not ssh and os.getenv("SSH_USER", "").strip():
        ssh = [{"username": os.getenv("SSH_USER", ""), "password": os.getenv("SSH_PASS", ""), "id": "default"}]
    ssh_out = []
    for idx, item in enumerate(ssh, 1):
        if isinstance(item, dict) and s(item.get("username")):
            ssh_out.append({"username": s(item["username"]), "password": s(item.get("password", "")), "id": s(item.get("id")) or f"city-{idx}"})

    try:
        snmp = json.loads(city.get("snmp_communities_json") or "[]")
    except Exception:
        snmp = []
    communities = []
    for item in snmp:
        if isinstance(item, str) and item.strip():
            communities.append(item.strip())
        elif isinstance(item, dict) and s(item.get("community")):
            communities.append(s(item["community"]))
    if not communities:
        communities = [os.getenv("SNMP_COMMUNITY", "ngstehwl").strip() or "ngstehwl"]
    return ssh_out, list(dict.fromkeys(communities))


async def _snmp_get_async(ip: str, port: int, community: str, oids: list[str], timeout: float, retries: int) -> dict[str, str]:
    if not get_cmd or not SnmpDispatcher:
        return {}
    disp = SnmpDispatcher()
    try:
        target = await UdpTransportTarget.create((ip, port), timeout=float(timeout), retries=int(retries))
        res = await get_cmd(disp, CommunityData(community, mpModel=1), target, *[(oid, None) for oid in oids])
        err_indication, err_status, _, var_binds = res
        if err_indication or err_status:
            return {}
        return {s(oid): s(v.prettyPrint() if hasattr(v, "prettyPrint") else v) for oid, v in var_binds}
    except Exception:
        return {}
    finally:
        try:
            disp.close_dispatcher()
        except Exception:
            pass


def snmp_get(ip: str, city: dict[str, Any], oids: list[str]) -> tuple[dict[str, str], str]:
    for community in city_credentials(city)[1]:
        try:
            result = asyncio.run(_snmp_get_async(ip, int(city["snmp_port"]), community, oids, float(city["snmp_timeout"]), int(city["snmp_retries"])))
            if result:
                return result, community
        except Exception as exc:
            LOG.debug("SNMP %s failed: %s", ip, exc)
    return {}, ""


def snmp_collect(ip: str, city: dict[str, Any]) -> dict[str, Any]:
    values, community = snmp_get(ip, city, list(STANDARD_OIDS.values()))
    reverse = {v: k for k, v in STANDARD_OIDS.items()}
    by = {reverse.get(k, k): v for k, v in values.items()}
    out: dict[str, Any] = {
        "snmp_status": "success" if values else "failed",
        "snmp_community": community,
        "snmp_raw": by,
    }
    if not values:
        return out

    descr = s(by.get("sysDescr"))
    obj = s(by.get("sysObjectID"))
    ident_text = (descr + " " + obj).lower()
    if "mikrotik" in ident_text or "routeros" in ident_text:
        out.update(device_type="MikroTik", vendor="MikroTik")
    elif "racom" in ident_text or "33555" in obj or "microwave link" in ident_text:
        out.update(device_type="Racom", vendor="Racom")
    elif "mimosa" in ident_text or "43356" in obj:
        out.update(device_type="Mimosa", vendor="Mimosa")
    elif "cisco" in ident_text or "ios" in ident_text:
        out.update(device_type="Cisco", vendor="Cisco")

    out.update({"hostname": s(by.get("sysName")), "firmware_version": descr, "uptime": s(by.get("sysUpTime"))})

    cpu = s(by.get("hrProcessorLoad"))
    if cpu:
        out["cpu_load"] = cpu if cpu.endswith("%") else f"{cpu}%"
    try:
        total = float(re.sub(r"[^0-9.]", "", s(by.get("memTotalReal"))) or 0)
        free = float(re.sub(r"[^0-9.]", "", s(by.get("memAvailReal"))) or 0)
        if total:
            out["memory_usage"] = f"{max(0.0, (1.0 - free / total) * 100.0):.1f}%"
    except Exception:
        pass
    for key in ("mtTemperature", "mtCpuTemperature"):
        if s(by.get(key)):
            target = "temperature" if key == "mtTemperature" else "cpu_temperature"
            try:
                out[target] = f"{float(re.sub(r'[^0-9.-]', '', s(by[key])))/10:.1f} C"
            except Exception:
                pass

    # Full Interface status/traffic comes from IF-MIB over SNMP.  This is
    # intentionally isolated: a failed walk must never fail the device scan.
    community = community
    if community and shutil.which("snmpbulkwalk"):
        try:
            base_rows = {}
            for label, oid in IF_OIDS.items():
                cmd = [
                    "snmpbulkwalk", "-v2c", "-c", community, "-On",
                    "-t", str(float(city["snmp_timeout"])),
                    "-r", str(int(city["snmp_retries"])), ip, oid
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(4, int(float(city["snmp_timeout"])) * 3 + 2))
                if proc.returncode != 0:
                    continue
                for line in proc.stdout.splitlines():
                    m = re.match(r"^([^ ]+)\s*=\s*(.*)$", line.strip())
                    if not m:
                        continue
                    full_oid, raw = m.group(1), m.group(2)
                    idx = full_oid.rsplit(".", 1)[-1]
                    value = raw.split(":", 1)[1].strip() if ":" in raw else raw.strip()
                    base_rows.setdefault(idx, {})[label] = value
            if base_rows:
                out["interfaces"] = json.dumps(
                    [{"index": idx, **vals} for idx, vals in sorted(base_rows.items(), key=lambda x: x[0])],
                    ensure_ascii=False,
                )
        except Exception as exc:
            LOG.debug("SNMP interface walk %s failed: %s", ip, exc)
    return out


def tcp_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, int(port)), timeout=float(timeout)):
            return True
    except Exception:
        return False


def precheck(ip: str, city: dict[str, Any]) -> list[str]:
    reasons=[]
    if tcp_open(ip, city["snmp_port"]): reasons.append("SNMP")
    # IMPORTANT: never probe/use 8729.
    if int(city.get("api_enabled", 1)) and int(city.get("api_ssl_enabled", 0)) == 0 and tcp_open(ip, city["api_port"]): reasons.append(f"API {city['api_port']}")
    if tcp_open(ip, city["ssh_port"]): reasons.append("SSH")
    try:
        rc=subprocess.run(["ping","-c","1","-W","1",ip],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2).returncode
        if rc==0: reasons.append("ICMP")
    except Exception: pass
    return reasons


def parse_key_value_lines(text: str) -> dict[str, str]:
    out={}
    for line in text.replace("\r","").splitlines():
        m=re.match(r"^\s*([A-Za-z][A-Za-z0-9_.-]*)\s*:\s*(.*?)\s*$",line)
        if m:out[m.group(1).lower()]=m.group(2).strip()
    return out


def parse_equal_lines(text: str) -> dict[str, str]:
    out={}
    for line in text.replace("\r","").splitlines():
        for m in re.finditer(r'([A-Za-z][A-Za-z0-9_.-]*)\s*=\s*(?:"([^"]*)"|([^\s]+))',line):
            out[m.group(1).lower()]=m.group(2) if m.group(2) is not None else m.group(3)
    return out


class LegacySSH:
    def __init__(self, ip: str, username: str, password: str, port: int): self.ip,self.username,self.password,self.port=ip,username,password,port
    def exec_command(self, command: str, timeout: float = 8):
        env=os.environ.copy(); env["SSHPASS"]=self.password
        opts=["-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null","-o",f"ConnectTimeout={max(1,int(timeout))}","-o","HostKeyAlgorithms=+ssh-rsa,ssh-dss","-o","KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1","-p",str(self.port)]
        p=subprocess.run(["sshpass","-e","ssh",*opts,f"{self.username}@{self.ip}",command],env=env,text=True,capture_output=True,timeout=max(10,int(timeout)+5))
        return None, _Out(p.stdout), _Out(p.stderr)
    def close(self): pass
class _Out:
    def __init__(self,x): self.x=x
    def read(self): return self.x.encode("utf-8","replace")


def ssh_connect(ip: str, city: dict[str, Any]):
    creds,_=city_credentials(city); last=None
    for cred in creds:
        try:
            c=paramiko.SSHClient();c.set_missing_host_key_policy(paramiko.AutoAddPolicy());c.connect(ip,port=int(city["ssh_port"]),username=cred["username"],password=cred["password"],timeout=float(city["ssh_timeout"]),banner_timeout=float(city["ssh_timeout"]),auth_timeout=float(city["ssh_timeout"]),allow_agent=False,look_for_keys=False);return c,f"ssh:{cred['id']}"
        except Exception as exc:last=exc
    if os.getenv("LEGACY_SSH_FALLBACK","1").lower() in {"1","true","yes","on"} and shutil.which("sshpass"):
        for cred in creds:
            try:
                c=LegacySSH(ip,cred["username"],cred["password"],int(city["ssh_port"]))
                _,o,e=c.exec_command("/system identity print",timeout=float(city["ssh_timeout"]));txt=o.read().decode("utf-8","replace").strip()
                if txt:return c,f"ssh-legacy:{cred['id']}"
                last=RuntimeError(e.read().decode("utf-8","replace")[:200] or "Legacy SSH failed")
            except Exception as exc:last=exc
    raise RuntimeError(str(last or "No SSH credentials"))


def ssh_cmd(c, command, timeout=8):
    try:
        _,o,_=c.exec_command(command,timeout=timeout);return o.read().decode("utf-8","replace").strip()
    except Exception:return ""


def ssh_mikrotik(c):
    identity=ssh_cmd(c,"/system identity print"); resource=ssh_cmd(c,"/system resource print"); health=ssh_cmd(c,"/system health print")
    monitor=ssh_cmd(c,"/interface wireless monitor wlan1 once")
    if not monitor: monitor=ssh_cmd(c,"/interface wifi monitor wlan1 once")
    registration=ssh_cmd(c,"/interface wireless registration-table print detail")
    if not registration: registration=ssh_cmd(c,"/interface wifi registration-table print detail")
    wireless_cfg=ssh_cmd(c,"/interface wireless print detail without-paging")
    if not wireless_cfg: wireless_cfg=ssh_cmd(c,"/interface wifi print detail without-paging")
    interfaces=ssh_cmd(c,"/interface print detail without-paging")
    queues=ssh_cmd(c,"/queue simple print detail without-paging")
    firewall=ssh_cmd(c,"/ip firewall filter print stats without-paging")
    pppoe=ssh_cmd(c,"/interface pppoe-client print detail without-paging")
    routes=ssh_cmd(c,"/ip route print detail without-paging")
    i=parse_equal_lines(identity+"\n"+resource); m=parse_key_value_lines(monitor); w=parse_equal_lines(wireless_cfg)
    out={"device_type":"MikroTik","vendor":"MikroTik","hostname":i.get("name",""),"model":i.get("board-name","") or i.get("platform",""),"routeros_version":i.get("version",""),"firmware_version":i.get("version",""),"uptime":i.get("uptime",""),"interfaces":interfaces,"wireless_registration":registration,"queues":queues,"firewall_counters":firewall,"pppoe_vpn":pppoe,"ip_routes":routes,"ssh_status":"success","ssh_raw":{"identity":identity,"resource":resource,"health":health,"monitor":monitor,"registration":registration}}
    mapping={"ssid":"ssid","channel":"channel","mode":"mode","frequency":"frequency","noise-floor":"noise_floor","signal-strength":"rx_power","tx-signal-strength":"peer_tx_signal","tx-rate":"tx_rate","rx-rate":"rx_rate","radio-name":"radio_name","signal-to-noise":"snr","tx-ccq":"tx_ccq","rx-ccq":"rx_ccq","overall-tx-ccq":"ccq","status":"wireless_status"}
    for src,dst in mapping.items():
        if m.get(src):out[dst]=m[src]
    if not out.get("ssid"):out["ssid"]=w.get("ssid","")
    if not out.get("mode"):out["mode"]=w.get("mode","")
    if out.get("rx_power"):out["rx_power"]=normdbm(out["rx_power"]);out["signal_strength"]=out["rx_power"]
    if out.get("peer_tx_signal"):out["peer_tx_signal"]=normdbm(out["peer_tx_signal"])
    if out.get("noise_floor"):out["noise_floor"]=normdbm(out["noise_floor"])
    ch=s(out.get("channel")); mm=re.match(r"^(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)",ch)
    if mm:out["frequency"]=mm.group(1);out["bandwidth"]=mm.group(2)+" MHz"
    out["mac_address"]=w.get("mac-address","")
    return out


def merge_nonempty(dst: dict[str, Any], src: dict[str, Any], preserve: set[str] | None = None):
    preserve=preserve or set()
    for k,v in src.items():
        if k in preserve:continue
        if s(v):dst[k]=v


def normalize_api_data(api: dict[str, Any]) -> dict[str, Any]:
    """Flatten RouterOS API runtime radio/topology into dashboard fields."""
    out={}
    radio=api.get("radio") or {}
    if isinstance(radio,dict):
        mapping={
            "ssid":"ssid","frequency":"frequency","channel":"channel","channel-width":"bandwidth","bandwidth":"bandwidth",
            "mode":"mode","signal-strength":"rx_power","tx-signal-strength":"peer_tx_signal","tx-rate":"tx_rate","rx-rate":"rx_rate",
            "signal-to-noise":"snr","noise-floor":"noise_floor","tx-ccq":"tx_ccq","rx-ccq":"rx_ccq","overall-tx-ccq":"ccq",
            "radio-name":"radio_name","status":"wireless_status"
        }
        for src,dst in mapping.items():
            if s(radio.get(src)):out[dst]=radio[src]
        if out.get("rx_power"):out["rx_power"]=normdbm(out["rx_power"]);out["signal_strength"]=out["rx_power"]
        if out.get("peer_tx_signal"):out["peer_tx_signal"]=normdbm(out["peer_tx_signal"])
        if out.get("noise_floor"):out["noise_floor"]=normdbm(out["noise_floor"])
    wireless=api.get("api_menus",{}).get("wireless") or []
    if isinstance(wireless,list) and wireless:wireless=wireless[0]
    if isinstance(wireless,dict):
        for src,dst in (("ssid","ssid"),("channel","channel"),("frequency","frequency"),("channel-width","bandwidth"),("mode","mode"),("antenna-gain","antenna_gain"),("polarization","polarization"),("tx-power","tx_power"),("mac-address","mac_address")):
            if not s(out.get(dst)) and s(wireless.get(src)):out[dst]=wireless[src]
    menus=api.get("api_menus",{})
    for key,dst in (("registration","wireless_registration"),("interfaces","interfaces"),("queues","queues"),("firewall_filter","firewall_counters"),("pppoe","pppoe_vpn"),("routes","ip_routes"),("bridges","bridges")):
        val=menus.get(key)
        if val:out[dst]=json.dumps(val,ensure_ascii=False,default=str)
    return out


def scan_one(item: dict[str, Any]) -> dict[str, Any]:
    ip=item["ip_address"]; city=item["city"]; result={"ip_address":ip,"city_id":city["id"],"city_name":city["name"],"status":"failed","stage":"precheck","reason":"","snapshot":{}}
    if is_blacklisted(ip):result.update(status="blacklisted",stage="target",reason="IP or CIDR is blacklisted");return result
    checks=precheck(ip,city); result["precheck"]=checks
    if not checks:result.update(status="not_alive",reason="No response on SNMP/API/SSH/ICMP");return result
    before=get_device(ip);data={"ip_address":ip,"city_id":city["id"],"city":city["name"],"scan_status":"success"}
    sn=snmp_collect(ip,city);merge_nonempty(data,{k:v for k,v in sn.items() if k not in {"snmp_raw","snmp_community"}})
    api_data={}
    # Try plain RouterOS API when enabled. A successful API login can
    # identify MikroTik even when SNMP is unavailable. API-SSL is never used.
    if int(city.get("api_enabled",1)) and int(city.get("api_ssl_enabled",0))==0:
        creds,_=city_credentials(city)
        for cred in creds:
            ac=None
            try:
                ac=RouterOSAPI(ip,cred["username"],cred["password"],port=int(city["api_port"]),timeout=float(city["api_timeout"]))
                ac.connect();api_data=collect_mikrotik_api(ac);data["api_status"]="success";break
            except Exception as exc:
                data["api_status"]=f"failed: {str(exc)[:180]}"
            finally:
                if ac:ac.close()
        merge_nonempty(data,api_data,preserve={"api_menus","api_errors","api_source","api_status"})
        merge_nonempty(data,normalize_api_data(api_data))
        if not data.get("device_type") and (api_data.get("routeros_version") or api_data.get("board_name") or api_data.get("radio")):
            data.update(device_type="MikroTik",vendor="MikroTik")
    elif data.get("device_type")=="MikroTik":
        data["api_status"]="disabled"
    ssh_data={}
    try:
        c,method=ssh_connect(ip,city)
        try:
            identity_probe=ssh_cmd(c,"/system identity print")
            resource_probe=ssh_cmd(c,"/system resource print")
            if data.get("device_type")=="MikroTik" or "routeros" in (resource_probe+identity_probe).lower() or "name:" in identity_probe.lower():
                data.update(device_type="MikroTik",vendor="MikroTik")
                ssh_data=ssh_mikrotik(c)
            data["ssh_status"]="success";data["credential_id"]=method
        finally:c.close()
        # SSH fills only gaps; live API/SNMP data remains authoritative.
        fields=("ssid","frequency","channel","bandwidth","mode","radio_name","wireless_status","tx_power","rx_power","signal_strength","peer_tx_signal","tx_rate","rx_rate","ccq","tx_ccq","rx_ccq","snr","noise_floor","wireless_registration","interfaces","queues","firewall_counters","pppoe_vpn","ip_routes")
        for f in fields:
            if not s(data.get(f)) and s(ssh_data.get(f)):data[f]=ssh_data[f]
        # For MikroTik, wireless rates/signals from SSH are the requested fallback when API monitor is absent.
    except Exception as exc:data["ssh_status"]=f"failed: {str(exc)[:180]}"
    data["raw_data"]=json.dumps({"snmp":sn,"api":api_data,"ssh":ssh_data},ensure_ascii=False,default=str)
    row=db.upsert_device(data);result.update(status="success",stage="collect",reason="; ".join(checks),snapshot=row,before=before,after=row);return result


def targets(city_ids: list[int] | None=None):
    cities=[c for c in list_cities() if c["enabled"]]; selected=set(city_ids or [])
    if selected:cities=[c for c in cities if c["id"] in selected]
    out=[];seen=set()
    for city in cities:
        try:
            for ip in ipaddress.ip_network(city["cidr"],strict=False).hosts():
                sip=str(ip)
                if sip not in seen:seen.add(sip);out.append({"ip_address":sip,"city":city})
        except Exception:continue
    # Manual IPs use legacy/global credentials and ports.
    for m in list_manual_ips():
        if not m["enabled"] or m["ip_address"] in seen:continue
        seen.add(m["ip_address"]);out.append({"ip_address":m["ip_address"],"city":{"id":None,"name":"Manual","enabled":1,"ssh_port":int(os.getenv("SSH_PORT","22")),"snmp_port":int(os.getenv("SNMP_PORT","161")),"api_port":int(os.getenv("API_PORT","8728")),"api_enabled":1,"api_ssl_enabled":0,"api_timeout":float(os.getenv("API_TIMEOUT","4")),"snmp_timeout":float(os.getenv("SNMP_TIMEOUT","2.5")),"snmp_retries":int(os.getenv("SNMP_RETRIES","1")),"ssh_timeout":float(os.getenv("SSH_TIMEOUT","6")),"ssh_credentials_json":os.getenv("SSH_CREDENTIALS_JSON","[]"),"snmp_communities_json":json.dumps([os.getenv("SNMP_COMMUNITY","ngstehwl")])}})
    return out


def run_scan(city_ids: list[int] | None=None, started_by: str="system"):
    init_db(); items=targets(city_ids); selected=[c["name"] for c in list_cities() if c["enabled"] and (not city_ids or c["id"] in city_ids)]
    selection={"mode":"all" if not city_ids else "selected","city_ids":city_ids or [],"cities":selected}
    scan_id=create_scan(selection,started_by,len(items)); stats={"found":0,"success":0,"failed":0,"skipped":0};start=time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(100,max(1,int(os.getenv("SCAN_WORKERS","40"))))) as pool:
        futures=[pool.submit(scan_one,x) for x in items]
        for fut in concurrent.futures.as_completed(futures):
            try:r=fut.result()
            except Exception as exc:r={"ip_address":"?","status":"failed","stage":"exception","reason":str(exc)[:300],"snapshot":{}}
            st=r.get("status")
            if st=="success":stats["success"]+=1;stats["found"]+=1;db_before=r.get("before");db_after=r.get("after");
            elif st in {"not_alive","blacklisted","skipped"}:stats["skipped"]+=1
            else:stats["failed"]+=1;stats["found"]+=1
            if st=="success" and r.get("ip_address")!="?":record_changes(scan_id,r["ip_address"],r.get("before"),r.get("after"))
            add_scan_result(scan_id,r)
    duration=time.time()-start;finish_scan(scan_id,stats,duration);cleanup_retention();return {"scan_id":scan_id,"total_ips":len(items),**stats,"duration":duration,"selection":selection}
