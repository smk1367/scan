#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fix Wireless Monitor Enterprise scan/credential issues without removing features.

Run this file from the repository root (the directory containing scanner.py).
It creates *.pre_scan_fix.bak backups, patches the code, and syntax-checks it.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FILES = ["scanner.py", "routeros_api.py", "database.py", "index.html"]


def backup(path: Path) -> None:
    bak = path.with_suffix(path.suffix + ".pre_scan_fix.bak")
    if not bak.exists():
        shutil.copy2(path, bak)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        raise RuntimeError(f"{label}: expected 1 match, found {n}")
    return text.replace(old, new, 1)


def patch_scanner(path: Path) -> None:
    c = path.read_text(encoding="utf-8")

    helper_old = '''def parse_equal_lines(text: str) -> dict[str, str]:
    out={}
    for line in text.replace("\\r","").splitlines():
        for m in re.finditer(r'([A-Za-z][A-Za-z0-9_.-]*)\\s*=\\s*(?:"([^"]*)"|([^\\s]+))',line):
            out[m.group(1).lower()]=m.group(2) if m.group(2) is not None else m.group(3)
    return out
'''
    helper_new = helper_old + '''
def routeros_interface_names(text: str) -> list[str]:
    """Extract interface names from RouterOS print detail/terse output."""
    names = []
    for m in re.finditer(r'(?:^|\\s)name=(?:"([^"]+)"|([^\\s]+))', text, flags=re.MULTILINE):
        name = (m.group(1) or m.group(2) or "").strip()
        if name and name not in names:
            names.append(name)
    return names
'''
    c = replace_once(c, helper_old, helper_new, "scanner helper")

    ssh_old = '''def ssh_mikrotik(c):
    identity=ssh_cmd(c,"/system identity print"); resource=ssh_cmd(c,"/system resource print"); health=ssh_cmd(c,"/system health print")
    monitor=ssh_cmd(c,"/interface wireless monitor wlan1 once")
    if not monitor: monitor=ssh_cmd(c,"/interface wifi monitor wlan1 once")
    registration=ssh_cmd(c,"/interface wireless registration-table print detail")
    if not registration: registration=ssh_cmd(c,"/interface wifi registration-table print detail")
    wireless_cfg=ssh_cmd(c,"/interface wireless print detail without-paging")
    if not wireless_cfg: wireless_cfg=ssh_cmd(c,"/interface wifi print detail without-paging")
'''
    ssh_new = '''def ssh_mikrotik(c):
    identity=ssh_cmd(c,"/system identity print"); resource=ssh_cmd(c,"/system resource print"); health=ssh_cmd(c,"/system health print")
    wireless_cfg=ssh_cmd(c,"/interface wireless print detail without-paging")
    wireless_api="wireless"
    if not wireless_cfg:
        wireless_cfg=ssh_cmd(c,"/interface wifi print detail without-paging")
        wireless_api="wifi"
    interface_names=routeros_interface_names(wireless_cfg)
    wireless_interface=interface_names[0] if interface_names else "wlan1"
    monitor=ssh_cmd(c,f"/interface {wireless_api} monitor {wireless_interface} once")
    if not monitor and wireless_api=="wireless":
        monitor=ssh_cmd(c,f"/interface wifi monitor {wireless_interface} once")
    elif not monitor and wireless_api=="wifi":
        monitor=ssh_cmd(c,f"/interface wireless monitor {wireless_interface} once")
    registration=ssh_cmd(c,f"/interface {wireless_api} registration-table print detail")
    if not registration and wireless_api=="wireless":
        registration=ssh_cmd(c,"/interface wifi registration-table print detail")
    elif not registration and wireless_api=="wifi":
        registration=ssh_cmd(c,"/interface wireless registration-table print detail")
'''
    c = replace_once(c, ssh_old, ssh_new, "scanner SSH wireless selection")

    out_old = '''    out={"device_type":"MikroTik","vendor":"MikroTik","hostname":i.get("name",""),"model":i.get("board-name","") or i.get("platform",""),"routeros_version":i.get("version",""),"firmware_version":i.get("version",""),"uptime":i.get("uptime",""),"interfaces":interfaces,"wireless_registration":registration,"queues":queues,"firewall_counters":firewall,"pppoe_vpn":pppoe,"ip_routes":routes,"ssh_status":"success","ssh_raw":{"identity":identity,"resource":resource,"health":health,"monitor":monitor,"registration":registration}}
'''
    out_new = '''    out={"device_type":"MikroTik","vendor":"MikroTik","hostname":i.get("name",""),"model":i.get("board-name","") or i.get("platform",""),"routeros_version":i.get("version",""),"firmware_version":i.get("version",""),"uptime":i.get("uptime",""),"interface_name":wireless_interface,"interfaces":interfaces,"wireless_registration":registration,"queues":queues,"firewall_counters":firewall,"pppoe_vpn":pppoe,"ip_routes":routes,"ssh_status":"success","ssh_raw":{"identity":identity,"resource":resource,"health":health,"monitor":monitor,"registration":registration,"wireless_interface":wireless_interface}}
'''
    c = replace_once(c, out_old, out_new, "scanner SSH output")

    pre_old = '''def precheck(ip: str, city: dict[str, Any]) -> list[str]:
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
'''
    pre_new = '''def precheck(ip: str, city: dict[str, Any]) -> list[str]:
    reasons=[]
    # SNMP is UDP. Do not TCP-probe port 161: a valid SNMP-only device
    # would otherwise be incorrectly classified as "not_alive".
    # IMPORTANT: never probe/use RouterOS API SSL 8729.
    if int(city.get("api_enabled", 1)) and int(city.get("api_ssl_enabled", 0)) == 0 and tcp_open(ip, city["api_port"]):
        reasons.append(f"API {city['api_port']}")
    if tcp_open(ip, city["ssh_port"]):
        reasons.append("SSH")
    try:
        rc=subprocess.run(["ping","-c","1","-W","1",ip],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2).returncode
        if rc==0: reasons.append("ICMP")
    except Exception:
        pass
    if not reasons:
        # Only do a direct SNMP UDP check when the faster probes found
        # nothing. This preserves scan speed on large networks while still
        # discovering SNMP-only devices.
        probe,_=snmp_get(ip,city,[STANDARD_OIDS["sysObjectID"]])
        if probe:
            reasons.append("SNMP")
    return reasons
'''
    c = replace_once(c, pre_old, pre_new, "scanner SNMP precheck")

    fields_old = '''        fields=("ssid","frequency","channel","bandwidth","mode","radio_name","wireless_status","tx_power","rx_power","signal_strength","peer_tx_signal","tx_rate","rx_rate","ccq","tx_ccq","rx_ccq","snr","noise_floor","wireless_registration","interfaces","queues","firewall_counters","pppoe_vpn","ip_routes")
'''
    fields_new = '''        fields=("ssid","frequency","channel","bandwidth","mode","radio_name","interface_name","wireless_status","tx_power","rx_power","signal_strength","peer_tx_signal","tx_rate","rx_rate","ccq","tx_ccq","rx_ccq","snr","noise_floor","wireless_registration","interfaces","queues","firewall_counters","pppoe_vpn","ip_routes")
'''
    c = replace_once(c, fields_old, fields_new, "scanner field merge")

    tail_old = '''    data["raw_data"]=json.dumps({"snmp":sn,"api":api_data,"ssh":ssh_data},ensure_ascii=False,default=str)
    row=db.upsert_device(data);result.update(status="success",stage="collect",reason="; ".join(checks),snapshot=row,before=before,after=row);return result
'''
    tail_new = '''    data["raw_data"]=json.dumps({"snmp":sn,"api":api_data,"ssh":ssh_data},ensure_ascii=False,default=str)
    protocol_ok = sn.get("snmp_status") == "success" or data.get("api_status") == "success" or data.get("ssh_status") == "success"
    if not protocol_ok:
        failed_reasons=[]
        if sn.get("snmp_status") != "success": failed_reasons.append("SNMP failed")
        if data.get("api_status","").startswith("failed"): failed_reasons.append(data["api_status"])
        if data.get("ssh_status","").startswith("failed"): failed_reasons.append(data["ssh_status"])
        reason = "; ".join(failed_reasons) or "No usable monitoring protocol responded"
        result.update(status="failed",stage="collect",reason=reason,snapshot=data,before=before,after=None)
        return result
    row=db.upsert_device(data);result.update(status="success",stage="collect",reason="; ".join(checks),snapshot=row,before=before,after=row);return result
'''
    c = replace_once(c, tail_old, tail_new, "scanner protocol result handling")

    backup(path)
    path.write_text(c, encoding="utf-8")


def patch_routeros(path: Path) -> None:
    c = path.read_text(encoding="utf-8")

    old = '''    def connect(self):
        self.sock=socket.create_connection((self.host,self.port),timeout=self.timeout);self.sock.settimeout(self.timeout)
        try:
            self._sentence(["/login",f"=name={self.username}",f"=password={self.password}"]);return
        except Exception:
            pass
        try:
            rows=self._sentence(["/login"])
            token=rows[0].get("ret") if rows else ""
            if token:
                digest=hashlib.md5(b"\\x00"+self.password.encode()+bytes.fromhex(token)).hexdigest()
                self._sentence(["/login",f"=name={self.username}",f"=response=00{digest}"]);return
        except Exception as exc:
            self.close();raise RouterOSAPIError(f"login failed: {exc}") from exc
        self.close();raise RouterOSAPIError("login failed")
'''
    new = '''    def _open_socket(self):
        self.close()
        self.sock=socket.create_connection((self.host,self.port),timeout=self.timeout)
        self.sock.settimeout(self.timeout)

    def connect(self):
        # RouterOS 6.43+ usually accepts username/password directly. If a
        # legacy RouterOS build answers with a challenge, reconnect cleanly
        # and complete the MD5 challenge on a fresh socket.
        self._open_socket()
        try:
            self._sentence(["/login",f"=name={self.username}",f"=password={self.password}"])
            return
        except Exception:
            self.close()

        self._open_socket()
        try:
            rows=self._sentence(["/login"])
            token=rows[0].get("ret") if rows else ""
            if not token:
                raise RouterOSAPIError("login challenge token missing")
            digest=hashlib.md5(b"\\x00"+self.password.encode()+bytes.fromhex(token)).hexdigest()
            self._sentence(["/login",f"=name={self.username}",f"=response=00{digest}"])
            return
        except Exception as exc:
            self.close()
            raise RouterOSAPIError(f"login failed: {exc}") from exc
'''
    c = replace_once(c, old, new, "RouterOS API login")

    old = '''    # Wireless configuration and live values. RouterOS 6 first, RouterOS 7 second.
    run("wireless",["/interface/wireless/print","/interface/wifi/print"])
    run("interfaces",["/interface/print"])
'''
    new = '''    # Wireless configuration and live values. RouterOS 6 first, RouterOS 7 second.
    wireless_rows=run("wireless",["/interface/wireless/print","/interface/wifi/print"])
    interface_name=""
    if wireless_rows:
        for row in wireless_rows:
            candidate=row.get("name") or row.get(".id") or ""
            if candidate:
                interface_name=candidate
                if str(row.get("running","")).lower() in {"true","yes","1"}:
                    break
        if interface_name:
            out["interface_name"]=interface_name
    run("interfaces",["/interface/print"])
'''
    c = replace_once(c, old, new, "RouterOS API wireless discovery")

    old = '''    for path in ("/interface/wireless/monitor","/interface/wifi/monitor"):
        try:
            rows=c.command(path,once="",numbers="wlan1")
            if rows:
                out["radio_path"]=path;out["radio"]=rows[0];break
        except Exception as exc:out["api_errors"]["radio_monitor"]=f"{path}: {str(exc)[:180]}"
'''
    new = '''    monitor_interface=out.get("interface_name","wlan1")
    for path in ("/interface/wireless/monitor","/interface/wifi/monitor"):
        try:
            rows=c.command(path,once="",numbers=monitor_interface)
            if rows:
                out["radio_path"]=path;out["radio"]=rows[0];break
        except Exception as exc:
            out["api_errors"]["radio_monitor"]=f"{path} {monitor_interface}: {str(exc)[:180]}"
'''
    c = replace_once(c, old, new, "RouterOS API monitor interface")

    backup(path)
    path.write_text(c, encoding="utf-8")


def patch_database(path: Path) -> None:
    c = path.read_text(encoding="utf-8")
    c = replace_once(c, "    radio_name TEXT,\n    wireless_status TEXT,", "    radio_name TEXT,\n    interface_name TEXT,\n    wireless_status TEXT,", "database schema interface_name")
    c = replace_once(c, '            "bandwidth", "mode", "radio_name", "wireless_status", "tx_power",', '            "bandwidth", "mode", "radio_name", "interface_name", "wireless_status", "tx_power",', "database ensure-columns interface_name")
    c = replace_once(c, '    "channel", "bandwidth", "mode", "radio_name", "wireless_status", "tx_power",', '    "channel", "bandwidth", "mode", "radio_name", "interface_name", "wireless_status", "tx_power",', "database tracked fields interface_name")
    c = replace_once(c, '"ssid","frequency","channel","bandwidth","mode","radio_name","wireless_status","tx_power","rx_power"', '"ssid","frequency","channel","bandwidth","mode","radio_name","interface_name","wireless_status","tx_power","rx_power"', "database upsert fields interface_name")
    backup(path)
    path.write_text(c, encoding="utf-8")


def patch_index(path: Path) -> None:
    c = path.read_text(encoding="utf-8")
    old = 'placeholder=\'SSH credentials JSON: [{\\"id\\":\\"a\\",\\"username\\":\\"admin\\",\\"password\\":\\"xxx\\"},{\\"id\\":\\"b\\",\\"username\\":\\"op\\",\\"password\\":\\"yyy\\"}]\''
    new = 'placeholder=\'SSH + RouterOS API credentials JSON: [{\\"id\\":\\"a\\",\\"username\\":\\"admin\\",\\"password\\":\\"xxx\\"},{\\"id\\":\\"b\\",\\"username\\":\\"op\\",\\"password\\":\\"yyy\\"}]\''
    if old in c:
        c = c.replace(old, new, 1)
    old = 'برای هر شهر پورت‌ها و credentialهای مستقل ثبت می‌شوند. <b>API-SSL عمداً خاموش است و استفاده نمی‌شود.</b>'
    new = 'برای هر شهر پورت‌ها و credentialهای مستقل ثبت می‌شوند. همان credentialهای SSH برای RouterOS API Plain نیز استفاده می‌شوند. <b>API-SSL عمداً خاموش است و استفاده نمی‌شود.</b>'
    if old in c:
        c = c.replace(old, new, 1)
    old = "['Mode',d.mode],['Radio',d.radio_name],['Wireless Status',d.wireless_status]"
    new = "['Mode',d.mode],['Radio',d.radio_name],['Interface',d.interface_name],['Wireless Status',d.wireless_status]"
    if old in c:
        c = c.replace(old, new, 1)
    backup(path)
    path.write_text(c, encoding="utf-8")


def main() -> None:
    for f in FILES:
        p = ROOT / f
        if not p.exists():
            raise SystemExit(f"Missing file: {p}")
    patch_scanner(ROOT / "scanner.py")
    patch_routeros(ROOT / "routeros_api.py")
    patch_database(ROOT / "database.py")
    patch_index(ROOT / "index.html")
    py_files = ["scanner.py", "routeros_api.py", "database.py", "app.py"]
    r = subprocess.run(["python3", "-m", "py_compile", *py_files], cwd=ROOT, text=True, capture_output=True)
    if r.returncode:
        print(r.stdout)
        print(r.stderr)
        raise SystemExit("Python syntax check failed; restore *.pre_scan_fix.bak and review.")
    print("FIX APPLIED SUCCESSFULLY")
    print("Backups: *.pre_scan_fix.bak")
    print("Validated: scanner.py routeros_api.py database.py app.py")
    print("Next:")
    print("  git diff --check")
    print("  git diff")
    print("  git add scanner.py routeros_api.py database.py index.html")
    print("  git commit -m 'Fix SNMP discovery and MikroTik credential/radio scan'")
    print("  git push origin main")


if __name__ == "__main__":
    main()
