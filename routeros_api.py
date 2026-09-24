#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small plain RouterOS API client. API-SSL is intentionally unsupported."""
from __future__ import annotations

import hashlib
import socket
from typing import Any

class RouterOSAPIError(RuntimeError):
    pass

def enc_len(n:int)->bytes:
    if n<0x80:return bytes([n])
    if n<0x4000:return (n|0x8000).to_bytes(2,"big")
    if n<0x200000:return (n|0xC00000).to_bytes(3,"big")
    if n<0x10000000:return (n|0xE0000000).to_bytes(4,"big")
    return b"\xf0"+n.to_bytes(4,"big")

def read_exact(sock,n):
    data=b""
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk:raise RouterOSAPIError("connection closed")
        data+=chunk
    return data

def dec_len(sock):
    x=read_exact(sock,1)[0]
    if x<0x80:return x
    if x&0xC0==0x80:return ((x&0x3F)<<8)|read_exact(sock,1)[0]
    if x&0xE0==0xC0:return ((x&0x1F)<<16)|int.from_bytes(read_exact(sock,2),"big")
    if x&0xF0==0xE0:return ((x&0x0F)<<24)|int.from_bytes(read_exact(sock,3),"big")
    return int.from_bytes(read_exact(sock,4),"big")

def write_word(sock,word):
    raw=str(word).encode("utf-8","replace");sock.sendall(enc_len(len(raw))+raw)

def parse_sentence(words):
    out={"!type":words[0] if words else ""}
    for w in words[1:]:
        if w.startswith("=") and "=" in w[1:]:
            k,v=w[1:].split("=",1);out[k]=v
    return out

class RouterOSAPI:
    def __init__(self,host,username,password,port=8728,timeout=4):
        self.host,self.username,self.password=host,username,password;self.port=int(port);self.timeout=float(timeout);self.sock=None
    def connect(self):
        self.sock=socket.create_connection((self.host,self.port),timeout=self.timeout);self.sock.settimeout(self.timeout)
        try:
            self._sentence(["/login",f"=name={self.username}",f"=password={self.password}"]);return
        except Exception:
            pass
        try:
            rows=self._sentence(["/login"])
            token=rows[0].get("ret") if rows else ""
            if token:
                digest=hashlib.md5(b"\x00"+self.password.encode()+bytes.fromhex(token)).hexdigest()
                self._sentence(["/login",f"=name={self.username}",f"=response=00{digest}"]);return
        except Exception as exc:
            self.close();raise RouterOSAPIError(f"login failed: {exc}") from exc
        self.close();raise RouterOSAPIError("login failed")
    def close(self):
        if self.sock:
            try:self.sock.close()
            except Exception:pass
        self.sock=None
    def _sentence(self,words):
        if not self.sock:raise RouterOSAPIError("not connected")
        for w in words:write_word(self.sock,w)
        write_word(self.sock,"")
        rows=[]
        while True:
            words=[]
            while True:
                n=dec_len(self.sock)
                if n==0:break
                words.append(read_exact(self.sock,n).decode("utf-8","replace"))
            msg=parse_sentence(words);kind=msg.get("!type")
            if kind=="!re":rows.append(msg)
            elif kind=="!trap":raise RouterOSAPIError(msg.get("message","command trap"))
            elif kind=="!fatal":raise RouterOSAPIError(msg.get("message","fatal"))
            elif kind=="!done":return rows
    def command(self,path,**kwargs):
        return self._sentence([path]+[f"={k}={v}" for k,v in kwargs.items() if v is not None])
    def safe(self,path,**kwargs):
        try:return self.command(path,**kwargs)
        except Exception:return []

def collect_mikrotik_api(c:RouterOSAPI)->dict[str,Any]:
    out={"api_source":"plain-8728","api_status":"success","api_menus":{},"api_errors":{}}
    def run(name,paths,**kwargs):
        last=""
        for path in paths:
            try:
                rows=c.command(path,**kwargs);out["api_menus"][name]=rows;return rows
            except Exception as exc:last=f"{path}: {str(exc)[:180]}"
        if last:out["api_errors"][name]=last
        return []
    res=run("resource",["/system/resource/print"]);ident=run("identity",["/system/identity/print"]);rb=run("routerboard",["/system/routerboard/print"]);health=run("health",["/system/health/print"])
    if res:out.update({"routeros_version":res[0].get("version",""),"uptime":res[0].get("uptime",""),"cpu_load":res[0].get("cpu-load",""),"memory_total":res[0].get("total-memory",""),"memory_free":res[0].get("free-memory",""),"board_name":res[0].get("board-name","")})
    if ident:out["hostname"]=ident[0].get("name","")
    if rb:out["model"]=rb[0].get("model","") or out.get("board_name","");out["serial_number"]=rb[0].get("serial-number","")
    if health:
        out["health"]=health[0]
        for k in ("temperature","cpu-temperature","voltage","power-consumption","fan-speed"):
            if health[0].get(k):out[k.replace("-","_")]=health[0][k]

    # Wireless configuration and live values. RouterOS 6 first, RouterOS 7 second.
    run("wireless",["/interface/wireless/print","/interface/wifi/print"])
    run("interfaces",["/interface/print"])
    run("pppoe",["/interface/pppoe-client/print"])
    run("queues",["/queue/simple/print","/queue/tree/print"])
    run("firewall_filter",["/ip/firewall/filter/print"],stats="")
    run("firewall_nat",["/ip/firewall/nat/print"])
    run("routes",["/ip/route/print"])
    run("bridges",["/interface/bridge/print","/interface/bridge/port/print"])
    run("registration",["/interface/wireless/registration-table/print","/interface/wifi/registration-table/print"])

    for path in ("/interface/wireless/monitor","/interface/wifi/monitor"):
        try:
            rows=c.command(path,once="",numbers="wlan1")
            if rows:
                out["radio_path"]=path;out["radio"]=rows[0];break
        except Exception as exc:out["api_errors"]["radio_monitor"]=f"{path}: {str(exc)[:180]}"
    return out
