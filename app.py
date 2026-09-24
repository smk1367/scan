#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import base64, io, json, os, threading, time
from functools import wraps
from pathlib import Path
from flask import Flask, jsonify, request, send_file, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
import database as db
import scanner
from excel_manager import export_excel, import_excel, template_excel

app=Flask(__name__)
DB_PATH=os.getenv("DB_PATH","/app/data/data.db")
PORT=int(os.getenv("PORT","5000")); BACKUP_DIR=Path(os.getenv("BACKUP_DIR","/app/backups")); BACKUP_DIR.mkdir(parents=True,exist_ok=True)
scan_lock=threading.Lock();scan_running=False;last_scan=None

def ensure_admin():
    db.init_db();u=os.getenv("DASHBOARD_USER","admin").strip() or "admin";p=os.getenv("DASHBOARD_PASS","change-me")
    if not db.get_user(u):
        try:db.insert_user(u,generate_password_hash(p),"full")
        except Exception:pass

def current_user():
    h=request.headers.get("Authorization","")
    if not h.startswith("Basic "):return None
    try:u,p=base64.b64decode(h[6:]).decode().split(":",1)
    except Exception:return None
    user=db.get_user(u)
    if user and check_password_hash(user["password_hash"],p):return user
    return None

def auth(fn):
    @wraps(fn)
    def w(*a,**kw):
        if request.method=="OPTIONS":return "",204
        u=current_user()
        if not u:
            r=jsonify(error="unauthorized",message="نام کاربری یا رمز عبور اشتباه است");r.status_code=401;r.headers["WWW-Authenticate"]='Basic realm="Wireless Monitor"';return r
        request.current_user=u;return fn(*a,**kw)
    return w

def full(fn):
    @wraps(fn)
    def w(*a,**kw):
        if request.current_user.get("role")!="full":return jsonify(error="forbidden",message="دسترسی مدیریتی ندارید"),403
        return fn(*a,**kw)
    return w

def auto_backup_worker():
    while True:
        try:
            interval=int(db.get_setting("backup_interval_hours",os.getenv("BACKUP_INTERVAL_HOURS","24")))
            if interval not in (12,24,36): interval=24
            time.sleep(interval*3600)
            data=export_excel(DB_PATH,hours=interval)
            name=f"auto_backup_{interval}h_{time.strftime('%Y%m%d_%H%M%S')}.xlsx"
            (BACKUP_DIR/name).write_bytes(data.getvalue())
        except Exception:
            time.sleep(300)

def retention_worker():
    while True:
        try: db.cleanup_retention()
        except Exception: pass
        time.sleep(600)

def start_workers():
    threading.Thread(target=auto_backup_worker,daemon=True).start()
    threading.Thread(target=retention_worker,daemon=True).start()

def run_background(city_ids,user):
    global scan_running,last_scan
    try:last_scan=scanner.run_scan(city_ids=city_ids,started_by=user);db.cleanup_retention()
    except Exception as e:last_scan={"status":"failed","error":str(e)[:400]}
    finally:scan_running=False

@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"]="*";r.headers["Access-Control-Allow-Headers"]="Content-Type, Authorization";r.headers["Access-Control-Allow-Methods"]="GET,POST,PUT,DELETE,OPTIONS";return r
@app.get("/")
def index():return send_file("/app/index.html")
@app.get("/images/<path:filename>")
def images(filename):return send_from_directory("/app/images",filename)
@app.get("/api/health")
def health():return jsonify(status="ok",service="wireless-monitor")
@app.get("/api/me")
@auth
def me():
    u=request.current_user;return jsonify(id=u["id"],username=u["username"],role=u["role"],enabled=u["enabled"])
@app.post("/api/logout")
@auth
def logout():return jsonify(status="ok")
@app.get("/api/stats")
@auth
def stats():return jsonify(db.get_stats())
@app.get("/api/devices")
@auth
def devices():
    q=request.args.get("q",request.args.get("search","")).strip();cid=request.args.get("city_id");cid=int(cid) if cid and cid.isdigit() else None
    rows=db.get_devices(q,cid,online_only=request.current_user["role"]!="full")
    for d in rows:
        mr=db.get_manual_radio(d["ip_address"]);d["manual_radio"] = mr
    return jsonify(rows)
@app.get("/api/device/<path:ip>")
@auth
def device(ip):
    d=db.get_device(ip)
    if not d:return jsonify(error="device_not_found"),404
    if request.current_user["role"]!="full" and d.get("scan_status")!="success":return jsonify(error="device_offline"),403
    d["manual_radio"]=db.get_manual_radio(ip)
    if d.get("raw_data"):
        try:d["raw_data_parsed"]=json.loads(d["raw_data"])
        except Exception:pass
    if request.current_user["role"]!="full":d.pop("raw_data",None);d.pop("raw_data_parsed",None)
    return jsonify(d)
@app.put("/api/device/<path:ip>/manual")
@auth
@full
def device_manual(ip):
    x=db.update_manual(ip,request.get_json(silent=True) or {});return jsonify(x) if x else (jsonify(error="device_not_found"),404)

@app.get("/api/cities")
@auth
def cities():return jsonify(db.list_cities())
@app.post("/api/cities")
@auth
@full
def city_add():
    x=request.get_json(silent=True) or {}
    try:return jsonify(db.add_city(x)),201
    except Exception as e:return jsonify(error="invalid_city",message=str(e)),400
@app.put("/api/cities/<int:cid>")
@auth
@full
def city_update(cid):
    x=request.get_json(silent=True) or {}
    try:
        r=db.update_city(cid,x);return jsonify(r) if r else (jsonify(error="not_found"),404)
    except Exception as e:return jsonify(error="invalid_city",message=str(e)),400
@app.delete("/api/cities/<int:cid>")
@auth
@full
def city_delete(cid):return jsonify(status="deleted") if db.delete_city(cid) else (jsonify(error="not_found"),404)

@app.get("/api/scan-status")
@auth
def scan_status():return jsonify(running=scan_running,last_result=last_scan)
@app.post("/api/scan-now")
@auth
@full
def scan_now():
    global scan_running
    x=request.get_json(silent=True) or {};ids=x.get("city_ids");ids=[int(v) for v in ids] if isinstance(ids,list) else None
    with scan_lock:
        if scan_running:return jsonify(status="running",message="اسکن دیگری در حال اجراست"),409
        scan_running=True
    threading.Thread(target=run_background,args=(ids,request.current_user["username"]),daemon=True).start()
    return jsonify(status="started",city_ids=ids or [],message="اسکن شروع شد")
@app.get("/api/scan-history")
@auth
def history():return jsonify(db.get_scan_history(max(1,min(int(request.args.get("limit",200)),1000))))
@app.get("/api/scan/<int:sid>")
@auth
def scan_detail(sid):
    x=db.get_scan_detail(sid);return jsonify(x) if x else (jsonify(error="scan_not_found"),404)
@app.get("/api/changes")
@auth
@full
def changes():return jsonify(db.get_changes(max(1,min(int(request.args.get("limit",1000)),5000))))
@app.delete("/api/history")
@auth
@full
def history_delete():
    before=request.args.get("before","").strip()
    if not before:return jsonify(error="before_required"),400
    try:return jsonify(deleted_scans=db.delete_history_before(before))
    except Exception as e:return jsonify(error="invalid_date",message=str(e)),400
@app.post("/api/history/cleanup")
@auth
@full
def history_cleanup():return jsonify(deleted_scans=db.cleanup_retention())

@app.get("/api/blacklist")
@auth
def blacklist_get():return jsonify(db.list_blacklist())
@app.post("/api/blacklist")
@auth
@full
def blacklist_add():
    x=request.get_json(silent=True) or {}
    try:return jsonify(db.add_blacklist(x.get("entry","").strip(),x.get("description","").strip())),201
    except Exception as e:return jsonify(error="invalid_entry",message=str(e)),400
@app.delete("/api/blacklist/<int:i>")
@auth
@full
def blacklist_delete(i):return jsonify(status="deleted") if db.delete_blacklist(i) else (jsonify(error="not_found"),404)

@app.get("/api/manual-ips")
@auth
def mi_get():return jsonify(db.list_manual_ips())
@app.post("/api/manual-ips")
@auth
@full
def mi_add():
    x=request.get_json(silent=True) or {}
    try:return jsonify(db.add_manual_ip(x.get("ip_address","").strip(),x.get("description","").strip())),201
    except Exception as e:return jsonify(error="invalid_ip",message=str(e)),400
@app.delete("/api/manual-ips/<int:i>")
@auth
@full
def mi_delete(i):return jsonify(status="deleted") if db.delete_manual_ip(i) else (jsonify(error="not_found"),404)

@app.get("/api/manual-radios")
@auth
@full
def radios_get():return jsonify(db.list_manual_radios())
@app.post("/api/manual-radios")
@auth
@full
def radios_add():
    try:return jsonify(db.upsert_manual_radio(request.get_json(silent=True) or {})),201
    except Exception as e:return jsonify(error="invalid_radio",message=str(e)),400
@app.delete("/api/manual-radios/<int:i>")
@auth
@full
def radios_delete(i):return jsonify(status="deleted") if db.delete_manual_radio(i) else (jsonify(error="not_found"),404)

@app.get("/api/users")
@auth
@full
def users_get():return jsonify(db.list_users())
@app.post("/api/users")
@auth
@full
def users_add():
    x=request.get_json(silent=True) or {};u=str(x.get("username","")).strip();p=str(x.get("password",""));role=str(x.get("role","view")).lower()
    if not u or not p or role not in {"view","full"}:return jsonify(error="invalid_user"),400
    try:return jsonify(db.insert_user(u,generate_password_hash(p),role)),201
    except Exception:return jsonify(error="username_already_exists"),409
@app.delete("/api/users/<int:i>")
@auth
@full
def users_del(i):
    if i==request.current_user["id"]:return jsonify(error="cannot_delete_current_user"),400
    return jsonify(status="deleted") if db.delete_user(i) else (jsonify(error="not_found"),404)

# Excel: devices/history plus current/historical sheets.
@app.get("/api/excel/export")
@auth
@full
def excel_export():
    hours=request.args.get("hours","all")
    try:hours=None if hours=="all" else int(hours)
    except:hours=None
    return send_file(export_excel(DB_PATH,hours=hours),as_attachment=True,download_name=f"wireless_monitor_{hours or 'all'}h.xlsx",mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
@app.get("/api/excel/template")
@auth
@full
def excel_template_route():return send_file(template_excel("devices"),as_attachment=True,download_name="wireless_monitor_devices_template.xlsx",mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
@app.post("/api/excel/import")
@auth
@full
def excel_import_route():
    f=request.files.get("file")
    if not f:return jsonify(error="file_required"),400
    try:return jsonify(import_excel(f.stream,DB_PATH,"devices"))
    except Exception as e:return jsonify(error="excel_import_failed",message=str(e)),400
@app.get("/api/excel/blacklist")
@auth
@full
def blacklist_excel_export():return send_file(export_excel(DB_PATH,mode="blacklist"),as_attachment=True,download_name="wireless_monitor_blacklist.xlsx",mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
@app.post("/api/excel/blacklist")
@auth
@full
def blacklist_excel_import():
    f=request.files.get("file")
    if not f:return jsonify(error="file_required"),400
    try:return jsonify(import_excel(f.stream,DB_PATH,"blacklist"))
    except Exception as e:return jsonify(error="blacklist_excel_failed",message=str(e)),400
@app.get("/api/excel/radios")
@auth
@full
def radio_excel_export():return send_file(export_excel(DB_PATH,mode="radios"),as_attachment=True,download_name="wireless_monitor_manual_radios.xlsx",mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
@app.post("/api/excel/radios")
@auth
@full
def radio_excel_import():
    f=request.files.get("file")
    if not f:return jsonify(error="file_required"),400
    try:return jsonify(import_excel(f.stream,DB_PATH,"radios"))
    except Exception as e:return jsonify(error="radio_excel_failed",message=str(e)),400

# Backups: selectable 12/24/36h, stored as real files; scheduled auto backup supported.
@app.get("/api/backup/list")
@auth
@full
def backup_list():
    return jsonify([{"name":p.name,"size":p.stat().st_size,"mtime":p.stat().st_mtime} for p in sorted(BACKUP_DIR.glob("*.xlsx"),key=lambda x:x.stat().st_mtime,reverse=True)])
@app.post("/api/backup")
@auth
@full
def backup_create():
    x=request.get_json(silent=True) or {};hours=int(x.get("hours",24));hours=hours if hours in (12,24,36) else 24
    data=export_excel(DB_PATH,hours=hours);name=f"wireless_monitor_backup_{hours}h_{time.strftime('%Y%m%d_%H%M%S')}.xlsx";p=BACKUP_DIR/name;p.write_bytes(data.getvalue());return jsonify(status="ok",name=name,download=f"/api/backup/file/{name}")
@app.get("/api/backup/file/<path:name>")
@auth
@full
def backup_file(name):
    p=(BACKUP_DIR/name).resolve()
    if BACKUP_DIR.resolve() not in p.parents:return jsonify(error="invalid_path"),400
    if not p.is_file():return jsonify(error="not_found"),404
    return send_file(p,as_attachment=True,download_name=p.name,mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
@app.post("/api/settings/backup-interval")
@auth
@full
def backup_interval():
    x=request.get_json(silent=True) or {};h=int(x.get("hours",24));
    if h not in (12,24,36):return jsonify(error="invalid_interval"),400
    db.set_setting("backup_interval_hours",h);return jsonify(hours=h)

# Manual Radio Scan via SSH CLI and API, never API-SSL. On RouterOS 6 the correct CLI is /interface wireless scan ...
@app.post("/api/device/<path:ip>/radio-scan")
@auth
@full
def radio_scan(ip):
    d=db.get_device(ip)
    if not d or d.get("device_type")!="MikroTik":return jsonify(error="not_mikrotik"),400
    city=next((c for c in db.list_cities() if c["id"]==d.get("city_id")),None)
    if not city:return jsonify(error="city_not_found"),400
    body=request.get_json(silent=True) or {};interface=body.get("interface") or d.get("interface_name") or "wlan1"
    errors=[]
    # First try the classic RouterOS API on plain TCP only.
    if int(city.get("api_enabled",1)) and int(city.get("api_ssl_enabled",0))==0:
        creds,_=scanner.city_credentials(city)
        for cred in creds:
            client=None
            try:
                client=scanner.RouterOSAPI(ip,cred["username"],cred["password"],port=int(city["api_port"]),timeout=float(city["api_timeout"]))
                client.connect();paths=["/interface/wifi/scan","/interface/wireless/scan"] if str(d.get("routeros_version","")).startswith("7.") else ["/interface/wireless/scan","/interface/wifi/scan"]
                for path in paths:
                    try:
                        rows=client.command(path,interface=interface,duration="5s");client.close();return jsonify(status="success",method="routeros-api-plain",command=path,interface=interface,data=rows)
                    except Exception as exc:errors.append(f"{path}: {str(exc)[:180]}")
            except Exception as exc:errors.append(f"API: {str(exc)[:180]}")
            finally:
                if client:client.close()
    # Then use the correct RouterOS CLI syntax for the version.
    try:
        c,method=scanner.ssh_connect(ip,city)
        try:
            ros=str(d.get("routeros_version","") or "")
            cmd=f"/interface wifi scan {interface} duration=5s" if ros.startswith("7.") else f"/interface wireless scan {interface} duration=5s"
            out=scanner.ssh_cmd(c,cmd,timeout=15)
            if out:return jsonify(status="success",method=method,command=cmd,interface=interface,data=out)
            errors.append("SSH scan returned no data")
        finally:c.close()
    except Exception as exc:errors.append(f"SSH: {str(exc)[:240]}")
    return jsonify(status="failed",errors=errors),400

if __name__=="__main__":
    ensure_admin(); start_workers(); app.run(host="0.0.0.0",port=PORT,debug=False)
