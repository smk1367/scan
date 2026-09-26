#!/usr/bin/env python3
from pathlib import Path

path = Path('excel_manager.py')
s = path.read_text(encoding='utf-8')

old_helper = '''def add_city_sheets(wb,conn,rows):
    by_city={}
    for row in rows:
        city=text(row.get("City") or "").strip() or "نامشخص"
        by_city.setdefault(city,[]).append(row)
    used=set()
    city_rows=conn.execute("SELECT name FROM cities WHERE enabled=1 ORDER BY name").fetchall()
    for row in city_rows:
        city=text(row[0]).strip() or "نامشخص"
        add_sheet(wb,city_sheet_title(city,used),VIEW_HEADERS,by_city.pop(city,[]))
    for city,items in by_city.items():
        add_sheet(wb,city_sheet_title(city,used),VIEW_HEADERS,items)
'''

new_helper = '''def _city_section_rows(rows, headers, section):
    if section=="main":
        return [{h:row.get(h,"") for h in headers} for row in rows]
    if section=="wireless":
        return [{h:row.get(h,"") for h in headers} for row in rows]
    return [{
        "IP": row.get("IP",""),
        "Scan City": row.get("City",""),
        "Latitude": row.get("_antenna_latitude",""),
        "Longitude": row.get("_antenna_longitude",""),
        "Province": row.get("_antenna_province",""),
        "City": row.get("_antenna_city",""),
        "Antenna Gain": row.get("_antenna_gain",""),
        "Polarization": row.get("_antenna_polarization",""),
        "Capacity": row.get("_antenna_capacity",""),
    } for row in rows]


def add_city_section_sheet(wb,title,rows):
    ws=wb.create_sheet(title)
    sections=(
        ("اصلی",VIEW_HEADERS,"main"),
        ("Wireless",WIRELESS_HEADERS,"wireless"),
        ("اطلاعات آنتن",ANTENNA_HEADERS,"antenna"),
    )
    current_row=1
    title_fill=PatternFill("solid",fgColor="17365D")
    header_fill=PatternFill("solid",fgColor="1F4E78")
    for section_title,headers,section in sections:
        last_col=max(1,len(headers))
        ws.merge_cells(start_row=current_row,start_column=1,end_row=current_row,end_column=last_col)
        cell=ws.cell(current_row,1,section_title)
        cell.font=Font(bold=True,color="FFFFFF",size=12)
        cell.fill=title_fill
        cell.alignment=Alignment(horizontal="center",vertical="center")
        current_row+=1
        for col,header in enumerate(headers,1):
            cell=ws.cell(current_row,col,header)
            cell.font=Font(bold=True,color="FFFFFF")
            cell.fill=header_fill
            cell.alignment=Alignment(horizontal="center",vertical="center")
        current_row+=1
        for row in _city_section_rows(rows,headers,section):
            for col,header in enumerate(headers,1):
                ws.cell(current_row,col,row.get(header,""))
            current_row+=1
        current_row+=2
    ws.freeze_panes="A3"
    for col in range(1,ws.max_column+1):
        max_len=min(42,max(12,max((len(text(r[0].value)) for r in ws.iter_rows(min_col=col,max_col=col)),default=12)+2))
        ws.column_dimensions[get_column_letter(col)].width=max_len
    return ws


def add_city_section_sheets(wb,conn,rows):
    by_city={}
    for row in rows:
        city=text(row.get("City") or "").strip() or "نامشخص"
        by_city.setdefault(city,[]).append(row)
    used=set()
    city_rows=conn.execute("SELECT name FROM cities WHERE enabled=1 ORDER BY name").fetchall()
    for row in city_rows:
        city=text(row[0]).strip() or "نامشخص"
        add_city_section_sheet(wb,city_sheet_title(city,used),by_city.pop(city,[]))
    for city,items in sorted(by_city.items(),key=lambda item:text(item[0]).casefold()):
        add_city_section_sheet(wb,city_sheet_title(city,used),items)
'''

old_view_start='''        elif mode=="view_full":
'''
old_view_end='''        else:
'''
start = s.find(old_view_start)
end = s.find(old_view_end, start)
if start < 0 or end < 0:
    raise SystemExit('view_full block not found')

new_view = '''        elif mode=="view_full":
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
                       d.ssh_status AS SSH,d.last_seen AS 'Last Seen',d.scan_status AS Status,
                       COALESCE(NULLIF(d.manual_latitude,''),d.latitude,'') AS _antenna_latitude,
                       COALESCE(NULLIF(d.manual_longitude,''),d.longitude,'') AS _antenna_longitude,
                       COALESCE(NULLIF(d.manual_province,''),d.province,'') AS _antenna_province,
                       COALESCE(d.manual_city,'') AS _antenna_city,
                       COALESCE(NULLIF(d.manual_antenna_gain,''),d.antenna_gain,'') AS _antenna_gain,
                       COALESCE(NULLIF(d.manual_polarization,''),d.polarization,'') AS _antenna_polarization,
                       COALESCE(NULLIF(d.manual_capacity,''),d.capacity,'') AS _antenna_capacity
                FROM devices d WHERE %s ORDER BY d.city,d.ip_address
            """ % " AND ".join(where),args)]
            # View Excel: one worksheet per city, containing three sections only:
            # Main, Wireless and Antenna Information. No separate Devices/Wireless tabs.
            add_city_section_sheets(wb,conn,rows)
'''

if old_helper not in s:
    raise SystemExit('old helper block not found')
s = s.replace(old_helper, new_helper, 1)
s = s[:start] + new_view + s[end:]
path.write_text(s, encoding='utf-8')
print('UPDATED', path)
