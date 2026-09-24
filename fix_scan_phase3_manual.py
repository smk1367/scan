#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Add editable antenna/site form to the existing phase-3 index.html."""
from __future__ import annotations
import re
import shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parent
p=ROOT/'index.html'
backup=p.with_suffix(p.suffix+'.phase3manual.bak')

c=p.read_text(encoding='utf-8')

if 'async function saveAntennaDetail()' not in c:
    anchor='function openAdmin(){'
    fn="""async function saveAntennaDetail(){const payload={latitude:$('a_lat').value,longitude:$('a_lon').value,province:$('a_prov').value,city:$('a_city').value,antenna_gain:$('a_gain').value,polarization:$('a_pol').value,capacity:$('a_cap').value};try{current=await api('/api/device/'+encodeURIComponent(current.ip_address)+'/manual',{method:'PUT',body:JSON.stringify(payload)});alert('اطلاعات آنتن ذخیره شد ✅');detailTab('antenna',document.querySelector('.tab.active'))}catch(e){alert(e.message)}}\n"""
    if anchor not in c:
        raise SystemExit('openAdmin anchor not found')
    c=c.replace(anchor,fn+anchor,1)

if 'id="a_lat"' not in c:
    marker=re.search(r"if\(name==='antenna'\)\{rows=\[[^\n]+?\}\}",c)
    if not marker:
        raise SystemExit('antenna detail branch not found; run fix_scan_phase3.py first')
    branch=marker.group(0)
    edit='''if(name==='antenna'){ $('detailBody').innerHTML=`<div class="notice">اطلاعات آنتن برای همین IP ذخیره می‌شود و با Excel شهر نیز هماهنگ است.</div><div class="form-grid"><input id="a_lat" placeholder="Latitude" value="${h(d.manual_latitude||d.latitude||'')}"><input id="a_lon" placeholder="Longitude" value="${h(d.manual_longitude||d.longitude||'')}"><input id="a_prov" placeholder="Province" value="${h(d.manual_province||d.province||'')}"><input id="a_city" placeholder="City" value="${h(d.manual_city||'')}"><input id="a_gain" placeholder="Antenna Gain" value="${h(d.manual_antenna_gain||d.antenna_gain||'')}"><input id="a_pol" placeholder="Polarization" value="${h(d.manual_polarization||d.polarization||'')}"><input id="a_cap" placeholder="Capacity" value="${h(d.manual_capacity||d.capacity||'')}"><button class="btn primary wide" onclick="saveAntennaDetail()">💾 ذخیره اطلاعات دستی</button></div>`;return}'''


    c=c.replace(branch,branch+edit,1)

if c==p.read_text(encoding='utf-8'):
    print('NO_CHANGE')
else:
    if not backup.exists():
        shutil.copy2(p,backup)
    p.write_text(c,encoding='utf-8')
    print('MANUAL ANTENNA UI APPLIED')
    print('Backup:',backup.name)

