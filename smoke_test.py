import os, tempfile
os.environ['DB_PATH'] = os.path.join(tempfile.gettempdir(), 'wireless_monitor_smoke.db')
try:
    os.remove(os.environ['DB_PATH'])
except FileNotFoundError:
    pass
import database as db

db.init_db()
city = db.add_city('تست', '192.0.2.0/30', 'smoke')
assert city['name'] == 'تست'
scan = db.create_scan({'cities':[city['id']]}, 'smoke', 2)
db.add_scan_result(scan, {'ip_address':'192.0.2.1','city_id':city['id'],'city_name':'تست','status':'not_alive','stage':'precheck','reason':'test'})
db.finish_scan(scan, {'found':0,'success':0,'failed':0,'skipped':1}, 0.1)
d = db.get_scan_detail(scan)
assert d and len(d['results']) == 1 and d['results'][0]['status'] == 'not_alive'
print('SMOKE_OK')
