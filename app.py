#!/usr/bin/env python3
"""Manish Uniform — stitching job-work tracker.

Flow: cloth order to cloth vendor -> cloth despatched (to a stitching vendor or to us)
-> stitch order to stitching vendor -> stitched goods despatched back to us.
Cloth stock is tracked per location ('self' = Manish Uniform, or a stitch vendor id).
"""
import sqlite3, os, sys, json, hashlib, hmac, base64, time, uuid, shutil, threading, collections
from datetime import datetime, date
from functools import wraps
from flask import Flask, request, jsonify, g

for _s in (sys.stdout, sys.stderr):
    try: _s.reconfigure(encoding='utf-8', errors='replace')
    except Exception: pass

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
except ImportError:
    pass

app = Flask(__name__, static_folder='static', static_url_path='')

BASE = os.path.dirname(os.path.abspath(__file__))
# On Railway DATA_DIR points at the mounted volume; the container's own disk is wiped on redeploy.
DATA_DIR = os.environ.get('DATA_DIR') or os.path.join(BASE, 'data')
DB_PATH = os.path.join(DATA_DIR, 'manish.db')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')
JWT_SECRET = os.environ.get('JWT_SECRET', 'manish-uniform-change-me')
if os.environ.get('RAILWAY_ENVIRONMENT') and JWT_SECRET == 'manish-uniform-change-me':
    raise SystemExit('JWT_SECRET must be set in the Railway service variables')
PORT = int(os.environ.get('PORT', 5004))
BACKUP_KEEP_DAYS = int(os.environ.get('BACKUP_KEEP_DAYS', 30))
os.makedirs(BACKUP_DIR, exist_ok=True)

SELF = 'self'   # location code for Manish Uniform's own godown
CHARGE_HEADS = ['Transport', 'Buttons', 'Labels', 'Thread', 'Packing', 'Other']

# ── login rate limit ──────────────────────────────────────────────────────────
_login_attempts = collections.defaultdict(list)
def _rate_limited(key):
    now = time.time()
    _login_attempts[key] = [t for t in _login_attempts[key] if now - t < 900]
    return len(_login_attempts[key]) >= 10

_number_lock = threading.Lock()

# ── auth helpers (same scheme as GPCI ERP) ────────────────────────────────────
def b64url(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
def make_token(payload, ttl=43200):
    payload = {**payload, 'exp': int(time.time()) + ttl}
    header = b64url(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())
    body = b64url(json.dumps(payload).encode())
    sig = b64url(hmac.new(JWT_SECRET.encode(), f'{header}.{body}'.encode(), 'sha256').digest())
    return f'{header}.{body}.{sig}'
def verify_token(token):
    try:
        header, body, sig = token.split('.')
        expected = b64url(hmac.new(JWT_SECRET.encode(), f'{header}.{body}'.encode(), 'sha256').digest())
        if not hmac.compare_digest(sig, expected): return None
        payload = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
        if payload.get('exp', 0) < time.time(): return None
        return payload
    except Exception:
        return None
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

# ── db helpers ────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db
@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.commit(); db.close()
def q(sql, params=(), one=False):
    cur = get_db().execute(sql, params)
    return cur.fetchone() if one else cur.fetchall()
def qw(sql, params=()):
    get_db().execute(sql, params)
def rows(r): return [dict(x) for x in r]
def one(r): return dict(r) if r else None
def uid(): return str(uuid.uuid4())
def num(v, default=0.0):
    try: return float(v) if v not in (None, '') else default
    except (TypeError, ValueError): return default

def next_number(prefix, table):
    # Read through the request connection so numbers already used earlier in this
    # (uncommitted) request — e.g. several leftover-return rows on one delivery — are seen.
    with _number_lock:
        r = get_db().execute(f"SELECT MAX(CAST(SUBSTR(number,{len(prefix)+2}) AS INTEGER)) FROM {table} WHERE number LIKE ?",
                             (f'{prefix}-%',)).fetchone()
    return f'{prefix}-{str((r[0] or 0) + 1).zfill(4)}'

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users(
      id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'staff', active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS vendors(
      id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL,   -- cloth | stitch | both
      phone TEXT, address TEXT, gstin TEXT, notes TEXT, active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS cloths(
      id TEXT PRIMARY KEY, name TEXT NOT NULL, colour TEXT, unit TEXT DEFAULT 'm', notes TEXT,
      active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS products(
      id TEXT PRIMARY KEY, name TEXT NOT NULL, school TEXT, cloth_id TEXT REFERENCES cloths(id),
      cons_per_pc REAL DEFAULT 0, stitch_rate REAL DEFAULT 0, notes TEXT, active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);

    -- Order placed on the cloth vendor (vendor may supply more than needed because of MOQ)
    CREATE TABLE IF NOT EXISTS cloth_orders(
      id TEXT PRIMARY KEY, number TEXT UNIQUE, date TEXT, vendor_id TEXT REFERENCES vendors(id),
      notes TEXT, closed INTEGER DEFAULT 0, created_by TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS cloth_order_items(
      id TEXT PRIMARY KEY, order_id TEXT REFERENCES cloth_orders(id) ON DELETE CASCADE,
      cloth_id TEXT REFERENCES cloths(id), qty REAL, rate REAL);

    -- Cloth despatched by the cloth vendor against a cloth order, to a stitch vendor or to us
    CREATE TABLE IF NOT EXISTS cloth_despatches(
      id TEXT PRIMARY KEY, number TEXT UNIQUE, order_id TEXT REFERENCES cloth_orders(id),
      vendor_id TEXT REFERENCES vendors(id), cloth_id TEXT REFERENCES cloths(id),
      qty REAL, rate REAL, freight REAL DEFAULT 0, challan_no TEXT,
      dest TEXT NOT NULL,                -- 'self' or stitch vendor id
      despatch_date TEXT, received_date TEXT, notes TEXT, created_by TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);

    -- Order placed on the stitching vendor
    CREATE TABLE IF NOT EXISTS stitch_orders(
      id TEXT PRIMARY KEY, number TEXT UNIQUE, date TEXT, vendor_id TEXT REFERENCES vendors(id),
      due_date TEXT, notes TEXT, closed INTEGER DEFAULT 0, created_by TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS stitch_order_items(
      id TEXT PRIMARY KEY, order_id TEXT REFERENCES stitch_orders(id) ON DELETE CASCADE,
      product_id TEXT REFERENCES products(id), size TEXT, qty REAL, rate REAL,
      cloth_id TEXT REFERENCES cloths(id), cons_per_pc REAL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS stitch_charges(
      id TEXT PRIMARY KEY, order_id TEXT REFERENCES stitch_orders(id) ON DELETE CASCADE,
      date TEXT, head TEXT, amount REAL, notes TEXT);

    -- Finished goods despatched by stitch vendor to us
    CREATE TABLE IF NOT EXISTS stitch_deliveries(
      id TEXT PRIMARY KEY, number TEXT UNIQUE, order_id TEXT REFERENCES stitch_orders(id),
      vendor_id TEXT REFERENCES vendors(id), challan_no TEXT,
      despatch_date TEXT, received_date TEXT, notes TEXT, created_by TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS stitch_delivery_items(
      id TEXT PRIMARY KEY, delivery_id TEXT REFERENCES stitch_deliveries(id) ON DELETE CASCADE,
      order_item_id TEXT REFERENCES stitch_order_items(id), qty REAL, cloth_used REAL DEFAULT 0);

    -- Cloth moved between locations: us -> vendor, vendor -> us (leftover return), vendor -> vendor.
    -- delivery_id is set when leftover cloth came back along with a finished-goods despatch.
    CREATE TABLE IF NOT EXISTS cloth_transfers(
      id TEXT PRIMARY KEY, number TEXT UNIQUE, cloth_id TEXT REFERENCES cloths(id), qty REAL,
      from_loc TEXT NOT NULL, to_loc TEXT NOT NULL, stitch_order_id TEXT, delivery_id TEXT,
      despatch_date TEXT, received_date TEXT, notes TEXT, created_by TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);

    CREATE TABLE IF NOT EXISTS audit_log(
      id TEXT PRIMARY KEY, user_name TEXT, action TEXT, entity TEXT, entity_id TEXT, detail TEXT,
      at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        db.execute("INSERT INTO users(id,name,email,password,role) VALUES(?,?,?,?,?)",
                   (uid(), 'Admin', os.environ.get('ADMIN_EMAIL', 'admin@manishuniform.com').strip().lower(),
                    hash_pw(os.environ.get('ADMIN_PASSWORD', 'admin123')), 'admin'))
    db.commit(); db.close()

def require_auth(f):
    @wraps(f)
    def d(*a, **k):
        user = verify_token(request.headers.get('Authorization', '').replace('Bearer ', ''))
        if not user or user.get('type') == 'refresh': return jsonify({'error': 'Invalid token'}), 401
        g.user = user
        return f(*a, **k)
    return d

def require_admin(f):
    @wraps(f)
    def d(*a, **k):
        if g.user.get('role') != 'admin': return jsonify({'error': 'Admin only'}), 403
        return f(*a, **k)
    return d

def audit(action, entity, entity_id=None, detail=None):
    try:
        qw("INSERT INTO audit_log(id,user_name,action,entity,entity_id,detail) VALUES(?,?,?,?,?,?)",
           (uid(), g.user.get('name'), action, entity, entity_id, detail))
    except Exception:
        pass

def err(msg, code=400): return jsonify({'error': msg}), code

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.route('/api/auth/login', methods=['POST'])
def login():
    d = request.json or {}
    email = (d.get('email') or '').strip().lower()
    key = f"{request.headers.get('X-Forwarded-For', request.remote_addr)}|{email}"
    if _rate_limited(key): return err('Too many failed attempts. Try again in 15 minutes.', 429)
    u = one(q("SELECT * FROM users WHERE LOWER(email)=? AND active=1", (email,), one=True))
    if not u or u['password'] != hash_pw(d.get('password', '')):
        _login_attempts[key].append(time.time())
        return err('Invalid email or password', 401)
    _login_attempts.pop(key, None)
    p = {'id': u['id'], 'name': u['name'], 'email': u['email'], 'role': u['role']}
    return jsonify({'token': make_token(p), 'refresh_token': make_token({**p, 'type': 'refresh'}, 86400 * 30), 'user': p})

@app.route('/api/auth/refresh', methods=['POST'])
def refresh():
    p = verify_token((request.json or {}).get('refresh_token', ''))
    if not p or p.get('type') != 'refresh': return err('Invalid token', 401)
    u = one(q("SELECT * FROM users WHERE id=? AND active=1", (p['id'],), one=True))
    if not u: return err('Invalid token', 401)
    p = {'id': u['id'], 'name': u['name'], 'email': u['email'], 'role': u['role']}
    return jsonify({'token': make_token(p), 'user': p})

@app.route('/api/auth/password', methods=['POST'])
@require_auth
def change_password():
    d = request.json or {}
    u = one(q("SELECT * FROM users WHERE id=?", (g.user['id'],), one=True))
    if not u or u['password'] != hash_pw(d.get('old', '')): return err('Current password is wrong')
    if len(d.get('new', '')) < 6: return err('New password must be at least 6 characters')
    qw("UPDATE users SET password=? WHERE id=?", (hash_pw(d['new']), u['id']))
    return jsonify({'ok': True})

@app.route('/api/users')
@require_auth
@require_admin
def list_users():
    return jsonify(rows(q("SELECT id,name,email,role,active FROM users ORDER BY name")))

@app.route('/api/users', methods=['POST'])
@require_auth
@require_admin
def create_user():
    d = request.json or {}
    if not d.get('name') or not d.get('email') or len(d.get('password', '')) < 6:
        return err('Name, email and a 6+ character password are required')
    if q("SELECT 1 FROM users WHERE LOWER(email)=?", (d['email'].strip().lower(),), one=True):
        return err('Email already exists')
    i = uid()
    qw("INSERT INTO users(id,name,email,password,role) VALUES(?,?,?,?,?)",
       (i, d['name'].strip(), d['email'].strip().lower(), hash_pw(d['password']),
        'admin' if d.get('role') == 'admin' else 'staff'))
    audit('create', 'user', i, d['email'])
    return jsonify({'id': i})

@app.route('/api/users/<i>', methods=['PUT'])
@require_auth
@require_admin
def update_user(i):
    d = request.json or {}
    if i == g.user['id'] and (not d.get('active', 1) or d.get('role') != 'admin'):
        return err('You cannot disable or demote yourself')
    qw("UPDATE users SET name=?,role=?,active=? WHERE id=?",
       (d.get('name'), 'admin' if d.get('role') == 'admin' else 'staff', 1 if d.get('active', 1) else 0, i))
    if d.get('password'):
        if len(d['password']) < 6: return err('Password must be at least 6 characters')
        qw("UPDATE users SET password=? WHERE id=?", (hash_pw(d['password']), i))
    audit('update', 'user', i)
    return jsonify({'ok': True})

# ── MASTERS: vendors / cloths / products ──────────────────────────────────────
MASTERS = {
    'vendors':  ['name', 'type', 'phone', 'address', 'gstin', 'notes', 'active'],
    'cloths':   ['name', 'colour', 'unit', 'notes', 'active'],
    'products': ['name', 'school', 'cloth_id', 'cons_per_pc', 'stitch_rate', 'notes', 'active'],
}

def _clean_master(kind, d):
    vals = {}
    for c in MASTERS[kind]:
        v = d.get(c)
        if c in ('cons_per_pc', 'stitch_rate'): v = num(v)
        elif c == 'active': v = 0 if v in (0, False, '0') else 1
        elif isinstance(v, str): v = v.strip() or None
        vals[c] = v
    if not vals.get('name'): raise ValueError('Name is required')
    if kind == 'vendors' and vals.get('type') not in ('cloth', 'stitch', 'both'):
        raise ValueError('Vendor type must be cloth, stitch or both')
    if kind == 'cloths': vals['unit'] = vals.get('unit') or 'm'
    return vals

@app.route('/api/<kind>')
@require_auth
def list_master(kind):
    if kind not in MASTERS: return err('Not found', 404)
    return jsonify(rows(q(f"SELECT * FROM {kind} ORDER BY active DESC, name")))

@app.route('/api/<kind>', methods=['POST'])
@require_auth
def create_master(kind):
    if kind not in MASTERS: return err('Not found', 404)
    try: vals = _clean_master(kind, request.json or {})
    except ValueError as e: return err(str(e))
    i = uid(); cols = list(vals)
    qw(f"INSERT INTO {kind}(id,{','.join(cols)}) VALUES(?{',?' * len(cols)})", (i, *vals.values()))
    audit('create', kind, i, vals['name'])
    return jsonify({'id': i})

@app.route('/api/<kind>/<i>', methods=['PUT'])
@require_auth
def update_master(kind, i):
    if kind not in MASTERS: return err('Not found', 404)
    try: vals = _clean_master(kind, request.json or {})
    except ValueError as e: return err(str(e))
    qw(f"UPDATE {kind} SET {','.join(c + '=?' for c in vals)} WHERE id=?", (*vals.values(), i))
    audit('update', kind, i, vals['name'])
    return jsonify({'ok': True})

# ── CLOTH ORDERS (to cloth vendor) ────────────────────────────────────────────
def _cloth_order_items(order_id):
    return rows(q("""SELECT i.*, c.name cloth_name, c.colour, c.unit,
        (SELECT COALESCE(SUM(d.qty),0) FROM cloth_despatches d WHERE d.order_id=i.order_id AND d.cloth_id=i.cloth_id) despatched
        FROM cloth_order_items i JOIN cloths c ON c.id=i.cloth_id WHERE i.order_id=? ORDER BY c.name""", (order_id,)))

@app.route('/api/cloth-orders')
@require_auth
def list_cloth_orders():
    out = rows(q("""SELECT o.*, v.name vendor_name FROM cloth_orders o JOIN vendors v ON v.id=o.vendor_id
                    ORDER BY o.date DESC, o.number DESC"""))
    for o in out:
        o['items'] = _cloth_order_items(o['id'])
        o['qty'] = sum(i['qty'] for i in o['items'])
        o['amount'] = sum(i['qty'] * i['rate'] for i in o['items'])
        o['despatched'] = sum(i['despatched'] for i in o['items'])
    return jsonify(out)

@app.route('/api/cloth-orders/<i>')
@require_auth
def get_cloth_order(i):
    o = one(q("SELECT o.*, v.name vendor_name, v.phone vendor_phone, v.address vendor_address FROM cloth_orders o JOIN vendors v ON v.id=o.vendor_id WHERE o.id=?", (i,), one=True))
    if not o: return err('Not found', 404)
    o['items'] = _cloth_order_items(i)
    o['despatches'] = rows(q("""SELECT d.*, c.name cloth_name, c.unit, COALESCE(sv.name, 'Manish Uniform') dest_name
        FROM cloth_despatches d JOIN cloths c ON c.id=d.cloth_id LEFT JOIN vendors sv ON sv.id=d.dest
        WHERE d.order_id=? ORDER BY d.despatch_date, d.number""", (i,)))
    return jsonify(o)

def _save_cloth_order(i, d, is_new):
    items = [x for x in (d.get('items') or []) if x.get('cloth_id') and num(x.get('qty')) > 0]
    if not d.get('vendor_id') or not d.get('date'): raise ValueError('Vendor and date are required')
    if not items: raise ValueError('Add at least one cloth line')
    db = get_db()
    if is_new:
        db.execute("INSERT INTO cloth_orders(id,number,date,vendor_id,notes,created_by) VALUES(?,?,?,?,?,?)",
                   (i, next_number('CO', 'cloth_orders'), d['date'], d['vendor_id'], d.get('notes'), g.user['name']))
    else:
        db.execute("UPDATE cloth_orders SET date=?,vendor_id=?,notes=?,closed=? WHERE id=?",
                   (d['date'], d['vendor_id'], d.get('notes'), 1 if d.get('closed') else 0, i))
        db.execute("DELETE FROM cloth_order_items WHERE order_id=?", (i,))
    for x in items:
        db.execute("INSERT INTO cloth_order_items(id,order_id,cloth_id,qty,rate) VALUES(?,?,?,?,?)",
                   (uid(), i, x['cloth_id'], num(x['qty']), num(x.get('rate'))))

@app.route('/api/cloth-orders', methods=['POST'])
@require_auth
def create_cloth_order():
    i = uid()
    try: _save_cloth_order(i, request.json or {}, True)
    except ValueError as e: return err(str(e))
    audit('create', 'cloth_order', i)
    return jsonify({'id': i})

@app.route('/api/cloth-orders/<i>', methods=['PUT'])
@require_auth
def update_cloth_order(i):
    try: _save_cloth_order(i, request.json or {}, False)
    except ValueError as e: return err(str(e))
    audit('update', 'cloth_order', i)
    return jsonify({'ok': True})

@app.route('/api/cloth-orders/<i>', methods=['DELETE'])
@require_auth
@require_admin
def delete_cloth_order(i):
    if q("SELECT 1 FROM cloth_despatches WHERE order_id=?", (i,), one=True):
        return err('Delete the despatches of this order first')
    qw("DELETE FROM cloth_orders WHERE id=?", (i,))
    audit('delete', 'cloth_order', i)
    return jsonify({'ok': True})

# ── CLOTH DESPATCHES (cloth vendor -> stitch vendor / us) ─────────────────────
@app.route('/api/cloth-despatches')
@require_auth
def list_cloth_despatches():
    return jsonify(rows(q("""SELECT d.*, c.name cloth_name, c.colour, c.unit, v.name vendor_name, o.number order_number,
        COALESCE(sv.name, 'Manish Uniform') dest_name
        FROM cloth_despatches d JOIN cloths c ON c.id=d.cloth_id JOIN vendors v ON v.id=d.vendor_id
        LEFT JOIN cloth_orders o ON o.id=d.order_id LEFT JOIN vendors sv ON sv.id=d.dest
        ORDER BY d.despatch_date DESC, d.number DESC""")))

def _despatch_vals(d):
    if not d.get('cloth_id') or num(d.get('qty')) <= 0: raise ValueError('Cloth and quantity are required')
    if not d.get('despatch_date'): raise ValueError('Despatch date is required')
    if not d.get('dest'): raise ValueError('Choose where the cloth was sent')
    vendor_id = d.get('vendor_id')
    if d.get('order_id'):
        o = q("SELECT vendor_id FROM cloth_orders WHERE id=?", (d['order_id'],), one=True)
        if not o: raise ValueError('Cloth order not found')
        vendor_id = o['vendor_id']
    if not vendor_id: raise ValueError('Cloth vendor is required')
    return (d.get('order_id') or None, vendor_id, d['cloth_id'], num(d['qty']), num(d.get('rate')), num(d.get('freight')),
            d.get('challan_no'), d['dest'], d['despatch_date'], d.get('received_date') or None, d.get('notes'))

@app.route('/api/cloth-despatches', methods=['POST'])
@require_auth
def create_cloth_despatch():
    try: v = _despatch_vals(request.json or {})
    except ValueError as e: return err(str(e))
    i = uid()
    qw("""INSERT INTO cloth_despatches(id,number,order_id,vendor_id,cloth_id,qty,rate,freight,challan_no,dest,
          despatch_date,received_date,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
       (i, next_number('CD', 'cloth_despatches'), *v, g.user['name']))
    audit('create', 'cloth_despatch', i)
    return jsonify({'id': i})

@app.route('/api/cloth-despatches/<i>', methods=['PUT'])
@require_auth
def update_cloth_despatch(i):
    try: v = _despatch_vals(request.json or {})
    except ValueError as e: return err(str(e))
    qw("""UPDATE cloth_despatches SET order_id=?,vendor_id=?,cloth_id=?,qty=?,rate=?,freight=?,challan_no=?,dest=?,
          despatch_date=?,received_date=?,notes=? WHERE id=?""", (*v, i))
    audit('update', 'cloth_despatch', i)
    return jsonify({'ok': True})

@app.route('/api/cloth-despatches/<i>', methods=['DELETE'])
@require_auth
@require_admin
def delete_cloth_despatch(i):
    qw("DELETE FROM cloth_despatches WHERE id=?", (i,))
    audit('delete', 'cloth_despatch', i)
    return jsonify({'ok': True})

# ── CLOTH TRANSFERS (us <-> stitch vendor, vendor -> vendor) ──────────────────
@app.route('/api/cloth-transfers')
@require_auth
def list_cloth_transfers():
    return jsonify(rows(q("""SELECT t.*, c.name cloth_name, c.colour, c.unit,
        COALESCE(fv.name,'Manish Uniform') from_name, COALESCE(tv.name,'Manish Uniform') to_name,
        so.number stitch_order_number, sd.number delivery_number
        FROM cloth_transfers t JOIN cloths c ON c.id=t.cloth_id
        LEFT JOIN vendors fv ON fv.id=t.from_loc LEFT JOIN vendors tv ON tv.id=t.to_loc
        LEFT JOIN stitch_orders so ON so.id=t.stitch_order_id LEFT JOIN stitch_deliveries sd ON sd.id=t.delivery_id
        ORDER BY t.despatch_date DESC, t.number DESC""")))

def _transfer_vals(d):
    if not d.get('cloth_id') or num(d.get('qty')) <= 0: raise ValueError('Cloth and quantity are required')
    if not d.get('from_loc') or not d.get('to_loc') or d['from_loc'] == d['to_loc']:
        raise ValueError('Choose different From and To locations')
    if not d.get('despatch_date'): raise ValueError('Despatch date is required')
    return (d['cloth_id'], num(d['qty']), d['from_loc'], d['to_loc'], d.get('stitch_order_id') or None,
            d['despatch_date'], d.get('received_date') or None, d.get('notes'))

@app.route('/api/cloth-transfers', methods=['POST'])
@require_auth
def create_cloth_transfer():
    try: v = _transfer_vals(request.json or {})
    except ValueError as e: return err(str(e))
    i = uid()
    qw("""INSERT INTO cloth_transfers(id,number,cloth_id,qty,from_loc,to_loc,stitch_order_id,despatch_date,received_date,notes,created_by)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (i, next_number('CT', 'cloth_transfers'), *v, g.user['name']))
    audit('create', 'cloth_transfer', i)
    return jsonify({'id': i})

@app.route('/api/cloth-transfers/<i>', methods=['PUT'])
@require_auth
def update_cloth_transfer(i):
    try: v = _transfer_vals(request.json or {})
    except ValueError as e: return err(str(e))
    qw("""UPDATE cloth_transfers SET cloth_id=?,qty=?,from_loc=?,to_loc=?,stitch_order_id=?,despatch_date=?,
          received_date=?,notes=? WHERE id=?""", (*v, i))
    audit('update', 'cloth_transfer', i)
    return jsonify({'ok': True})

@app.route('/api/cloth-transfers/<i>', methods=['DELETE'])
@require_auth
@require_admin
def delete_cloth_transfer(i):
    qw("DELETE FROM cloth_transfers WHERE id=?", (i,))
    audit('delete', 'cloth_transfer', i)
    return jsonify({'ok': True})

# ── Mark received (quick action for despatch / transfer / delivery) ───────────
RECEIVABLE = {'cloth-despatches': 'cloth_despatches', 'cloth-transfers': 'cloth_transfers',
              'stitch-deliveries': 'stitch_deliveries'}

@app.route('/api/<kind>/<i>/received', methods=['POST'])
@require_auth
def mark_received(kind, i):
    if kind not in RECEIVABLE: return err('Not found', 404)
    dt = (request.json or {}).get('received_date') or date.today().isoformat()
    qw(f"UPDATE {RECEIVABLE[kind]} SET received_date=? WHERE id=?", (dt, i))
    if kind == 'stitch-deliveries':   # leftover cloth that travelled with the goods arrives with them
        qw("UPDATE cloth_transfers SET received_date=? WHERE delivery_id=?", (dt, i))
    audit('received', kind, i, dt)
    return jsonify({'ok': True})

# ── STITCH ORDERS (to stitching vendor) ───────────────────────────────────────
def _stitch_items(order_id):
    return rows(q("""SELECT i.*, p.name product_name, p.school, c.name cloth_name, c.unit,
        (SELECT COALESCE(SUM(di.qty),0) FROM stitch_delivery_items di JOIN stitch_deliveries d ON d.id=di.delivery_id
          WHERE di.order_item_id=i.id) delivered,
        (SELECT COALESCE(SUM(di.qty),0) FROM stitch_delivery_items di JOIN stitch_deliveries d ON d.id=di.delivery_id
          WHERE di.order_item_id=i.id AND d.received_date IS NOT NULL) received,
        (SELECT COALESCE(SUM(di.cloth_used),0) FROM stitch_delivery_items di WHERE di.order_item_id=i.id) cloth_used
        FROM stitch_order_items i JOIN products p ON p.id=i.product_id LEFT JOIN cloths c ON c.id=i.cloth_id
        WHERE i.order_id=? ORDER BY p.name, i.size""", (order_id,)))

@app.route('/api/stitch-orders')
@require_auth
def list_stitch_orders():
    out = rows(q("""SELECT o.*, v.name vendor_name FROM stitch_orders o JOIN vendors v ON v.id=o.vendor_id
                    ORDER BY o.date DESC, o.number DESC"""))
    for o in out:
        o['items'] = _stitch_items(o['id'])
        o['qty'] = sum(i['qty'] for i in o['items'])
        o['delivered'] = sum(i['delivered'] for i in o['items'])
        o['received'] = sum(i['received'] for i in o['items'])
    return jsonify(out)

@app.route('/api/stitch-orders/<i>')
@require_auth
def get_stitch_order(i):
    o = one(q("SELECT o.*, v.name vendor_name, v.phone vendor_phone, v.address vendor_address FROM stitch_orders o JOIN vendors v ON v.id=o.vendor_id WHERE o.id=?", (i,), one=True))
    if not o: return err('Not found', 404)
    o['items'] = _stitch_items(i)
    o['charges'] = rows(q("SELECT * FROM stitch_charges WHERE order_id=? ORDER BY date", (i,)))
    o['deliveries'] = _deliveries("WHERE d.order_id=?", (i,))
    o['transfers'] = rows(q("""SELECT t.*, c.name cloth_name, c.unit, COALESCE(fv.name,'Manish Uniform') from_name,
        COALESCE(tv.name,'Manish Uniform') to_name FROM cloth_transfers t JOIN cloths c ON c.id=t.cloth_id
        LEFT JOIN vendors fv ON fv.id=t.from_loc LEFT JOIN vendors tv ON tv.id=t.to_loc
        WHERE t.stitch_order_id=? ORDER BY t.despatch_date""", (i,)))
    o['costing'] = costing(order_id=i)
    return jsonify(o)

def _save_stitch_order(i, d, is_new):
    items = [x for x in (d.get('items') or []) if x.get('product_id') and num(x.get('qty')) > 0]
    charges = [x for x in (d.get('charges') or []) if num(x.get('amount')) != 0]
    if not d.get('vendor_id') or not d.get('date'): raise ValueError('Vendor and date are required')
    if not items: raise ValueError('Add at least one product line')
    db = get_db()
    if is_new:
        db.execute("INSERT INTO stitch_orders(id,number,date,vendor_id,due_date,notes,created_by) VALUES(?,?,?,?,?,?,?)",
                   (i, next_number('SO', 'stitch_orders'), d['date'], d['vendor_id'], d.get('due_date') or None,
                    d.get('notes'), g.user['name']))
    else:
        db.execute("UPDATE stitch_orders SET date=?,vendor_id=?,due_date=?,notes=?,closed=? WHERE id=?",
                   (d['date'], d['vendor_id'], d.get('due_date') or None, d.get('notes'), 1 if d.get('closed') else 0, i))
    # Lines already referenced by a delivery keep their id so delivery history stays linked.
    keep = set()
    for x in items:
        vals = (x['product_id'], (x.get('size') or '').strip() or None, num(x['qty']), num(x.get('rate')),
                x.get('cloth_id') or None, num(x.get('cons_per_pc')))
        if x.get('id') and db.execute("SELECT 1 FROM stitch_order_items WHERE id=? AND order_id=?", (x['id'], i)).fetchone():
            db.execute("UPDATE stitch_order_items SET product_id=?,size=?,qty=?,rate=?,cloth_id=?,cons_per_pc=? WHERE id=?", (*vals, x['id']))
            keep.add(x['id'])
        else:
            nid = uid(); keep.add(nid)
            db.execute("INSERT INTO stitch_order_items(id,order_id,product_id,size,qty,rate,cloth_id,cons_per_pc) VALUES(?,?,?,?,?,?,?,?)",
                       (nid, i, *vals))
    for r in db.execute("SELECT id FROM stitch_order_items WHERE order_id=?", (i,)).fetchall():
        if r['id'] not in keep:
            if db.execute("SELECT 1 FROM stitch_delivery_items WHERE order_item_id=?", (r['id'],)).fetchone():
                raise ValueError('A line that already has deliveries cannot be removed')
            db.execute("DELETE FROM stitch_order_items WHERE id=?", (r['id'],))
    db.execute("DELETE FROM stitch_charges WHERE order_id=?", (i,))
    for x in charges:
        db.execute("INSERT INTO stitch_charges(id,order_id,date,head,amount,notes) VALUES(?,?,?,?,?,?)",
                   (uid(), i, x.get('date') or d['date'], x.get('head') or 'Other', num(x['amount']), x.get('notes')))

@app.route('/api/stitch-orders', methods=['POST'])
@require_auth
def create_stitch_order():
    i = uid()
    try: _save_stitch_order(i, request.json or {}, True)
    except ValueError as e: get_db().rollback(); return err(str(e))
    audit('create', 'stitch_order', i)
    return jsonify({'id': i})

@app.route('/api/stitch-orders/<i>', methods=['PUT'])
@require_auth
def update_stitch_order(i):
    try: _save_stitch_order(i, request.json or {}, False)
    except ValueError as e: get_db().rollback(); return err(str(e))
    audit('update', 'stitch_order', i)
    return jsonify({'ok': True})

@app.route('/api/stitch-orders/<i>', methods=['DELETE'])
@require_auth
@require_admin
def delete_stitch_order(i):
    if q("SELECT 1 FROM stitch_deliveries WHERE order_id=?", (i,), one=True):
        return err('Delete the deliveries of this order first')
    qw("UPDATE cloth_transfers SET stitch_order_id=NULL WHERE stitch_order_id=?", (i,))
    qw("DELETE FROM stitch_orders WHERE id=?", (i,))
    audit('delete', 'stitch_order', i)
    return jsonify({'ok': True})

# ── STITCH DELIVERIES (stitch vendor -> us) ───────────────────────────────────
def _deliveries(where='', params=()):
    out = rows(q(f"""SELECT d.*, v.name vendor_name, o.number order_number FROM stitch_deliveries d
        JOIN vendors v ON v.id=d.vendor_id JOIN stitch_orders o ON o.id=d.order_id {where}
        ORDER BY d.despatch_date DESC, d.number DESC""", params))
    for d in out:
        d['items'] = rows(q("""SELECT di.*, p.name product_name, oi.size, c.name cloth_name, c.unit FROM stitch_delivery_items di
            JOIN stitch_order_items oi ON oi.id=di.order_item_id JOIN products p ON p.id=oi.product_id
            LEFT JOIN cloths c ON c.id=oi.cloth_id WHERE di.delivery_id=? ORDER BY p.name, oi.size""", (d['id'],)))
        d['returns'] = rows(q("""SELECT t.id, t.cloth_id, t.qty, c.name cloth_name, c.unit FROM cloth_transfers t
            JOIN cloths c ON c.id=t.cloth_id WHERE t.delivery_id=?""", (d['id'],)))
        d['qty'] = sum(x['qty'] for x in d['items'])
    return out

@app.route('/api/stitch-deliveries')
@require_auth
def list_stitch_deliveries():
    return jsonify(_deliveries())

def _save_delivery(i, d, is_new):
    o = q("SELECT * FROM stitch_orders WHERE id=?", (d.get('order_id'),), one=True)
    if not o: raise ValueError('Choose the stitch order')
    if not d.get('despatch_date'): raise ValueError('Despatch date is required')
    items = [x for x in (d.get('items') or []) if x.get('order_item_id') and num(x.get('qty')) > 0]
    returns = [x for x in (d.get('returns') or []) if x.get('cloth_id') and num(x.get('qty')) > 0]
    if not items and not returns: raise ValueError('Enter pieces received or cloth returned')
    db = get_db()
    if is_new:
        db.execute("""INSERT INTO stitch_deliveries(id,number,order_id,vendor_id,challan_no,despatch_date,received_date,notes,created_by)
                      VALUES(?,?,?,?,?,?,?,?,?)""",
                   (i, next_number('SD', 'stitch_deliveries'), o['id'], o['vendor_id'], d.get('challan_no'),
                    d['despatch_date'], d.get('received_date') or None, d.get('notes'), g.user['name']))
    else:
        db.execute("""UPDATE stitch_deliveries SET challan_no=?,despatch_date=?,received_date=?,notes=? WHERE id=?""",
                   (d.get('challan_no'), d['despatch_date'], d.get('received_date') or None, d.get('notes'), i))
        db.execute("DELETE FROM stitch_delivery_items WHERE delivery_id=?", (i,))
        db.execute("DELETE FROM cloth_transfers WHERE delivery_id=?", (i,))
    for x in items:
        if not db.execute("SELECT 1 FROM stitch_order_items WHERE id=? AND order_id=?", (x['order_item_id'], o['id'])).fetchone():
            raise ValueError('Line does not belong to this order')
        db.execute("INSERT INTO stitch_delivery_items(id,delivery_id,order_item_id,qty,cloth_used) VALUES(?,?,?,?,?)",
                   (uid(), i, x['order_item_id'], num(x['qty']), num(x.get('cloth_used'))))
    for x in returns:
        db.execute("""INSERT INTO cloth_transfers(id,number,cloth_id,qty,from_loc,to_loc,stitch_order_id,delivery_id,
                      despatch_date,received_date,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (uid(), next_number('CT', 'cloth_transfers'), x['cloth_id'], num(x['qty']), o['vendor_id'], SELF,
                    o['id'], i, d['despatch_date'], d.get('received_date') or None, 'Leftover returned with goods',
                    g.user['name']))

@app.route('/api/stitch-deliveries', methods=['POST'])
@require_auth
def create_stitch_delivery():
    i = uid()
    try: _save_delivery(i, request.json or {}, True)
    except ValueError as e: get_db().rollback(); return err(str(e))
    audit('create', 'stitch_delivery', i)
    return jsonify({'id': i})

@app.route('/api/stitch-deliveries/<i>', methods=['PUT'])
@require_auth
def update_stitch_delivery(i):
    try: _save_delivery(i, request.json or {}, False)
    except ValueError as e: get_db().rollback(); return err(str(e))
    audit('update', 'stitch_delivery', i)
    return jsonify({'ok': True})

@app.route('/api/stitch-deliveries/<i>', methods=['DELETE'])
@require_auth
@require_admin
def delete_stitch_delivery(i):
    qw("DELETE FROM cloth_transfers WHERE delivery_id=?", (i,))
    qw("DELETE FROM stitch_deliveries WHERE id=?", (i,))
    audit('delete', 'stitch_delivery', i)
    return jsonify({'ok': True})

# ── STOCK ─────────────────────────────────────────────────────────────────────
def cloth_rates():
    """Weighted average landed cost per cloth = (qty*rate + freight) / qty over all despatches."""
    return {r['cloth_id']: (r['amt'] / r['qty'] if r['qty'] else 0) for r in
            q("SELECT cloth_id, SUM(qty) qty, SUM(qty*rate + COALESCE(freight,0)) amt FROM cloth_despatches GROUP BY cloth_id")}

def stock_positions():
    """{(loc, cloth_id): {'in','out','used','stock','transit'}}.
    Cloth enters a location only once received; it leaves the sender on despatch, so cloth on the
    road shows as 'transit' at the destination."""
    pos = collections.defaultdict(lambda: {'in': 0.0, 'out': 0.0, 'used': 0.0, 'transit': 0.0})
    for r in q("SELECT dest loc, cloth_id, qty, received_date FROM cloth_despatches"):
        pos[(r['loc'], r['cloth_id'])]['in' if r['received_date'] else 'transit'] += r['qty']
    for r in q("SELECT from_loc, to_loc, cloth_id, qty, received_date FROM cloth_transfers"):
        pos[(r['from_loc'], r['cloth_id'])]['out'] += r['qty']
        pos[(r['to_loc'], r['cloth_id'])]['in' if r['received_date'] else 'transit'] += r['qty']
    for r in q("""SELECT d.vendor_id loc, oi.cloth_id, SUM(di.cloth_used) used FROM stitch_delivery_items di
                  JOIN stitch_deliveries d ON d.id=di.delivery_id JOIN stitch_order_items oi ON oi.id=di.order_item_id
                  WHERE oi.cloth_id IS NOT NULL GROUP BY d.vendor_id, oi.cloth_id"""):
        pos[(r['loc'], r['cloth_id'])]['used'] += r['used'] or 0
    for p in pos.values():
        p['stock'] = round(p['in'] - p['out'] - p['used'], 3)
    return pos

@app.route('/api/stock')
@require_auth
def stock():
    rates = cloth_rates()
    cloths = {r['id']: dict(r) for r in q("SELECT * FROM cloths")}
    vendors = {r['id']: r['name'] for r in q("SELECT id,name FROM vendors")}
    locs = collections.OrderedDict()
    for (loc, cid), p in sorted(stock_positions().items(), key=lambda kv: (kv[0][0] != SELF, vendors.get(kv[0][0], ''))):
        if abs(p['stock']) < 0.0005 and abs(p['transit']) < 0.0005: continue
        c = cloths.get(cid, {})
        L = locs.setdefault(loc, {'loc': loc, 'name': 'Manish Uniform (own stock)' if loc == SELF else vendors.get(loc, '?'),
                                  'lines': [], 'value': 0.0})
        rate = rates.get(cid, 0)
        L['lines'].append({'cloth_id': cid, 'cloth_name': c.get('name'), 'colour': c.get('colour'), 'unit': c.get('unit', 'm'),
                           **{k: round(v, 3) for k, v in p.items()}, 'rate': round(rate, 2), 'value': round(p['stock'] * rate, 2)})
        L['value'] += p['stock'] * rate
    # pending from cloth vendors: ordered but not yet despatched
    pending = rows(q("""SELECT o.number, o.date, v.name vendor_name, c.name cloth_name, c.unit, i.qty,
        (SELECT COALESCE(SUM(d.qty),0) FROM cloth_despatches d WHERE d.order_id=o.id AND d.cloth_id=i.cloth_id) despatched
        FROM cloth_order_items i JOIN cloth_orders o ON o.id=i.order_id JOIN vendors v ON v.id=o.vendor_id
        JOIN cloths c ON c.id=i.cloth_id WHERE o.closed=0 ORDER BY o.date"""))
    pending = [p for p in pending if p['qty'] - p['despatched'] > 0.0005]
    # finished goods received by us, per product/size
    goods = rows(q("""SELECT p.name product_name, p.school, oi.size, SUM(di.qty) qty FROM stitch_delivery_items di
        JOIN stitch_deliveries d ON d.id=di.delivery_id JOIN stitch_order_items oi ON oi.id=di.order_item_id
        JOIN products p ON p.id=oi.product_id WHERE d.received_date IS NOT NULL
        GROUP BY p.id, oi.size ORDER BY p.name, oi.size"""))
    return jsonify({'locations': list(locs.values()), 'pending_from_vendors': pending, 'goods_received': goods})

# ── COSTING ───────────────────────────────────────────────────────────────────
def costing(order_id=None):
    """Average manufacturing cost per piece.
    Per stitch-order line: cloth cost = cloth used x weighted avg landed cloth rate,
    stitching = pieces x stitch rate, other charges of the order split by pieces delivered."""
    rates = cloth_rates()
    where, params = ('WHERE o.id=?', (order_id,)) if order_id else ('', ())
    lines = rows(q(f"""SELECT oi.id, oi.order_id, oi.product_id, p.name product_name, p.school, oi.size, oi.rate, oi.cloth_id,
        o.number order_number, v.name vendor_name,
        COALESCE(SUM(di.qty),0) pcs, COALESCE(SUM(di.cloth_used),0) cloth_used
        FROM stitch_order_items oi JOIN stitch_orders o ON o.id=oi.order_id JOIN vendors v ON v.id=o.vendor_id
        JOIN products p ON p.id=oi.product_id LEFT JOIN stitch_delivery_items di ON di.order_item_id=oi.id
        {where} GROUP BY oi.id""", params))
    charges = {r['order_id']: r['amt'] for r in q("SELECT order_id, SUM(amount) amt FROM stitch_charges GROUP BY order_id")}
    order_pcs = collections.defaultdict(float)
    for l in lines: order_pcs[l['order_id']] += l['pcs']
    for l in lines:
        crate = rates.get(l['cloth_id'], 0)
        l['cloth_rate'] = round(crate, 2)
        l['cloth_cost'] = l['cloth_used'] * crate
        l['stitch_cost'] = l['pcs'] * (l['rate'] or 0)
        op = order_pcs[l['order_id']]
        l['other_cost'] = charges.get(l['order_id'], 0) * (l['pcs'] / op) if op else 0
        l['total'] = l['cloth_cost'] + l['stitch_cost'] + l['other_cost']
        l['avg'] = l['total'] / l['pcs'] if l['pcs'] else 0
    by_product = collections.OrderedDict()
    for l in sorted(lines, key=lambda x: (x['product_name'], x['size'] or '')):
        k = (l['product_id'], l['size'] or '')
        b = by_product.setdefault(k, {'product_name': l['product_name'], 'school': l['school'], 'size': l['size'],
                                      'pcs': 0, 'cloth_used': 0, 'cloth_cost': 0, 'stitch_cost': 0, 'other_cost': 0, 'total': 0})
        for f in ('pcs', 'cloth_used', 'cloth_cost', 'stitch_cost', 'other_cost', 'total'): b[f] += l[f]
    prods = list(by_product.values())
    for b in prods: b['avg'] = b['total'] / b['pcs'] if b['pcs'] else 0
    tot = {f: sum(l[f] for l in lines) for f in ('pcs', 'cloth_used', 'cloth_cost', 'stitch_cost', 'other_cost', 'total')}
    tot['unallocated_charges'] = sum(v for k, v in charges.items() if not order_pcs.get(k) and (not order_id or k == order_id))
    tot['avg'] = tot['total'] / tot['pcs'] if tot['pcs'] else 0
    return {'lines': [l for l in lines if l['pcs']], 'products': [p for p in prods if p['pcs']], 'total': tot}

@app.route('/api/costing')
@require_auth
def costing_api():
    return jsonify(costing())

# ── DASHBOARD ─────────────────────────────────────────────────────────────────
@app.route('/api/dashboard')
@require_auth
def dashboard():
    pos = stock_positions()
    self_stock = sum(p['stock'] for (loc, _), p in pos.items() if loc == SELF)
    vendor_stock = sum(p['stock'] for (loc, _), p in pos.items() if loc != SELF)
    transit = sum(p['transit'] for p in pos.values())
    so = q("""SELECT COUNT(*) n, COALESCE(SUM(qty),0) qty FROM stitch_order_items i JOIN stitch_orders o ON o.id=i.order_id WHERE o.closed=0""", one=True)
    delivered = q("""SELECT COALESCE(SUM(di.qty),0) d FROM stitch_delivery_items di JOIN stitch_order_items i ON i.id=di.order_item_id
                     JOIN stitch_orders o ON o.id=i.order_id WHERE o.closed=0""", one=True)['d']
    open_orders = q("SELECT COUNT(*) FROM stitch_orders WHERE closed=0", one=True)[0]
    goods_transit = q("""SELECT COALESCE(SUM(di.qty),0) FROM stitch_delivery_items di JOIN stitch_deliveries d ON d.id=di.delivery_id
                         WHERE d.received_date IS NULL""", one=True)[0]
    overdue = rows(q("""SELECT o.id, o.number, o.due_date, v.name vendor_name FROM stitch_orders o JOIN vendors v ON v.id=o.vendor_id
                        WHERE o.closed=0 AND o.due_date IS NOT NULL AND o.due_date < ? ORDER BY o.due_date""", (date.today().isoformat(),)))
    awaiting = []
    for r in q("""SELECT 'cloth-despatches' kind, d.id, d.number, d.despatch_date, c.name || ' · ' || d.qty || ' ' || c.unit what,
                  v.name || ' → ' || COALESCE(sv.name,'Manish Uniform') route FROM cloth_despatches d JOIN cloths c ON c.id=d.cloth_id
                  JOIN vendors v ON v.id=d.vendor_id LEFT JOIN vendors sv ON sv.id=d.dest WHERE d.received_date IS NULL
                  UNION ALL
                  SELECT 'cloth-transfers', t.id, t.number, t.despatch_date, c.name || ' · ' || t.qty || ' ' || c.unit,
                  COALESCE(fv.name,'Manish Uniform') || ' → ' || COALESCE(tv.name,'Manish Uniform') FROM cloth_transfers t
                  JOIN cloths c ON c.id=t.cloth_id LEFT JOIN vendors fv ON fv.id=t.from_loc LEFT JOIN vendors tv ON tv.id=t.to_loc
                  WHERE t.received_date IS NULL AND t.delivery_id IS NULL
                  UNION ALL
                  SELECT 'stitch-deliveries', d.id, d.number, d.despatch_date, 'Goods against ' || o.number,
                  v.name || ' → Manish Uniform' FROM stitch_deliveries d JOIN stitch_orders o ON o.id=d.order_id
                  JOIN vendors v ON v.id=d.vendor_id WHERE d.received_date IS NULL
                  ORDER BY 4"""):
        awaiting.append(dict(r))
    c = costing()['total']
    return jsonify({'self_stock': round(self_stock, 2), 'vendor_stock': round(vendor_stock, 2), 'transit': round(transit, 2),
                    'open_orders': open_orders, 'ordered_pcs': so['qty'], 'pending_pcs': max(so['qty'] - delivered, 0),
                    'goods_transit': goods_transit, 'overdue': overdue, 'awaiting': awaiting,
                    'avg_cost': c['avg'], 'pcs_made': c['pcs'], 'total_cost': c['total']})

@app.route('/api/meta')
@require_auth
def meta():
    return jsonify({'charge_heads': CHARGE_HEADS, 'today': date.today().isoformat()})

@app.route('/api/health')
def health():
    q("SELECT 1", one=True)
    return jsonify({'ok': True})

@app.route('/')
def index(): return app.send_static_file('index.html')

# ── backups ───────────────────────────────────────────────────────────────────
def run_backup():
    try:
        dest = os.path.join(BACKUP_DIR, f"manish_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
        src = sqlite3.connect(DB_PATH); dst = sqlite3.connect(dest)
        src.backup(dst); dst.close(); src.close()
        cutoff = time.time() - BACKUP_KEEP_DAYS * 86400
        for f in os.listdir(BACKUP_DIR):
            fp = os.path.join(BACKUP_DIR, f)
            if os.path.isfile(fp) and os.path.getmtime(fp) < cutoff: os.remove(fp)
        print(f'[Backup] Saved {dest}')
    except Exception as e:
        print(f'[Backup] WARNING: backup failed — {e}')

def schedule_daily_backup():
    def _loop():
        while True:
            run_backup(); time.sleep(86400)
    threading.Thread(target=_loop, daemon=True).start()

init_db()

if __name__ == '__main__':
    schedule_daily_backup()
    print(f"\n  Manish Uniform\n  http://localhost:{PORT}\n  Data: {DATA_DIR}\n")
    try:
        from waitress import serve
        serve(app, host='0.0.0.0', port=PORT, threads=8)
    except ImportError:
        app.run(host='0.0.0.0', port=PORT, debug=False)
