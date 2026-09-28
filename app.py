#!/usr/bin/env python3
"""Manish Uniform — school-uniform stitching job-work tracker.

Flow: school order -> stitch order(s) on tailors -> cloth order(s) on cloth vendors
(one cloth order can cover several stitch orders) -> cloth despatched to a tailor or to us
-> tailor despatches finished goods (and leftover cloth) back to us.
Cloth stock is tracked per location ('self' = Manish Uniform, or a tailor's vendor id).
"""
import sqlite3, os, sys, json, hashlib, hmac, base64, time, uuid, shutil, threading, collections, secrets
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
os.makedirs(BACKUP_DIR, exist_ok=True)

def _jwt_secret():
    """JWT_SECRET from env, else a random one generated once and kept beside the database,
    so a fresh deploy never runs on a guessable default."""
    if os.environ.get('JWT_SECRET'): return os.environ['JWT_SECRET']
    path = os.path.join(DATA_DIR, '.jwt_secret')
    if not os.path.exists(path):
        with open(path, 'w') as f: f.write(secrets.token_hex(32))
    with open(path) as f: return f.read().strip()
JWT_SECRET = _jwt_secret()
PORT = int(os.environ.get('PORT', 5004))
BACKUP_KEEP_DAYS = int(os.environ.get('BACKUP_KEEP_DAYS', 30))

SCHEMA_VERSION = 2
SELF = 'self'   # location code for Manish Uniform's own godown
CHARGE_HEADS = ['Transport', 'Buttons', 'Labels', 'Thread', 'Packing', 'Other']
STD_WIDTH = 58  # inches — the width the standard size chart is worked out for

def _chart(sizes, small, large):
    """Linear consumption from the smallest to the largest size, rounded to 5 cm."""
    n = len(sizes)
    return [(str(s), round((small + (large - small) * i / max(n - 1, 1)) * 20) / 20) for i, s in enumerate(sizes)]
EVEN = lambda a, b: list(range(a, b + 1, 2))
# Starting estimates at 58" cloth width — meant to be corrected to the tailor's actual figures.
# (name, default stitching rate, scales with cloth width?, size chart)
STD_ITEMS = [
    ('Shirt (Half Sleeve)',  0, 1, _chart(EVEN(20, 44), 0.70, 1.40)),
    ('Shirt (Full Sleeve)',  0, 1, _chart(EVEN(20, 44), 0.85, 1.65)),
    ('Trouser / Pant',       0, 1, _chart(EVEN(20, 42), 0.60, 1.25)),
    ('Half Pant / Shorts',   0, 1, _chart(EVEN(10, 20), 0.30, 0.60)),
    ('Skirt',                0, 1, _chart(EVEN(12, 26), 0.45, 1.05)),
    ('Divided Skirt',        0, 1, _chart(EVEN(12, 26), 0.60, 1.30)),
    ('Tunic / Pinafore',     0, 1, _chart(EVEN(22, 40), 0.70, 1.40)),
    ('Frock',                0, 1, _chart(EVEN(18, 32), 0.70, 1.40)),
    ('Kurta / Kameez',       0, 1, _chart(EVEN(28, 44), 1.00, 1.70)),
    ('Salwar',               0, 1, _chart(EVEN(28, 42), 1.00, 1.60)),
    ('Dupatta',              0, 0, [('Free', 2.25)]),
    ('Blazer',               0, 1, _chart(EVEN(22, 44), 0.90, 1.80)),
    ('Waistcoat / Vest',     0, 1, _chart(EVEN(22, 40), 0.50, 0.95)),
    ('T-Shirt',              0, 1, _chart(EVEN(20, 44), 0.55, 1.10)),
    ('Track Pant',           0, 1, _chart(EVEN(20, 42), 0.60, 1.25)),
    ('Tie',                  0, 0, [('Free', 0.10)]),
]

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
def txt(v):
    v = (v or '').strip() if isinstance(v, str) else v
    return v or None

def next_number(prefix, table):
    # Read through the request connection so numbers already used earlier in this
    # (uncommitted) request — e.g. several leftover-return rows on one delivery — are seen.
    with _number_lock:
        r = get_db().execute(f"SELECT MAX(CAST(SUBSTR(number,{len(prefix)+2}) AS INTEGER)) FROM {table} WHERE number LIKE ?",
                             (f'{prefix}-%',)).fetchone()
    return f'{prefix}-{str((r[0] or 0) + 1).zfill(4)}'

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'staff', active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS vendors(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL,   -- cloth | stitch | both
  phone TEXT, address TEXT, gstin TEXT, notes TEXT, active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS schools(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, contact TEXT, phone TEXT, address TEXT, notes TEXT,
  active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS cloths(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, colour TEXT, unit TEXT DEFAULT 'm', width REAL DEFAULT 58,
  notes TEXT, active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);

-- Uniform item types (Shirt, Skirt, ...) with a size chart of cloth needed per piece
CREATE TABLE IF NOT EXISTS items(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, stitch_rate REAL DEFAULT 0,
  base_width REAL DEFAULT 58,        -- cloth width the size chart is written for (inches)
  width_scaling INTEGER DEFAULT 1,   -- 1: narrower cloth needs proportionally more metres
  sort INTEGER DEFAULT 999, notes TEXT, active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS item_sizes(
  id TEXT PRIMARY KEY, item_id TEXT REFERENCES items(id) ON DELETE CASCADE,
  size TEXT NOT NULL, cons REAL DEFAULT 0, sort INTEGER DEFAULT 0);

-- Order received from a school
CREATE TABLE IF NOT EXISTS school_orders(
  id TEXT PRIMARY KEY, number TEXT UNIQUE, school_id TEXT REFERENCES schools(id), date TEXT,
  due_date TEXT, ref TEXT, notes TEXT, closed INTEGER DEFAULT 0, created_by TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS school_order_items(
  id TEXT PRIMARY KEY, order_id TEXT REFERENCES school_orders(id) ON DELETE CASCADE,
  item_id TEXT REFERENCES items(id), size TEXT, qty REAL);

-- Order placed on the cloth vendor (vendor may supply more than needed because of MOQ)
CREATE TABLE IF NOT EXISTS cloth_orders(
  id TEXT PRIMARY KEY, number TEXT UNIQUE, date TEXT, vendor_id TEXT REFERENCES vendors(id),
  notes TEXT, closed INTEGER DEFAULT 0, created_by TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS cloth_order_items(
  id TEXT PRIMARY KEY, order_id TEXT REFERENCES cloth_orders(id) ON DELETE CASCADE,
  cloth_id TEXT REFERENCES cloths(id), qty REAL, rate REAL, width REAL);
-- which stitch orders a cloth order is meant for (many-to-many)
CREATE TABLE IF NOT EXISTS cloth_order_links(
  cloth_order_id TEXT REFERENCES cloth_orders(id) ON DELETE CASCADE,
  stitch_order_id TEXT REFERENCES stitch_orders(id) ON DELETE CASCADE,
  PRIMARY KEY(cloth_order_id, stitch_order_id));

-- Cloth despatched by the cloth vendor, to a tailor or to us. amount = the bill value.
CREATE TABLE IF NOT EXISTS cloth_despatches(
  id TEXT PRIMARY KEY, number TEXT UNIQUE, order_id TEXT REFERENCES cloth_orders(id),
  vendor_id TEXT REFERENCES vendors(id), cloth_id TEXT REFERENCES cloths(id),
  qty REAL, rate REAL, amount REAL, freight REAL DEFAULT 0, challan_no TEXT,
  dest TEXT NOT NULL,                -- 'self' or tailor vendor id
  despatch_date TEXT, received_date TEXT, notes TEXT, created_by TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);

-- Order placed on the tailor
CREATE TABLE IF NOT EXISTS stitch_orders(
  id TEXT PRIMARY KEY, number TEXT UNIQUE, date TEXT, vendor_id TEXT REFERENCES vendors(id),
  school_order_id TEXT REFERENCES school_orders(id),
  due_date TEXT, notes TEXT, closed INTEGER DEFAULT 0, created_by TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS stitch_order_items(
  id TEXT PRIMARY KEY, order_id TEXT REFERENCES stitch_orders(id) ON DELETE CASCADE,
  item_id TEXT REFERENCES items(id), school_id TEXT REFERENCES schools(id),
  school_order_item_id TEXT, size TEXT, qty REAL, rate REAL,
  cloth_id TEXT REFERENCES cloths(id), width REAL, cons_per_pc REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS stitch_charges(
  id TEXT PRIMARY KEY, order_id TEXT REFERENCES stitch_orders(id) ON DELETE CASCADE,
  date TEXT, head TEXT, amount REAL, notes TEXT);
-- Tailor's bill; when present it replaces pieces x rate as the stitching cost of the order
CREATE TABLE IF NOT EXISTS stitch_bills(
  id TEXT PRIMARY KEY, order_id TEXT REFERENCES stitch_orders(id) ON DELETE CASCADE,
  bill_no TEXT, date TEXT, amount REAL, notes TEXT, created_by TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);

-- Finished goods despatched by the tailor to us
CREATE TABLE IF NOT EXISTS stitch_deliveries(
  id TEXT PRIMARY KEY, number TEXT UNIQUE, order_id TEXT REFERENCES stitch_orders(id),
  vendor_id TEXT REFERENCES vendors(id), challan_no TEXT,
  despatch_date TEXT, received_date TEXT, notes TEXT, created_by TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS stitch_delivery_items(
  id TEXT PRIMARY KEY, delivery_id TEXT REFERENCES stitch_deliveries(id) ON DELETE CASCADE,
  order_item_id TEXT REFERENCES stitch_order_items(id), qty REAL, cloth_used REAL DEFAULT 0);

-- Cloth moved between locations: us -> tailor, tailor -> us (leftover), tailor -> tailor.
-- delivery_id is set when leftover cloth came back along with a finished-goods despatch.
CREATE TABLE IF NOT EXISTS cloth_transfers(
  id TEXT PRIMARY KEY, number TEXT UNIQUE, cloth_id TEXT REFERENCES cloths(id), qty REAL,
  from_loc TEXT NOT NULL, to_loc TEXT NOT NULL, stitch_order_id TEXT, delivery_id TEXT,
  despatch_date TEXT, received_date TEXT, notes TEXT, created_by TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS audit_log(
  id TEXT PRIMARY KEY, user_name TEXT, action TEXT, entity TEXT, entity_id TEXT, detail TEXT,
  at TEXT DEFAULT CURRENT_TIMESTAMP);
"""

def init_db():
    # v1 held test data only; it is set aside (users are kept) rather than migrated.
    old_users = []
    if os.path.exists(DB_PATH):
        db = sqlite3.connect(DB_PATH)
        ver = db.execute("PRAGMA user_version").fetchone()[0]
        if ver < SCHEMA_VERSION and db.execute("SELECT 1 FROM sqlite_master WHERE name='users'").fetchone():
            old_users = db.execute("SELECT id,name,email,password,role,active FROM users").fetchall()
            db.close()
            dest = os.path.join(BACKUP_DIR, f"pre_v{SCHEMA_VERSION}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
            shutil.move(DB_PATH, dest)
            for ext in ('-wal', '-shm'):
                if os.path.exists(DB_PATH + ext): os.remove(DB_PATH + ext)
            print(f'[Setup] Old test database moved to {dest}; users carried over', flush=True)
        else:
            db.close()
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    for u in old_users:
        db.execute("INSERT OR IGNORE INTO users(id,name,email,password,role,active) VALUES(?,?,?,?,?,?)", u)
    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        email = os.environ.get('ADMIN_EMAIL', 'admin@manishuniform.com').strip().lower()
        pw = os.environ.get('ADMIN_PASSWORD')
        if not pw:
            # Hosted: never seed a known password. Printed once so it can be read from the deploy log.
            pw = secrets.token_urlsafe(9) if os.environ.get('RAILWAY_ENVIRONMENT') else 'admin123'
            print(f'[Setup] First admin login: {email} / {pw}  (change it after signing in)', flush=True)
        db.execute("INSERT INTO users(id,name,email,password,role) VALUES(?,?,?,?,?)",
                   (uid(), 'Admin', email, hash_pw(pw), 'admin'))
    if not db.execute("SELECT 1 FROM items LIMIT 1").fetchone():
        for n, (name, rate, scaling, chart) in enumerate(STD_ITEMS):
            iid = uid()
            db.execute("INSERT INTO items(id,name,stitch_rate,base_width,width_scaling,sort) VALUES(?,?,?,?,?,?)",
                       (iid, name, rate, STD_WIDTH, scaling, n))
            for k, (size, cons) in enumerate(chart):
                db.execute("INSERT INTO item_sizes(id,item_id,size,cons,sort) VALUES(?,?,?,?,?)", (uid(), iid, size, cons, k))
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

class Invalid(ValueError): pass

def saving(fn):
    """Run a save inside the request transaction; roll back and return 400 on Invalid."""
    @wraps(fn)
    def d(*a, **k):
        try:
            return fn(*a, **k)
        except Invalid as e:
            get_db().rollback()
            return err(str(e))
    return d

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

# ── MASTERS: vendors / schools / cloths ───────────────────────────────────────
MASTERS = {
    'vendors': ['name', 'type', 'phone', 'address', 'gstin', 'notes', 'active'],
    'schools': ['name', 'contact', 'phone', 'address', 'notes', 'active'],
    'cloths':  ['name', 'colour', 'unit', 'width', 'notes', 'active'],
}

def _clean_master(kind, d):
    vals = {}
    for c in MASTERS[kind]:
        v = d.get(c)
        if c == 'width': v = num(v, STD_WIDTH) or STD_WIDTH
        elif c == 'active': v = 0 if v in (0, False, '0') else 1
        else: v = txt(v)
        vals[c] = v
    if not vals.get('name'): raise Invalid('Name is required')
    if kind == 'vendors' and vals.get('type') not in ('cloth', 'stitch', 'both'):
        raise Invalid('Vendor type must be cloth, stitch or both')
    if kind == 'cloths': vals['unit'] = vals.get('unit') or 'm'
    dup = q(f"SELECT id FROM {kind} WHERE LOWER(name)=LOWER(?) AND id<>?", (vals['name'], d.get('id') or ''), one=True)
    if dup and kind != 'cloths': raise Invalid(f'"{vals["name"]}" already exists')
    return vals

@app.route('/api/m/<kind>')
@require_auth
def list_master(kind):
    if kind not in MASTERS: return err('Not found', 404)
    return jsonify(rows(q(f"SELECT * FROM {kind} ORDER BY active DESC, name")))

@app.route('/api/m/<kind>', methods=['POST'])
@require_auth
@saving
def create_master(kind):
    if kind not in MASTERS: return err('Not found', 404)
    vals = _clean_master(kind, request.json or {})
    i = uid(); cols = list(vals)
    qw(f"INSERT INTO {kind}(id,{','.join(cols)}) VALUES(?{',?' * len(cols)})", (i, *vals.values()))
    audit('create', kind, i, vals['name'])
    return jsonify({'id': i})

@app.route('/api/m/<kind>/<i>', methods=['PUT'])
@require_auth
@saving
def update_master(kind, i):
    if kind not in MASTERS: return err('Not found', 404)
    vals = _clean_master(kind, {**(request.json or {}), 'id': i})
    qw(f"UPDATE {kind} SET {','.join(c + '=?' for c in vals)} WHERE id=?", (*vals.values(), i))
    audit('update', kind, i, vals['name'])
    return jsonify({'ok': True})

# ── ITEMS (uniform item types + size chart) ───────────────────────────────────
@app.route('/api/items')
@require_auth
def list_items():
    items = rows(q("SELECT * FROM items ORDER BY active DESC, sort, name"))
    sizes = collections.defaultdict(list)
    for s in q("SELECT * FROM item_sizes ORDER BY sort"):
        sizes[s['item_id']].append({'id': s['id'], 'size': s['size'], 'cons': s['cons']})
    for it in items: it['sizes'] = sizes[it['id']]
    return jsonify(items)

def _save_item(i, d, is_new):
    name = txt(d.get('name'))
    if not name: raise Invalid('Name is required')
    if q("SELECT 1 FROM items WHERE LOWER(name)=LOWER(?) AND id<>?", (name, i), one=True):
        raise Invalid(f'"{name}" already exists')
    vals = (name, num(d.get('stitch_rate')), num(d.get('base_width'), STD_WIDTH) or STD_WIDTH,
            0 if d.get('width_scaling') in (0, False, '0') else 1, txt(d.get('notes')),
            0 if d.get('active') in (0, False, '0') else 1)
    db = get_db()
    if is_new:
        sort = (q("SELECT MAX(sort) FROM items", one=True)[0] or 0) + 1
        db.execute("INSERT INTO items(id,name,stitch_rate,base_width,width_scaling,notes,active,sort) VALUES(?,?,?,?,?,?,?,?)",
                   (i, *vals, sort))
    else:
        db.execute("UPDATE items SET name=?,stitch_rate=?,base_width=?,width_scaling=?,notes=?,active=? WHERE id=?", (*vals, i))
    if 'sizes' in d:
        db.execute("DELETE FROM item_sizes WHERE item_id=?", (i,))
        seen = set()
        for k, s in enumerate(d.get('sizes') or []):
            size = txt(str(s.get('size') or ''))
            if not size or size.lower() in seen: continue
            seen.add(size.lower())
            db.execute("INSERT INTO item_sizes(id,item_id,size,cons,sort) VALUES(?,?,?,?,?)", (uid(), i, size, num(s.get('cons')), k))

@app.route('/api/items', methods=['POST'])
@require_auth
@saving
def create_item():
    i = uid(); _save_item(i, request.json or {}, True)
    audit('create', 'item', i)
    return jsonify({'id': i})

@app.route('/api/items/<i>', methods=['PUT'])
@require_auth
@saving
def update_item(i):
    _save_item(i, request.json or {}, False)
    audit('update', 'item', i)
    return jsonify({'ok': True})

@app.route('/api/line-defaults')
@require_auth
def line_defaults():
    """Most recent cloth / width / rate used for each item, per school and overall —
    so a new stitch order line starts with what was used last time."""
    out = {'by_school': {}, 'by_item': {}}
    for r in q("""SELECT i.item_id, i.school_id, i.cloth_id, i.width, i.rate FROM stitch_order_items i
                  JOIN stitch_orders o ON o.id=i.order_id ORDER BY o.date, o.created_at"""):
        v = {'cloth_id': r['cloth_id'], 'width': r['width'], 'rate': r['rate']}
        out['by_item'][r['item_id']] = v
        if r['school_id']: out['by_school'][f"{r['item_id']}|{r['school_id']}"] = v
    return jsonify(out)

# ── SCHOOL ORDERS ─────────────────────────────────────────────────────────────
def _school_items(order_id):
    return rows(q("""SELECT si.*, it.name item_name, it.sort item_sort,
        (SELECT COALESCE(SUM(oi.qty),0) FROM stitch_order_items oi WHERE oi.school_order_item_id=si.id) stitch_ordered,
        (SELECT COALESCE(SUM(di.qty),0) FROM stitch_delivery_items di JOIN stitch_order_items oi ON oi.id=di.order_item_id
           JOIN stitch_deliveries d ON d.id=di.delivery_id WHERE oi.school_order_item_id=si.id AND d.received_date IS NOT NULL) received
        FROM school_order_items si JOIN items it ON it.id=si.item_id
        LEFT JOIN item_sizes sz ON sz.item_id=si.item_id AND sz.size=si.size
        WHERE si.order_id=? ORDER BY it.sort, it.name, COALESCE(sz.sort, 999), si.size""", (order_id,)))

def _school_totals(o):
    o['qty'] = sum(i['qty'] for i in o['items'])
    o['stitch_ordered'] = sum(min(i['stitch_ordered'], i['qty']) for i in o['items'])
    o['received'] = sum(min(i['received'], i['qty']) for i in o['items'])
    return o

@app.route('/api/school-orders')
@require_auth
def list_school_orders():
    out = rows(q("""SELECT o.*, s.name school_name FROM school_orders o JOIN schools s ON s.id=o.school_id
                    ORDER BY o.date DESC, o.number DESC"""))
    for o in out:
        o['items'] = _school_items(o['id']); _school_totals(o)
    return jsonify(out)

@app.route('/api/school-orders/<i>')
@require_auth
def get_school_order(i):
    o = one(q("SELECT o.*, s.name school_name FROM school_orders o JOIN schools s ON s.id=o.school_id WHERE o.id=?", (i,), one=True))
    if not o: return err('Not found', 404)
    o['items'] = _school_items(i); _school_totals(o)
    o['stitch_orders'] = rows(q("""SELECT so.id, so.number, so.date, v.name vendor_name,
        (SELECT COALESCE(SUM(qty),0) FROM stitch_order_items WHERE order_id=so.id) qty
        FROM stitch_orders so JOIN vendors v ON v.id=so.vendor_id
        WHERE so.school_order_id=? OR so.id IN (SELECT oi.order_id FROM stitch_order_items oi
          JOIN school_order_items si ON si.id=oi.school_order_item_id WHERE si.order_id=?) ORDER BY so.date""", (i, i)))
    return jsonify(o)

def _upsert_lines(db, table, order_id, lines, cols, guard_sql, guard_msg):
    """Save order lines, keeping the ids of lines that already exist so rows that point
    at them (deliveries, stitch lines) stay linked. Lines that disappear are deleted
    unless guard_sql finds something depending on them."""
    keep = set()
    for x in lines:
        vals = tuple(x[c] for c in cols)
        if x.get('id') and db.execute(f"SELECT 1 FROM {table} WHERE id=? AND order_id=?", (x['id'], order_id)).fetchone():
            db.execute(f"UPDATE {table} SET {','.join(c + '=?' for c in cols)} WHERE id=?", (*vals, x['id']))
            keep.add(x['id'])
        else:
            nid = uid(); keep.add(nid)
            db.execute(f"INSERT INTO {table}(id,order_id,{','.join(cols)}) VALUES(?,?{',?' * len(cols)})", (nid, order_id, *vals))
    for r in db.execute(f"SELECT id FROM {table} WHERE order_id=?", (order_id,)).fetchall():
        if r[0] not in keep:
            if db.execute(guard_sql, (r[0],)).fetchone(): raise Invalid(guard_msg)
            db.execute(f"DELETE FROM {table} WHERE id=?", (r[0],))

def _save_school_order(i, d, is_new):
    if not d.get('school_id') or not d.get('date'): raise Invalid('School and date are required')
    lines = [{'id': x.get('id'), 'item_id': x['item_id'], 'size': txt(str(x.get('size') or '')), 'qty': num(x['qty'])}
             for x in (d.get('items') or []) if x.get('item_id') and num(x.get('qty')) > 0]
    if not lines: raise Invalid('Enter at least one item with quantity')
    db = get_db()
    if is_new:
        db.execute("INSERT INTO school_orders(id,number,school_id,date,due_date,ref,notes,created_by) VALUES(?,?,?,?,?,?,?,?)",
                   (i, next_number('SCH', 'school_orders'), d['school_id'], d['date'], d.get('due_date') or None,
                    txt(d.get('ref')), txt(d.get('notes')), g.user['name']))
    else:
        db.execute("UPDATE school_orders SET school_id=?,date=?,due_date=?,ref=?,notes=?,closed=? WHERE id=?",
                   (d['school_id'], d['date'], d.get('due_date') or None, txt(d.get('ref')), txt(d.get('notes')),
                    1 if d.get('closed') else 0, i))
    _upsert_lines(db, 'school_order_items', i, lines, ('item_id', 'size', 'qty'),
                  "SELECT 1 FROM stitch_order_items WHERE school_order_item_id=?",
                  'A size already given to a tailor cannot be removed — set its quantity instead')

@app.route('/api/school-orders', methods=['POST'])
@require_auth
@saving
def create_school_order():
    i = uid(); _save_school_order(i, request.json or {}, True)
    audit('create', 'school_order', i)
    return jsonify({'id': i})

@app.route('/api/school-orders/<i>', methods=['PUT'])
@require_auth
@saving
def update_school_order(i):
    _save_school_order(i, request.json or {}, False)
    audit('update', 'school_order', i)
    return jsonify({'ok': True})

@app.route('/api/school-orders/<i>', methods=['DELETE'])
@require_auth
@require_admin
def delete_school_order(i):
    if q("""SELECT 1 FROM stitch_order_items oi JOIN school_order_items si ON si.id=oi.school_order_item_id
            WHERE si.order_id=?""", (i,), one=True) or q("SELECT 1 FROM stitch_orders WHERE school_order_id=?", (i,), one=True):
        return err('Delete the stitch orders made from this school order first')
    qw("DELETE FROM school_orders WHERE id=?", (i,))
    audit('delete', 'school_order', i)
    return jsonify({'ok': True})

# ── CLOTH ORDERS (to cloth vendor) ────────────────────────────────────────────
def _cloth_order_items(order_id):
    return rows(q("""SELECT i.*, c.name cloth_name, c.colour, c.unit,
        (SELECT COALESCE(SUM(d.qty),0) FROM cloth_despatches d WHERE d.order_id=i.order_id AND d.cloth_id=i.cloth_id) despatched
        FROM cloth_order_items i JOIN cloths c ON c.id=i.cloth_id WHERE i.order_id=? ORDER BY c.name""", (order_id,)))

def _linked_stitch(cloth_order_id):
    return rows(q("""SELECT so.id, so.number, so.date, v.name vendor_name FROM cloth_order_links l
        JOIN stitch_orders so ON so.id=l.stitch_order_id JOIN vendors v ON v.id=so.vendor_id
        WHERE l.cloth_order_id=? ORDER BY so.date""", (cloth_order_id,)))

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
        o['stitch_orders'] = _linked_stitch(o['id'])
    return jsonify(out)

@app.route('/api/cloth-orders/<i>')
@require_auth
def get_cloth_order(i):
    o = one(q("SELECT o.*, v.name vendor_name, v.phone vendor_phone, v.address vendor_address FROM cloth_orders o JOIN vendors v ON v.id=o.vendor_id WHERE o.id=?", (i,), one=True))
    if not o: return err('Not found', 404)
    o['items'] = _cloth_order_items(i)
    o['stitch_orders'] = _linked_stitch(i)
    o['requirement'] = requirement([s['id'] for s in o['stitch_orders']])
    o['despatches'] = rows(q("""SELECT d.*, c.name cloth_name, c.unit, COALESCE(sv.name, 'Manish Uniform') dest_name
        FROM cloth_despatches d JOIN cloths c ON c.id=d.cloth_id LEFT JOIN vendors sv ON sv.id=d.dest
        WHERE d.order_id=? ORDER BY d.despatch_date, d.number""", (i,)))
    return jsonify(o)

def _save_cloth_order(i, d, is_new):
    items = [x for x in (d.get('items') or []) if x.get('cloth_id') and num(x.get('qty')) > 0]
    if not d.get('vendor_id') or not d.get('date'): raise Invalid('Vendor and date are required')
    if not items: raise Invalid('Add at least one cloth line')
    db = get_db()
    if is_new:
        db.execute("INSERT INTO cloth_orders(id,number,date,vendor_id,notes,created_by) VALUES(?,?,?,?,?,?)",
                   (i, next_number('CO', 'cloth_orders'), d['date'], d['vendor_id'], txt(d.get('notes')), g.user['name']))
    else:
        db.execute("UPDATE cloth_orders SET date=?,vendor_id=?,notes=?,closed=? WHERE id=?",
                   (d['date'], d['vendor_id'], txt(d.get('notes')), 1 if d.get('closed') else 0, i))
        db.execute("DELETE FROM cloth_order_items WHERE order_id=?", (i,))
    for x in items:
        db.execute("INSERT INTO cloth_order_items(id,order_id,cloth_id,qty,rate,width) VALUES(?,?,?,?,?,?)",
                   (uid(), i, x['cloth_id'], num(x['qty']), num(x.get('rate')), num(x.get('width')) or None))
    if 'stitch_order_ids' in d:
        db.execute("DELETE FROM cloth_order_links WHERE cloth_order_id=?", (i,))
        for sid in set(d.get('stitch_order_ids') or []):
            db.execute("INSERT OR IGNORE INTO cloth_order_links(cloth_order_id,stitch_order_id) VALUES(?,?)", (i, sid))

@app.route('/api/cloth-orders', methods=['POST'])
@require_auth
@saving
def create_cloth_order():
    i = uid(); _save_cloth_order(i, request.json or {}, True)
    audit('create', 'cloth_order', i)
    return jsonify({'id': i})

@app.route('/api/cloth-orders/<i>', methods=['PUT'])
@require_auth
@saving
def update_cloth_order(i):
    _save_cloth_order(i, request.json or {}, False)
    audit('update', 'cloth_order', i)
    return jsonify({'ok': True})

@app.route('/api/cloth-orders/<i>/links', methods=['POST'])
@require_auth
def link_cloth_order(i):
    sid = (request.json or {}).get('stitch_order_id')
    if not sid: return err('Choose a stitch order')
    if (request.json or {}).get('remove'):
        qw("DELETE FROM cloth_order_links WHERE cloth_order_id=? AND stitch_order_id=?", (i, sid))
    else:
        qw("INSERT OR IGNORE INTO cloth_order_links(cloth_order_id,stitch_order_id) VALUES(?,?)", (i, sid))
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

# ── CLOTH DESPATCHES (cloth vendor -> tailor / us) ────────────────────────────
@app.route('/api/cloth-despatches')
@require_auth
def list_cloth_despatches():
    return jsonify(rows(q("""SELECT d.*, c.name cloth_name, c.colour, c.unit, v.name vendor_name, o.number order_number,
        COALESCE(sv.name, 'Manish Uniform') dest_name
        FROM cloth_despatches d JOIN cloths c ON c.id=d.cloth_id JOIN vendors v ON v.id=d.vendor_id
        LEFT JOIN cloth_orders o ON o.id=d.order_id LEFT JOIN vendors sv ON sv.id=d.dest
        ORDER BY d.despatch_date DESC, d.number DESC""")))

def _despatch_vals(d):
    qty = num(d.get('qty'))
    if not d.get('cloth_id') or qty <= 0: raise Invalid('Cloth and quantity are required')
    if not d.get('despatch_date'): raise Invalid('Despatch date is required')
    if not d.get('dest'): raise Invalid('Choose where the cloth was sent')
    vendor_id = d.get('vendor_id')
    if d.get('order_id'):
        o = q("SELECT vendor_id FROM cloth_orders WHERE id=?", (d['order_id'],), one=True)
        if not o: raise Invalid('Cloth order not found')
        vendor_id = o['vendor_id']
    if not vendor_id: raise Invalid('Cloth vendor is required')
    # Either a rate or the bill total may be entered; the bill total wins when given.
    amount = num(d.get('amount')) if d.get('amount') not in (None, '') else qty * num(d.get('rate'))
    rate = amount / qty
    return (d.get('order_id') or None, vendor_id, d['cloth_id'], qty, rate, amount, num(d.get('freight')),
            txt(d.get('challan_no')), d['dest'], d['despatch_date'], d.get('received_date') or None, txt(d.get('notes')))

@app.route('/api/cloth-despatches', methods=['POST'])
@require_auth
@saving
def create_cloth_despatch():
    v = _despatch_vals(request.json or {})
    i = uid()
    qw("""INSERT INTO cloth_despatches(id,number,order_id,vendor_id,cloth_id,qty,rate,amount,freight,challan_no,dest,
          despatch_date,received_date,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
       (i, next_number('CD', 'cloth_despatches'), *v, g.user['name']))
    audit('create', 'cloth_despatch', i)
    return jsonify({'id': i})

@app.route('/api/cloth-despatches/<i>', methods=['PUT'])
@require_auth
@saving
def update_cloth_despatch(i):
    v = _despatch_vals(request.json or {})
    qw("""UPDATE cloth_despatches SET order_id=?,vendor_id=?,cloth_id=?,qty=?,rate=?,amount=?,freight=?,challan_no=?,dest=?,
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

# ── CLOTH TRANSFERS (us <-> tailor, tailor -> tailor) ─────────────────────────
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
    if not d.get('cloth_id') or num(d.get('qty')) <= 0: raise Invalid('Cloth and quantity are required')
    if not d.get('from_loc') or not d.get('to_loc') or d['from_loc'] == d['to_loc']:
        raise Invalid('Choose different From and To locations')
    if not d.get('despatch_date'): raise Invalid('Despatch date is required')
    return (d['cloth_id'], num(d['qty']), d['from_loc'], d['to_loc'], d.get('stitch_order_id') or None,
            d['despatch_date'], d.get('received_date') or None, txt(d.get('notes')))

@app.route('/api/cloth-transfers', methods=['POST'])
@require_auth
@saving
def create_cloth_transfer():
    v = _transfer_vals(request.json or {})
    i = uid()
    qw("""INSERT INTO cloth_transfers(id,number,cloth_id,qty,from_loc,to_loc,stitch_order_id,despatch_date,received_date,notes,created_by)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (i, next_number('CT', 'cloth_transfers'), *v, g.user['name']))
    audit('create', 'cloth_transfer', i)
    return jsonify({'id': i})

@app.route('/api/cloth-transfers/<i>', methods=['PUT'])
@require_auth
@saving
def update_cloth_transfer(i):
    v = _transfer_vals(request.json or {})
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

# ── STITCH ORDERS (to tailor) ─────────────────────────────────────────────────
ITEM_LINE_SQL = """SELECT i.*, it.name item_name, it.sort item_sort, sc.name school_name, c.name cloth_name, c.unit,
    (SELECT COALESCE(SUM(di.qty),0) FROM stitch_delivery_items di WHERE di.order_item_id=i.id) delivered,
    (SELECT COALESCE(SUM(di.qty),0) FROM stitch_delivery_items di JOIN stitch_deliveries d ON d.id=di.delivery_id
      WHERE di.order_item_id=i.id AND d.received_date IS NOT NULL) received,
    (SELECT COALESCE(SUM(di.cloth_used),0) FROM stitch_delivery_items di WHERE di.order_item_id=i.id) cloth_used
    FROM stitch_order_items i JOIN items it ON it.id=i.item_id LEFT JOIN schools sc ON sc.id=i.school_id
    LEFT JOIN cloths c ON c.id=i.cloth_id LEFT JOIN item_sizes sz ON sz.item_id=i.item_id AND sz.size=i.size"""

def _stitch_items(order_id):
    return rows(q(ITEM_LINE_SQL + " WHERE i.order_id=? ORDER BY sc.name, it.sort, it.name, COALESCE(sz.sort,999), i.size", (order_id,)))

def _order_schools(items):
    return ', '.join(sorted({i['school_name'] for i in items if i.get('school_name')}))

@app.route('/api/stitch-orders')
@require_auth
def list_stitch_orders():
    out = rows(q("""SELECT o.*, v.name vendor_name, so.number school_order_number FROM stitch_orders o
                    JOIN vendors v ON v.id=o.vendor_id LEFT JOIN school_orders so ON so.id=o.school_order_id
                    ORDER BY o.date DESC, o.number DESC"""))
    for o in out:
        o['items'] = _stitch_items(o['id'])
        o['qty'] = sum(i['qty'] for i in o['items'])
        o['delivered'] = sum(i['delivered'] for i in o['items'])
        o['received'] = sum(i['received'] for i in o['items'])
        o['schools'] = _order_schools(o['items'])
    return jsonify(out)

@app.route('/api/stitch-orders/<i>')
@require_auth
def get_stitch_order(i):
    o = one(q("""SELECT o.*, v.name vendor_name, v.phone vendor_phone, v.address vendor_address, so.number school_order_number
                 FROM stitch_orders o JOIN vendors v ON v.id=o.vendor_id LEFT JOIN school_orders so ON so.id=o.school_order_id
                 WHERE o.id=?""", (i,), one=True))
    if not o: return err('Not found', 404)
    o['items'] = _stitch_items(i)
    o['schools'] = _order_schools(o['items'])
    o['charges'] = rows(q("SELECT * FROM stitch_charges WHERE order_id=? ORDER BY date", (i,)))
    o['bills'] = rows(q("SELECT * FROM stitch_bills WHERE order_id=? ORDER BY date", (i,)))
    o['deliveries'] = _deliveries("WHERE d.order_id=?", (i,))
    o['transfers'] = rows(q("""SELECT t.*, c.name cloth_name, c.unit, COALESCE(fv.name,'Manish Uniform') from_name,
        COALESCE(tv.name,'Manish Uniform') to_name FROM cloth_transfers t JOIN cloths c ON c.id=t.cloth_id
        LEFT JOIN vendors fv ON fv.id=t.from_loc LEFT JOIN vendors tv ON tv.id=t.to_loc
        WHERE t.stitch_order_id=? ORDER BY t.despatch_date""", (i,)))
    o['cloth_orders'] = rows(q("""SELECT co.id, co.number, co.date, v.name vendor_name FROM cloth_order_links l
        JOIN cloth_orders co ON co.id=l.cloth_order_id JOIN vendors v ON v.id=co.vendor_id
        WHERE l.stitch_order_id=? ORDER BY co.date""", (i,)))
    o['requirement'] = requirement([i])
    o['costing'] = costing(order_id=i)
    return jsonify(o)

def _save_stitch_order(i, d, is_new):
    if not d.get('vendor_id') or not d.get('date'): raise Invalid('Tailor and date are required')
    lines = []
    for x in d.get('items') or []:
        if not x.get('item_id') or num(x.get('qty')) <= 0: continue
        lines.append({'id': x.get('id'), 'item_id': x['item_id'], 'school_id': x.get('school_id') or None,
                      'school_order_item_id': x.get('school_order_item_id') or None,
                      'size': txt(str(x.get('size') or '')), 'qty': num(x['qty']), 'rate': num(x.get('rate')),
                      'cloth_id': x.get('cloth_id') or None, 'width': num(x.get('width')) or None,
                      'cons_per_pc': num(x.get('cons_per_pc'))})
    if not lines: raise Invalid('Enter at least one item with pieces')
    charges = [x for x in (d.get('charges') or []) if num(x.get('amount')) != 0]
    db = get_db()
    if is_new:
        db.execute("INSERT INTO stitch_orders(id,number,date,vendor_id,school_order_id,due_date,notes,created_by) VALUES(?,?,?,?,?,?,?,?)",
                   (i, next_number('SO', 'stitch_orders'), d['date'], d['vendor_id'], d.get('school_order_id') or None,
                    d.get('due_date') or None, txt(d.get('notes')), g.user['name']))
    else:
        db.execute("UPDATE stitch_orders SET date=?,vendor_id=?,school_order_id=?,due_date=?,notes=?,closed=? WHERE id=?",
                   (d['date'], d['vendor_id'], d.get('school_order_id') or None, d.get('due_date') or None,
                    txt(d.get('notes')), 1 if d.get('closed') else 0, i))
    _upsert_lines(db, 'stitch_order_items', i, lines,
                  ('item_id', 'school_id', 'school_order_item_id', 'size', 'qty', 'rate', 'cloth_id', 'width', 'cons_per_pc'),
                  "SELECT 1 FROM stitch_delivery_items WHERE order_item_id=?",
                  'A line that already has goods received cannot be removed')
    db.execute("DELETE FROM stitch_charges WHERE order_id=?", (i,))
    for x in charges:
        db.execute("INSERT INTO stitch_charges(id,order_id,date,head,amount,notes) VALUES(?,?,?,?,?,?)",
                   (uid(), i, x.get('date') or d['date'], x.get('head') or 'Other', num(x['amount']), txt(x.get('notes'))))

@app.route('/api/stitch-orders', methods=['POST'])
@require_auth
@saving
def create_stitch_order():
    i = uid(); _save_stitch_order(i, request.json or {}, True)
    audit('create', 'stitch_order', i)
    return jsonify({'id': i})

@app.route('/api/stitch-orders/<i>', methods=['PUT'])
@require_auth
@saving
def update_stitch_order(i):
    _save_stitch_order(i, request.json or {}, False)
    audit('update', 'stitch_order', i)
    return jsonify({'ok': True})

@app.route('/api/stitch-orders/<i>', methods=['DELETE'])
@require_auth
@require_admin
def delete_stitch_order(i):
    if q("SELECT 1 FROM stitch_deliveries WHERE order_id=?", (i,), one=True):
        return err('Delete the goods-received entries of this order first')
    qw("UPDATE cloth_transfers SET stitch_order_id=NULL WHERE stitch_order_id=?", (i,))
    qw("DELETE FROM stitch_orders WHERE id=?", (i,))
    audit('delete', 'stitch_order', i)
    return jsonify({'ok': True})

# tailor bills
@app.route('/api/stitch-orders/<i>/bills', methods=['POST'])
@require_auth
def add_stitch_bill(i):
    d = request.json or {}
    if num(d.get('amount')) <= 0 or not d.get('date'): return err('Bill date and amount are required')
    b = uid()
    qw("INSERT INTO stitch_bills(id,order_id,bill_no,date,amount,notes,created_by) VALUES(?,?,?,?,?,?,?)",
       (b, i, txt(d.get('bill_no')), d['date'], num(d['amount']), txt(d.get('notes')), g.user['name']))
    audit('create', 'stitch_bill', b)
    return jsonify({'id': b})

@app.route('/api/stitch-bills/<b>', methods=['PUT'])
@require_auth
def update_stitch_bill(b):
    d = request.json or {}
    if num(d.get('amount')) <= 0 or not d.get('date'): return err('Bill date and amount are required')
    qw("UPDATE stitch_bills SET bill_no=?,date=?,amount=?,notes=? WHERE id=?",
       (txt(d.get('bill_no')), d['date'], num(d['amount']), txt(d.get('notes')), b))
    audit('update', 'stitch_bill', b)
    return jsonify({'ok': True})

@app.route('/api/stitch-bills/<b>', methods=['DELETE'])
@require_auth
def delete_stitch_bill(b):
    qw("DELETE FROM stitch_bills WHERE id=?", (b,))
    audit('delete', 'stitch_bill', b)
    return jsonify({'ok': True})

# ── STITCH DELIVERIES (tailor -> us) ──────────────────────────────────────────
def _deliveries(where='', params=()):
    out = rows(q(f"""SELECT d.*, v.name vendor_name, o.number order_number FROM stitch_deliveries d
        JOIN vendors v ON v.id=d.vendor_id JOIN stitch_orders o ON o.id=d.order_id {where}
        ORDER BY d.despatch_date DESC, d.number DESC""", params))
    for d in out:
        d['items'] = rows(q("""SELECT di.*, it.name item_name, oi.size, sc.name school_name, c.name cloth_name, c.unit
            FROM stitch_delivery_items di JOIN stitch_order_items oi ON oi.id=di.order_item_id
            JOIN items it ON it.id=oi.item_id LEFT JOIN schools sc ON sc.id=oi.school_id
            LEFT JOIN cloths c ON c.id=oi.cloth_id WHERE di.delivery_id=? ORDER BY it.sort, oi.size""", (d['id'],)))
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
    if not o: raise Invalid('Choose the stitch order')
    if not d.get('despatch_date'): raise Invalid('Despatch date is required')
    items = [x for x in (d.get('items') or []) if x.get('order_item_id') and num(x.get('qty')) > 0]
    returns = [x for x in (d.get('returns') or []) if x.get('cloth_id') and num(x.get('qty')) > 0]
    if not items and not returns: raise Invalid('Enter pieces received or cloth returned')
    db = get_db()
    if is_new:
        db.execute("""INSERT INTO stitch_deliveries(id,number,order_id,vendor_id,challan_no,despatch_date,received_date,notes,created_by)
                      VALUES(?,?,?,?,?,?,?,?,?)""",
                   (i, next_number('SD', 'stitch_deliveries'), o['id'], o['vendor_id'], txt(d.get('challan_no')),
                    d['despatch_date'], d.get('received_date') or None, txt(d.get('notes')), g.user['name']))
    else:
        db.execute("UPDATE stitch_deliveries SET challan_no=?,despatch_date=?,received_date=?,notes=? WHERE id=?",
                   (txt(d.get('challan_no')), d['despatch_date'], d.get('received_date') or None, txt(d.get('notes')), i))
        db.execute("DELETE FROM stitch_delivery_items WHERE delivery_id=?", (i,))
        db.execute("DELETE FROM cloth_transfers WHERE delivery_id=?", (i,))
    for x in items:
        if not db.execute("SELECT 1 FROM stitch_order_items WHERE id=? AND order_id=?", (x['order_item_id'], o['id'])).fetchone():
            raise Invalid('Line does not belong to this order')
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
@saving
def create_stitch_delivery():
    i = uid(); _save_delivery(i, request.json or {}, True)
    audit('create', 'stitch_delivery', i)
    return jsonify({'id': i})

@app.route('/api/stitch-deliveries/<i>', methods=['PUT'])
@require_auth
@saving
def update_stitch_delivery(i):
    _save_delivery(i, request.json or {}, False)
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
    """Weighted average landed cost per cloth = (bill amount + freight) / qty over all despatches."""
    return {r['cloth_id']: (r['amt'] / r['qty'] if r['qty'] else 0) for r in
            q("""SELECT cloth_id, SUM(qty) qty, SUM(COALESCE(amount, qty*rate) + COALESCE(freight,0)) amt
                 FROM cloth_despatches GROUP BY cloth_id""")}

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
    pending = rows(q("""SELECT o.number, o.date, v.name vendor_name, c.name cloth_name, c.unit, i.qty,
        (SELECT COALESCE(SUM(d.qty),0) FROM cloth_despatches d WHERE d.order_id=o.id AND d.cloth_id=i.cloth_id) despatched
        FROM cloth_order_items i JOIN cloth_orders o ON o.id=i.order_id JOIN vendors v ON v.id=o.vendor_id
        JOIN cloths c ON c.id=i.cloth_id WHERE o.closed=0 ORDER BY o.date"""))
    pending = [p for p in pending if p['qty'] - p['despatched'] > 0.0005]
    goods = rows(q("""SELECT it.name item_name, sc.name school_name, oi.size, SUM(di.qty) qty FROM stitch_delivery_items di
        JOIN stitch_deliveries d ON d.id=di.delivery_id JOIN stitch_order_items oi ON oi.id=di.order_item_id
        JOIN items it ON it.id=oi.item_id LEFT JOIN schools sc ON sc.id=oi.school_id
        LEFT JOIN item_sizes sz ON sz.item_id=oi.item_id AND sz.size=oi.size WHERE d.received_date IS NOT NULL
        GROUP BY oi.item_id, oi.school_id, oi.size ORDER BY sc.name, it.sort, COALESCE(sz.sort,999)"""))
    return jsonify({'locations': list(locs.values()), 'pending_from_vendors': pending, 'goods_received': goods})

# ── MATERIAL REQUIREMENT ──────────────────────────────────────────────────────
REMAINING_SQL = """MAX(i.qty - (SELECT COALESCE(SUM(di.qty),0) FROM stitch_delivery_items di
                   WHERE di.order_item_id=i.id), 0) * i.cons_per_pc"""

def requirement(stitch_order_ids, exclude_cloth_order=None):
    """Cloth still to be ordered to finish the given stitch orders, per cloth:

        to_order = to_finish - free_at_tailor - on_order

    to_finish      : metres for the pieces not yet received (pieces left x cloth per piece)
    free_at_tailor : cloth with / on the way to these orders' tailors, less what the same
                     tailors' other open orders still need of it
    on_order       : still to be despatched on cloth orders linked to these stitch orders
                     (leaving out exclude_cloth_order — the one being edited)
    in_godown      : your own stock, which could be sent instead of ordering"""
    if not stitch_order_ids: return []
    ph = ','.join('?' * len(stitch_order_ids))
    need = rows(q(f"""SELECT i.cloth_id, c.name cloth_name, c.unit, SUM(i.qty*i.cons_per_pc) required,
        SUM({REMAINING_SQL}) to_finish
        FROM stitch_order_items i JOIN cloths c ON c.id=i.cloth_id WHERE i.order_id IN ({ph}) AND i.cloth_id IS NOT NULL
        GROUP BY i.cloth_id ORDER BY c.name""", stitch_order_ids))
    tailors = [r[0] for r in q(f"SELECT DISTINCT vendor_id FROM stitch_orders WHERE id IN ({ph})", stitch_order_ids)]
    tph = ','.join('?' * len(tailors))
    other = {r['cloth_id']: r['need'] or 0 for r in q(f"""SELECT i.cloth_id, SUM({REMAINING_SQL}) need
        FROM stitch_order_items i JOIN stitch_orders o ON o.id=i.order_id
        WHERE o.closed=0 AND o.vendor_id IN ({tph}) AND o.id NOT IN ({ph}) AND i.cloth_id IS NOT NULL
        GROUP BY i.cloth_id""", (*tailors, *stitch_order_ids))}
    pos = stock_positions()
    pend = collections.defaultdict(float)
    for r in q(f"""SELECT i.cloth_id, i.qty - (SELECT COALESCE(SUM(d.qty),0) FROM cloth_despatches d
                     WHERE d.order_id=i.order_id AND d.cloth_id=i.cloth_id) pending
                   FROM cloth_order_items i JOIN cloth_orders o ON o.id=i.order_id
                   WHERE o.closed=0 AND o.id<>? AND o.id IN (SELECT cloth_order_id FROM cloth_order_links WHERE stitch_order_id IN ({ph}))""",
               (exclude_cloth_order or '', *stitch_order_ids)):
        pend[r['cloth_id']] += max(r['pending'], 0)
    for n in need:
        cid = n['cloth_id']
        at = sum(pos[(t, cid)]['stock'] + pos[(t, cid)]['transit'] for t in tailors if (t, cid) in pos)
        n['at_tailor'] = round(at, 3)
        n['for_other_orders'] = round(min(other.get(cid, 0), max(at, 0)), 3)
        n['free_at_tailor'] = round(max(at - other.get(cid, 0), 0), 3)
        n['in_godown'] = round(max(pos[(SELF, cid)]['stock'], 0) if (SELF, cid) in pos else 0, 3)
        n['on_order'] = round(pend[cid], 3)
        n['required'] = round(n['required'] or 0, 3)
        n['to_finish'] = round(n['to_finish'] or 0, 3)
        n['to_order'] = round(max(n['to_finish'] - n['free_at_tailor'] - n['on_order'], 0), 3)
        n['short'] = n['to_order']
    return need

@app.route('/api/requirement')
@require_auth
def requirement_api():
    ids = [x for x in (request.args.get('stitch_order_ids') or '').split(',') if x]
    return jsonify(requirement(ids, request.args.get('exclude_cloth_order')))

# ── COSTING ───────────────────────────────────────────────────────────────────
def costing(order_id=None):
    """Average manufacturing cost per piece.
    Per stitch-order line: cloth cost = cloth used x weighted avg landed cloth rate;
    stitching = pieces x stitch rate, or — when tailor bills are entered — the order's bill total
    spread over its lines by (pieces x rate), or by pieces if no rates were set;
    other charges of the order are spread by pieces delivered."""
    rates = cloth_rates()
    where, params = ('WHERE o.id=?', (order_id,)) if order_id else ('', ())
    lines = rows(q(f"""SELECT oi.id, oi.order_id, oi.item_id, it.name item_name, it.sort item_sort, sc.name school_name,
        oi.school_id, oi.size, oi.rate, oi.cloth_id, o.number order_number, v.name vendor_name,
        COALESCE(SUM(di.qty),0) pcs, COALESCE(SUM(di.cloth_used),0) cloth_used
        FROM stitch_order_items oi JOIN stitch_orders o ON o.id=oi.order_id JOIN vendors v ON v.id=o.vendor_id
        JOIN items it ON it.id=oi.item_id LEFT JOIN schools sc ON sc.id=oi.school_id
        LEFT JOIN stitch_delivery_items di ON di.order_item_id=oi.id
        {where} GROUP BY oi.id""", params))
    charges = {r['order_id']: r['amt'] for r in q("SELECT order_id, SUM(amount) amt FROM stitch_charges GROUP BY order_id")}
    bills = {r['order_id']: r['amt'] for r in q("SELECT order_id, SUM(amount) amt FROM stitch_bills GROUP BY order_id")}
    by_order = collections.defaultdict(list)
    for l in lines: by_order[l['order_id']].append(l)
    for oid, ls in by_order.items():
        pcs = sum(l['pcs'] for l in ls)
        weight = sum(l['pcs'] * (l['rate'] or 0) for l in ls)
        for l in ls:
            crate = rates.get(l['cloth_id'], 0)
            l['cloth_rate'] = round(crate, 2)
            l['cloth_cost'] = l['cloth_used'] * crate
            if oid in bills:
                share = (l['pcs'] * (l['rate'] or 0) / weight) if weight else (l['pcs'] / pcs if pcs else 0)
                l['stitch_cost'] = bills[oid] * share
                l['billed'] = True
            else:
                l['stitch_cost'] = l['pcs'] * (l['rate'] or 0)
                l['billed'] = False
            l['other_cost'] = charges.get(oid, 0) * (l['pcs'] / pcs) if pcs else 0
            l['total'] = l['cloth_cost'] + l['stitch_cost'] + l['other_cost']
            l['avg'] = l['total'] / l['pcs'] if l['pcs'] else 0
    F = ('pcs', 'cloth_used', 'cloth_cost', 'stitch_cost', 'other_cost', 'total')
    groups = collections.OrderedDict()
    for l in sorted(lines, key=lambda x: (x['school_name'] or '', x['item_sort'], x['item_name'], x['size'] or '')):
        k = (l['school_id'], l['item_id'], l['size'] or '')
        b = groups.setdefault(k, {'item_name': l['item_name'], 'school_name': l['school_name'], 'size': l['size'], **{f: 0 for f in F}})
        for f in F: b[f] += l[f]
    prods = [b for b in groups.values() if b['pcs']]
    for b in prods: b['avg'] = b['total'] / b['pcs']
    tot = {f: sum(l[f] for l in lines) for f in F}
    unbilled = [oid for oid, ls in by_order.items() if sum(l['pcs'] for l in ls) == 0]
    tot['unallocated_charges'] = sum(charges.get(o, 0) + bills.get(o, 0) for o in unbilled)
    tot['avg'] = tot['total'] / tot['pcs'] if tot['pcs'] else 0
    return {'lines': [l for l in lines if l['pcs']], 'products': prods, 'total': tot}

@app.route('/api/costing')
@require_auth
def costing_api():
    return jsonify(costing())

# ── REPORTS ───────────────────────────────────────────────────────────────────
@app.route('/api/reports/schools')
@require_auth
def report_schools():
    """Per school: pieces ordered by the school, given to tailors, received, still to deliver."""
    out = collections.OrderedDict()
    for o in list_school_orders().json:
        s = out.setdefault(o['school_id'], {'school_name': o['school_name'], 'orders': [], 'qty': 0, 'stitch_ordered': 0, 'received': 0})
        s['orders'].append({k: o[k] for k in ('id', 'number', 'date', 'due_date', 'closed', 'qty', 'stitch_ordered', 'received')})
        for f in ('qty', 'stitch_ordered', 'received'): s[f] += o[f]
    return jsonify(sorted(out.values(), key=lambda s: s['school_name']))

@app.route('/api/reports/tailors')
@require_auth
def report_tailors():
    """Per tailor: pieces pending in open orders and cloth lying with them."""
    pos = stock_positions()
    cl = {r['id']: dict(r) for r in q("SELECT id,name,unit FROM cloths")}
    out = []
    for v in q("SELECT id,name FROM vendors WHERE type IN ('stitch','both') ORDER BY name"):
        r = q("""SELECT COALESCE(SUM(i.qty),0) ordered,
                 COALESCE(SUM((SELECT COALESCE(SUM(di.qty),0) FROM stitch_delivery_items di WHERE di.order_item_id=i.id)),0) delivered
                 FROM stitch_order_items i JOIN stitch_orders o ON o.id=i.order_id WHERE o.vendor_id=? AND o.closed=0""", (v['id'],), one=True)
        cloth = [{'cloth_name': cl[c]['name'], 'unit': cl[c]['unit'], 'stock': p['stock'], 'transit': p['transit']}
                 for (loc, c), p in pos.items() if loc == v['id'] and c in cl and (abs(p['stock']) > 0.0005 or p['transit'] > 0.0005)]
        if r['ordered'] or cloth:
            out.append({'id': v['id'], 'name': v['name'], 'ordered': r['ordered'], 'delivered': r['delivered'],
                        'pending': max(r['ordered'] - r['delivered'], 0), 'cloth': cloth})
    return jsonify(out)

# ── DASHBOARD ─────────────────────────────────────────────────────────────────
@app.route('/api/dashboard')
@require_auth
def dashboard():
    pos = stock_positions()
    self_stock = sum(p['stock'] for (loc, _), p in pos.items() if loc == SELF)
    vendor_stock = sum(p['stock'] for (loc, _), p in pos.items() if loc != SELF)
    transit = sum(p['transit'] for p in pos.values())
    so = q("""SELECT COALESCE(SUM(qty),0) qty FROM stitch_order_items i JOIN stitch_orders o ON o.id=i.order_id WHERE o.closed=0""", one=True)
    delivered = q("""SELECT COALESCE(SUM(di.qty),0) d FROM stitch_delivery_items di JOIN stitch_order_items i ON i.id=di.order_item_id
                     JOIN stitch_orders o ON o.id=i.order_id WHERE o.closed=0""", one=True)['d']
    open_orders = q("SELECT COUNT(*) FROM stitch_orders WHERE closed=0", one=True)[0]
    goods_transit = q("""SELECT COALESCE(SUM(di.qty),0) FROM stitch_delivery_items di JOIN stitch_deliveries d ON d.id=di.delivery_id
                         WHERE d.received_date IS NULL""", one=True)[0]
    today = date.today().isoformat()
    overdue = rows(q("""SELECT o.id, o.number, o.due_date, v.name vendor_name, 'stitch' kind FROM stitch_orders o JOIN vendors v ON v.id=o.vendor_id
                        WHERE o.closed=0 AND o.due_date IS NOT NULL AND o.due_date < ?
                        UNION ALL
                        SELECT o.id, o.number, o.due_date, s.name, 'school' FROM school_orders o JOIN schools s ON s.id=o.school_id
                        WHERE o.closed=0 AND o.due_date IS NOT NULL AND o.due_date < ? ORDER BY 3""", (today, today)))
    # school orders with sizes not yet given to any tailor
    to_assign = []
    for o in list_school_orders().json:
        if o['closed']: continue
        left = sum(max(i['qty'] - i['stitch_ordered'], 0) for i in o['items'])
        if left > 0: to_assign.append({'id': o['id'], 'number': o['number'], 'school_name': o['school_name'], 'left': left})
    awaiting = rows(q("""SELECT 'cloth-despatches' kind, d.id, d.number, d.despatch_date, c.name || ' · ' || d.qty || ' ' || c.unit what,
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
                  ORDER BY 4"""))
    c = costing()['total']
    return jsonify({'self_stock': round(self_stock, 2), 'vendor_stock': round(vendor_stock, 2), 'transit': round(transit, 2),
                    'open_orders': open_orders, 'ordered_pcs': so['qty'], 'pending_pcs': max(so['qty'] - delivered, 0),
                    'goods_transit': goods_transit, 'overdue': overdue, 'awaiting': awaiting, 'to_assign': to_assign,
                    'avg_cost': c['avg'], 'pcs_made': c['pcs'], 'total_cost': c['total']})

@app.route('/api/meta')
@require_auth
def meta():
    return jsonify({'charge_heads': CHARGE_HEADS, 'today': date.today().isoformat(), 'std_width': STD_WIDTH})

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
