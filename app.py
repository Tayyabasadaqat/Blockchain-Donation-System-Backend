# app.py
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, hashlib, time, datetime, random, string, os

app = Flask(__name__)
CORS(app)

DATABASE = os.path.join(os.path.dirname(__file__), "donation_chain.db")
SESSION_TTL = 60 * 60  # 1 hour sessions

# ---------- DB ----------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        anon_id TEXT
    );

    CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        idx INTEGER,
        timestamp TEXT,
        donor_id INTEGER,
        amount REAL,
        category TEXT,
        prev_hash TEXT,
        hash TEXT
    );
    """)
    db.commit()

with app.app_context():
    init_db()

# ---------- SESSION ----------
sessions = {}

def make_token():
    return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()

def make_anon_id():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(6))

def auth_required(fn):
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        token = auth.split(" ", 1)[1]
        session = sessions.get(token)
        if not session or session["expires"] < time.time():
            return jsonify({"error": "expired token"}), 401
        request.user_id = session["user_id"]
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

# ---------- BLOCKCHAIN ----------
def calc_hash(idx, ts, donor, amt, cat, prev):
    s = f"{idx}{ts}{donor}{amt}{cat}{prev}"
    return hashlib.sha256(s.encode()).hexdigest()

def get_last_block():
    return get_db().execute(
        "SELECT * FROM blocks ORDER BY idx DESC LIMIT 1"
    ).fetchone()

def create_genesis():
    db = get_db()
    if db.execute("SELECT COUNT(*) c FROM blocks").fetchone()["c"] == 0:
        ts = datetime.datetime.utcnow().isoformat()
        h = calc_hash(0, ts, 0, 0, "GENESIS", "0")
        db.execute("""
        INSERT INTO blocks (idx,timestamp,donor_id,amount,category,prev_hash,hash)
        VALUES (0,?,?,?,?,?,?)
        """, (0, ts, 0, 0, "GENESIS", "0", h))
        db.commit()

with app.app_context():
    create_genesis()

# ---------- AUTH ----------
@app.route("/register", methods=["POST"])
def register():
    d = request.json
    db = get_db()
    db.execute(
        "INSERT INTO users (username,password_hash,anon_id) VALUES (?,?,?)",
        (d["username"], generate_password_hash(d["password"]), make_anon_id())
    )
    db.commit()
    return jsonify({"message": "registered"})

@app.route("/login", methods=["POST"])
def login():
    d = request.json
    db = get_db()
    u = db.execute(
        "SELECT * FROM users WHERE username=?", (d["username"],)
    ).fetchone()
    if not u or not check_password_hash(u["password_hash"], d["password"]):
        return jsonify({"error": "invalid"}), 401
    token = make_token()
    sessions[token] = {"user_id": u["id"], "expires": time.time() + SESSION_TTL}
    return jsonify({"token": token})

# ---------- USERS ----------
@app.route("/users")
def get_users():
    rows = get_db().execute("SELECT anon_id FROM users").fetchall()
    return jsonify([dict(r) for r in rows])

# ---------- DONATE ----------
@app.route("/donate", methods=["POST"])
@auth_required
def donate():
    d = request.json
    last = get_last_block()
    idx = last["idx"] + 1
    ts = datetime.datetime.utcnow().isoformat()
    prev = last["hash"]
    h = calc_hash(idx, ts, request.user_id, d["amount"], d["category"], prev)

    db = get_db()
    db.execute("""
    INSERT INTO blocks (idx,timestamp,donor_id,amount,category,prev_hash,hash)
    VALUES (?,?,?,?,?,?,?)
    """, (idx, ts, request.user_id, d["amount"], d["category"], prev, h))
    db.commit()

    return jsonify({"message": "block added"})

# ---------- DONATIONS CHAIN ----------
@app.route("/donations")
def donations():
    rows = get_db().execute("""
    SELECT b.idx,b.timestamp,u.anon_id donor,b.amount,b.category,b.prev_hash,b.hash
    FROM blocks b LEFT JOIN users u ON b.donor_id=u.id
    ORDER BY b.idx
    """).fetchall()
    return jsonify({"chain": [dict(r) for r in rows]})

# ---------- MY DONATIONS ----------
@app.route("/my_donations", methods=["POST"])
@auth_required
def my_donations():
    rows = get_db().execute("""
    SELECT idx,amount,category,timestamp,hash
    FROM blocks WHERE donor_id=? AND idx!=0
    ORDER BY idx DESC
    """, (request.user_id,)).fetchall()
    return jsonify({"history": [dict(r) for r in rows]})

# ---------- TOTAL DONATIONS BY NGO ----------
@app.route("/total_donations_by_ngo")
def total_donations_by_ngo():
    rows = get_db().execute("""
        SELECT category, SUM(amount) AS total
        FROM blocks
        WHERE idx != 0
        GROUP BY category
    """).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/users")
def admin_users():
    db = get_db()
    # Get user info + total donations + donation count
    rows = db.execute("""
        SELECT 
            u.id,
            u.username,
            u.anon_id,
            COALESCE(SUM(b.amount), 0) AS total_amount,
            COUNT(b.id) AS donation_count
        FROM users u
        LEFT JOIN blocks b ON b.donor_id = u.id AND b.idx != 0
        GROUP BY u.id
    """).fetchall()

    return jsonify([dict(r) for r in rows])

@app.route("/admin/user-donations")
def admin_user_donations():
    db = get_db()
    rows = db.execute("""
        SELECT u.username AS name, u.anon_id, b.category AS ngo, b.amount
        FROM blocks b
        LEFT JOIN users u ON b.donor_id = u.id
        WHERE b.idx != 0
        ORDER BY b.idx DESC
    """).fetchall()

    return jsonify({"data": [dict(r) for r in rows]})


if __name__ == "__main__":
    app.run(debug=True)
