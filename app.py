"""HoneyVault backend: accounts + honey-encrypted vault + attack lab (Flask + SQLite)."""
import os, re, sqlite3, secrets, hashlib, hmac, string
from flask import Flask, request, jsonify

app = Flask(__name__, static_folder="static", static_url_path="")
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.db")
TOKENS = {}                      # token -> username (in memory)
LOGIN_ITER = 200_000             # PBKDF2 iterations for account passwords
ALNUM = string.ascii_letters + string.digits
WORDS = ("apple river stone cloud tiger maple ocean ember falcon harbor island jungle kettle lantern "
         "meadow nectar orchid pepper quartz raven saddle timber umbra velvet willow xenon yonder zephyr "
         "amber basalt cedar dune echo fjord glacier hazel iris jasper koala lotus mango nova onyx pearl "
         "quill ridge sierra tundra ultra violet walnut yarrow zenith anchor beacon coral delta eagle "
         "flint garnet horizon ivory juniper krypton").split()
COMMON = ["123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567",
          "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "shadow", "master",
          "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "superman",
          "1qaz2wsx", "sunshine", "iloveyou", "welcome", "admin", "login", "princess", "sunshine1"]

def conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init_db():
    with conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, salt BLOB, hash BLOB)")
        c.execute("""CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT,
                     label TEXT, type TEXT, mode TEXT, salt BLOB, ct BLOB, tag BLOB)""")

# ---------- password strength (same 5 rules as the PBL project) ----------
def strength(pw):
    rules = [len(pw) >= 8, bool(re.search(r"[A-Z]", pw)), bool(re.search(r"[a-z]", pw)),
             bool(re.search(r"\d", pw)), bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', pw))]
    return sum(rules)

# ---------- honey encryption (distribution-transforming encoder + XOR keystream) ----------
TYPES = {"pin": 4, "card": 16, "apikey": 24, "seed": 6}

def luhn_check_digit(d15):
    total = 0
    for i, d in enumerate(reversed(d15)):
        if i % 2 == 0:
            d *= 2
            if d > 9: d -= 9
        total += d
    return (10 - total % 10) % 10

def encode(t, v):
    """secret string -> list of numbers (the 'seed space'). Raises ValueError on bad input."""
    if t == "pin":
        if not re.fullmatch(r"\d{4}", v): raise ValueError("PIN must be 4 digits")
        return [int(c) for c in v]
    if t == "card":
        if not re.fullmatch(r"\d{16}", v): raise ValueError("Card number must be 16 digits")
        d = [int(c) for c in v]
        if luhn_check_digit(d[:15]) != d[15]: raise ValueError("Card number fails the Luhn check")
        return d[:15]
    if t == "apikey":
        if not re.fullmatch(r"[A-Za-z0-9]{24}", v): raise ValueError("API key must be 24 letters/digits")
        return [ALNUM.index(c) for c in v]
    if t == "seed":
        w = v.lower().split()
        if len(w) != 6 or any(x not in WORDS for x in w): raise ValueError("Use 6 words from the allowed list")
        return [WORDS.index(x) for x in w]
    raise ValueError("Unknown type")

def decode(t, nums):
    """ANY list of numbers decodes to a well-formed secret of the right shape."""
    if t == "pin": return "".join(str(n % 10) for n in nums)
    if t == "card":
        d = [n % 10 for n in nums[:15]]
        return "".join(map(str, d)) + str(luhn_check_digit(d))   # always Luhn-valid
    if t == "apikey": return "".join(ALNUM[n % 62] for n in nums)
    if t == "seed": return " ".join(WORDS[n % len(WORDS)] for n in nums)

def derive(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

def keystream(key, n): return hashlib.shake_256(key + b"ks").digest(n)
def mac(key, ct): return hmac.new(hashlib.sha256(key + b"mac").digest(), ct, "sha256").digest()

def seal(t, secret, pw, mode):
    salt = secrets.token_bytes(16); key = derive(pw, salt); nums = encode(t, secret)
    ct = bytes(n ^ k for n, k in zip(nums, keystream(key, len(nums))))
    return salt, ct, (mac(key, ct) if mode == "standard" else b"")

def unseal(row, pw):
    """Returns plaintext, or None if standard mode and the tag does not verify."""
    key = derive(pw, row["salt"]); ct = row["ct"]
    if row["mode"] == "standard" and not hmac.compare_digest(mac(key, ct), row["tag"]): return None
    return decode(row["type"], [c ^ k for c, k in zip(ct, keystream(key, len(ct)))])

# ---------- helpers ----------
def me():
    return TOKENS.get(request.headers.get("Authorization", "").replace("Bearer ", ""))

def err(msg, code=400): return jsonify(error=msg), code

# ---------- routes ----------
@app.get("/")
def index(): return app.send_static_file("index.html")

@app.get("/api/info")
def info(): return jsonify(words=WORDS, types=TYPES)

@app.post("/api/register")
def register():
    j = request.get_json(force=True); u, p = j.get("username", "").strip(), j.get("password", "")
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", u): return err("Username: 3-20 letters, digits or _")
    if strength(p) < 4: return err("Password too weak. Meet at least 4 of the 5 strength rules.")
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", p.encode(), salt, LOGIN_ITER)
    try:
        with conn() as c: c.execute("INSERT INTO users VALUES(?,?,?)", (u, salt, h))
    except sqlite3.IntegrityError: return err("Username already taken", 409)
    return jsonify(ok=True)

@app.post("/api/login")
def login():
    j = request.get_json(force=True); u, p = j.get("username", ""), j.get("password", "")
    with conn() as c: r = c.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    salt = r["salt"] if r else b"0" * 16
    h = hashlib.pbkdf2_hmac("sha256", p.encode(), salt, LOGIN_ITER)
    if not r or not hmac.compare_digest(h, r["hash"]): return err("Invalid username or password", 401)
    t = secrets.token_urlsafe(32); TOKENS[t] = u
    return jsonify(token=t, username=u)

@app.post("/api/vault")
def add():
    u = me()
    if not u: return err("Log in first", 401)
    j = request.get_json(force=True)
    t, mode, pw = j.get("type"), j.get("mode", "honey"), j.get("passphrase", "")
    if mode not in ("honey", "standard"): return err("Bad mode")
    if len(pw) < 4: return err("Passphrase too short")
    try: salt, ct, tag = seal(t, j.get("secret", ""), pw, mode)
    except ValueError as e: return err(str(e))
    with conn() as c:
        c.execute("INSERT INTO entries(owner,label,type,mode,salt,ct,tag) VALUES(?,?,?,?,?,?,?)",
                  (u, j.get("label", t)[:40], t, mode, salt, ct, tag))
    return jsonify(ok=True)

@app.get("/api/vault")
def lst():
    u = me()
    if not u: return err("Log in first", 401)
    with conn() as c:
        rows = c.execute("SELECT id,label,type,mode FROM entries WHERE owner=?", (u,)).fetchall()
    return jsonify(entries=[dict(r) for r in rows])

def get_entry(eid):
    u = me()
    with conn() as c: return c.execute("SELECT * FROM entries WHERE id=? AND owner=?", (eid, u)).fetchone()

@app.post("/api/vault/open")
def open_():
    if not me(): return err("Log in first", 401)
    j = request.get_json(force=True); r = get_entry(j.get("id"))
    if not r: return err("Not found", 404)
    out = unseal(r, j.get("passphrase", ""))
    if out is None: return err("Wrong passphrase (authentication tag invalid)", 403)
    return jsonify(value=out)          # honey mode: ALWAYS returns something plausible

@app.post("/api/attack")
def attack():
    """Simulates an attacker running a dictionary attack against one stored entry."""
    if not me(): return err("Log in first", 401)
    j = request.get_json(force=True); r = get_entry(j.get("id"))
    if not r: return err("Not found", 404)
    owner_pw = j.get("owner_passphrase", None)   # demo only, used to label the real guess; never stored
    guesses = []
    for g in COMMON:
        out = unseal(r, g)
        guesses.append({"guess": g, "output": out,
                        "plausible": out is not None,
                        "truth": g == owner_pw})
    plaus = sum(x["plausible"] for x in guesses)
    return jsonify(mode=r["mode"], type=r["type"], guesses=guesses, tried=len(guesses), plausible=plaus)

if __name__ == "__main__":
    init_db(); app.run(debug=False, port=5000)
