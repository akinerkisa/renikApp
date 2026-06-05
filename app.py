import os
import re
import json
import sqlite3
import tempfile
import threading
import time
import random
import urllib.request
from datetime import datetime
from flask import Flask, request, render_template, abort, url_for, send_file, send_from_directory, redirect, jsonify
from jinja2 import Template
from markupsafe import escape

app = Flask(__name__)

# ─── Database ────────────────────────────────────────────────────────────────

DB_PATH = os.getenv("RENIKAPP_DB_PATH", os.path.join(os.path.dirname(__file__), "users.db"))

def init_db():
    global DB_PATH
    try:
        conn = sqlite3.connect(DB_PATH)
    except sqlite3.OperationalError:
        DB_PATH = os.path.join(tempfile.gettempdir(), "renikapp_users.db")
        conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin')")
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('secure_user', 'password123')")
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('testuser', 'testpass123')")
    conn.commit()
    conn.close()

init_db()

login_attempts = {}

# ─── SSRF helpers ────────────────────────────────────────────────────────────

_UNIQUE_ID_RE = re.compile(r"(?i)(?:https?://|//)([a-z0-9]{6,})\.")

def _get_oob_port() -> int:
    try:
        return int(os.getenv("SSRFORCER_OOB_PORT", "8080"))
    except Exception:
        return 8080

def _extract_unique_id(value: str):
    if not value or not isinstance(value, str):
        return None
    m = _UNIQUE_ID_RE.search(value)
    return m.group(1) if m else None

def _get_request_value(*keys: str) -> str:
    for key in keys:
        if key in request.args and request.args.get(key):
            return request.args.get(key, '')
        if key in request.form and request.form.get(key):
            return request.form.get(key, '')
    if request.is_json:
        data = request.get_json(silent=True) or {}
        for key in keys:
            value = data.get(key)
            if isinstance(value, str) and value:
                return value
    return ''

def _schedule_delayed_oob(url_value: str, delay_ms: int) -> None:
    def _runner():
        time.sleep(max(delay_ms, 0) / 1000.0)
        _trigger_oob_from_value(url_value)
    threading.Thread(target=_runner, daemon=True).start()

def _trigger_oob_http(unique_id: str) -> None:
    oob_port = _get_oob_port()
    url = f"http://127.0.0.1:{oob_port}/{unique_id}/callback?id={unique_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "renikApp-v3"})
        with urllib.request.urlopen(req, timeout=1) as resp:
            _ = resp.read(256)
    except Exception:
        return

def _looks_like_oast_url(url_value: str) -> bool:
    if not url_value or not isinstance(url_value, str):
        return False
    v = url_value.lower()
    oast_suffixes = [".interact.sh", ".oast.pro", ".oast.site", ".oast.me", ".oast.online",
                     "interact.sh", "oast.pro", "oast.site", "oast.me", "oast.online"]
    return any(suf in v for suf in oast_suffixes)

def _trigger_oob_from_value(url_value: str) -> None:
    if not url_value or not isinstance(url_value, str):
        return
    v = url_value.strip()
    if v.startswith("//"):
        v = "http:" + v
    if _looks_like_oast_url(v):
        try:
            req = urllib.request.Request(v, headers={"User-Agent": "renikApp-v3"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                _ = resp.read(128)
            return
        except Exception:
            pass
    unique_id = _extract_unique_id(url_value)
    if unique_id:
        _trigger_oob_http(unique_id)

def _scan_json_for_strings(obj):
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_scan_json_for_strings(v))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_scan_json_for_strings(item))
    return out

def _contains_any(value: str, needles: list) -> bool:
    if not value or not isinstance(value, str):
        return False
    v = value.lower()
    return any(n.lower() in v for n in needles)

# ─── ICS/SCADA Simulators ────────────────────────────────────────────────────

class SCADASimulator:
    def __init__(self):
        self.current_setpoint = 50.0
        self.current_value = 50.0
        self.target_value = 50.0
        self.is_running = True
        self.alarm_threshold = 80.0
        self.alarm_active = False
        self.events = []
        self.siem_logs = []
        threading.Thread(target=self._simulation_loop, daemon=True).start()
        self._add_event("System started", "INFO", {"setpoint": self.current_setpoint})

    def _simulation_loop(self):
        while self.is_running:
            diff = self.target_value - self.current_value
            if abs(diff) > 0.1:
                self.current_value += diff * 0.1
                if self.current_value > self.alarm_threshold and not self.alarm_active:
                    self.alarm_active = True
                    self._add_event(f"ALARM: Pressure threshold exceeded ({self.current_value:.1f} bar)", "ALARM",
                                    {"pressure": self.current_value})
                    self._add_siem_log("pressure_threshold_exceeded",
                                       {"pressure": self.current_value, "threshold": self.alarm_threshold})
                elif self.current_value <= self.alarm_threshold and self.alarm_active:
                    self.alarm_active = False
                    self._add_event("Alarm cleared", "INFO", {"pressure": self.current_value})
            time.sleep(0.5)

    def set_setpoint(self, new_setpoint):
        old = self.current_setpoint
        self.current_setpoint = float(new_setpoint)
        self.target_value = self.current_setpoint
        self._add_event(f"Setpoint changed: {old:.1f} → {new_setpoint:.1f} bar", "SETPOINT_CHANGE",
                        {"old_setpoint": old, "new_setpoint": new_setpoint, "user": "demo_user"})
        self._add_siem_log("setpoint_modification",
                           {"old_value": old, "new_value": new_setpoint, "user": "demo_user",
                            "timestamp": datetime.now().isoformat()})
        return True

    def _add_event(self, message, event_type, data=None):
        self.events.insert(0, {"timestamp": datetime.now().isoformat(), "type": event_type,
                                "message": message, "data": data or {}})
        self.events = self.events[:20]

    def _add_siem_log(self, rule_name, data):
        self.siem_logs.insert(0, {"timestamp": datetime.now().isoformat(), "rule": rule_name,
                                   "severity": "HIGH" if rule_name == "pressure_threshold_exceeded" else "MEDIUM",
                                   "data": data, "source": "scada_demo"})
        self.siem_logs = self.siem_logs[:50]

    def get_status(self):
        return {"current_value": round(self.current_value, 2), "setpoint": self.current_setpoint,
                "alarm_active": self.alarm_active, "alarm_threshold": self.alarm_threshold,
                "timestamp": datetime.now().isoformat()}

    def get_events(self):
        return self.events[:10]

    def get_siem_logs(self):
        return self.siem_logs[:20]


class MalwareBehaviorSimulator:
    WHITELIST_IPS = {"127.0.0.1", "::1"}

    def __init__(self):
        self.lock = threading.Lock()
        self.is_running = True
        self.events = []
        self.alarms = []
        self.event_count_window = []
        threading.Thread(target=self._telemetry_loop, daemon=True).start()
        self._log_event(event="system_start", actor="sim_core", user="instructor",
                        src_ip="127.0.0.1", dest="lab-host",
                        details={"message": "Malware behavior sim started"})

    def _now_iso(self):
        return datetime.now().isoformat()

    def _log_event(self, *, event, actor, user, src_ip, dest, details):
        entry = {"ts": self._now_iso(), "event": event, "actor": actor,
                 "user": user, "src_ip": src_ip, "dest": dest, "details": details or {}}
        with self.lock:
            self.events.insert(0, entry)
            self.events = self.events[:400]
            now_ts = time.time()
            self.event_count_window.append(now_ts)
            self.event_count_window = [t for t in self.event_count_window if t >= now_ts - 300]
        return entry

    def _raise_alarm(self, severity, message, context):
        alarm = {"ts": self._now_iso(), "severity": severity, "message": message, "context": context or {}}
        with self.lock:
            self.alarms.insert(0, alarm)
            self.alarms = self.alarms[:100]
        return alarm

    def _telemetry_loop(self):
        while self.is_running:
            self._log_event(event="telemetry_update", actor="telemetry", user="system",
                            src_ip="127.0.0.1", dest="lab-host",
                            details={"cpu": round(random.uniform(5.0, 35.0), 1),
                                     "mem": round(random.uniform(20.0, 60.0), 1),
                                     "io_ops": random.randint(50, 120)})
            time.sleep(1.0)

    def get_status(self):
        with self.lock:
            now_ts = time.time()
            per_min = len([t for t in self.event_count_window if t >= now_ts - 60])
            return {"event_rate_per_min": per_min, "alarms": self.alarms[:10], "ts": self._now_iso()}

    def get_logs(self, n=50):
        with self.lock:
            return self.events[:n]

    def get_alarms(self, n=50):
        with self.lock:
            return self.alarms[:n]

    def trigger_behavior(self, kind, user="instructor", token_ok=False):
        actor = "malware_actor_sim"
        src_ip = "127.0.0.1"
        dest = "lab-host"

        if not token_ok:
            self._log_event(event="auth_fail", actor="api", user=user, src_ip=src_ip, dest=dest,
                            details={"reason": "invalid_token"})
            return {"error": "unauthorized"}, 401

        if kind == "unexpected_process_start":
            e = self._log_event(event=kind, actor=actor, user=user, src_ip=src_ip, dest=dest,
                                details={"process": "svc_updater.exe_stub"})
            return {"success": True, "event": e}
        if kind == "file_integrity_change":
            e = self._log_event(event=kind, actor=actor, user=user, src_ip=src_ip, dest=dest,
                                details={"file": "conf_backup.zip", "change": "modified"})
            return {"success": True, "event": e}
        if kind == "high_cpu":
            e = self._log_event(event=kind, actor=actor, user=user, src_ip=src_ip, dest=dest,
                                details={"cpu": 92.4})
            self._raise_alarm("MEDIUM", "High CPU usage simulation", {"cpu": 92.4})
            return {"success": True, "event": e}
        if kind == "memory_spike":
            e = self._log_event(event=kind, actor=actor, user=user, src_ip=src_ip, dest=dest,
                                details={"mem": 88.9})
            self._raise_alarm("MEDIUM", "Memory spike simulation", {"mem": 88.9})
            return {"success": True, "event": e}
        if kind == "outbound_connection_attempt":
            ip = random.choice(["203.0.113.10", "198.51.100.4", "192.168.1.50"])
            e = self._log_event(event=kind, actor=actor, user=user, src_ip=src_ip, dest=ip,
                                details={"port": 443})
            if ip not in self.WHITELIST_IPS and not ip.startswith("192.168.") and not ip.startswith("10."):
                self._raise_alarm("HIGH", "Outbound attempt to non-whitelisted IP", {"dest": ip})
            return {"success": True, "event": e}
        if kind == "data_exfil_sim":
            e = self._log_event(event=kind, actor=actor, user=user, src_ip=src_ip, dest="198.51.100.77",
                                details={"bytes": 512, "note": "anon meta packet"})
            self._raise_alarm("HIGH", "Possible data exfiltration simulation", {"bytes": 512})
            return {"success": True, "event": e}

        return {"error": "unknown_kind"}, 400


scada = SCADASimulator()
mal = MalwareBehaviorSimulator()

def _ics_auth_ok(req) -> bool:
    auth = req.headers.get("Authorization", "")
    return auth.strip() == "Bearer demo-token"

# ═════════════════════════════════════════════════════════════════════════════
# Routes — Core
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')

# ─── 403 Bypass ──────────────────────────────────────────────────────────────

@app.route('/403')
def forbidden():
    return render_template('403/403.html')

@app.route('/403/secret')
def secret():
    if request.headers.get('X-Custom-IP-Authorization') == "127.0.0.1":
        return "Bypassed using X-Custom-IP-Authorization header"
    if request.headers.get('X-Forwarded-Host') == "localhost":
        return "Bypassed using X-Forwarded-Host header"
    if request.headers.get('X-Forwarded-For') == "127.0.0.1":
        return "Bypassed using X-Forwarded-For header"
    abort(403)

# ─── SSTI ────────────────────────────────────────────────────────────────────

@app.route('/ssti')
def ssti():
    return render_template('ssti/ssti.html')

@app.route('/vulnerable-ssti', methods=['GET', 'POST'])
def vulnerable_ssti():
    name = request.form.get('name', '') if request.method == 'POST' else ''
    template = '''
  <!DOCTYPE html><html lang="en"><head>
      <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Vulnerable SSTI Page</title>
      <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
  </head><body><div class="container">
      <h2 class="text-center">Vulnerable SSTI Form</h2>
      <div class="card"><form method="POST"><div class="form-group">
          <input type="text" name="name" placeholder="Enter your name">
      </div><input type="submit" value="Submit"></form>
      {% if name %}<div class="message warning mt-4"><h3>Hello, ''' + name + '''!</h3></div>{% endif %}
      </div>
      <div class="flex gap-4 mt-4">
          <a href="../ssti" class="card">Back to SSTI Examples</a>
          <a href="../" class="card">Back to main menu</a>
      </div></div></body></html>'''
    return Template(template).render(name=name, url_for=url_for)

@app.route('/safe-ssti', methods=['GET', 'POST'])
def safe_ssti():
    name = escape(request.form.get('name', '')) if request.method == 'POST' else ''
    return render_template('ssti/ssti_safe.html', name=name)

@app.route('/template-engine')
def template_engine():
    return render_template('ssti/template_engine.html', name="Akiner")

# ─── Login Bypass ────────────────────────────────────────────────────────────

@app.route('/lp')
def lp():
    return render_template('lp/lp.html')

@app.route('/lp/dashboard')
def dashboard():
    return render_template('lp/dashboard.html')

@app.route('/lp/insecure-login', methods=['GET', 'POST'])
def insecure_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()
            if user:
                response = redirect('/lp/dashboard')
                response.set_cookie('session_id', 'vulnerable_session_12345')
                return response
            return "Invalid username or password. Please try again."
        except sqlite3.OperationalError as e:
            conn.close()
            if "syntax error" in str(e).lower():
                return "Database error occurred."
            return "Login failed."
    return render_template('lp/insecure_login.html')

@app.route('/lp/secure-login', methods=['GET', 'POST'])
def secure_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            response = redirect('/lp/dashboard')
            response.set_cookie('session_id', 'secure_session_12345')
            return response
        return "Invalid username or password. Please try again."
    return render_template('lp/secure_login.html')

@app.route('/lp/default-login', methods=['GET', 'POST'])
def default_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'admin':
            response = redirect('/lp/dashboard')
            response.set_cookie('session_id', 'default_session_12345')
            return response
        return "Invalid username or password. Please try again."
    return render_template('lp/default_login.html')

@app.route('/lp/rate-limit-login', methods=['GET', 'POST'])
def rate_limit_login():
    if request.method == 'GET':
        username = request.remote_addr
    else:
        username = request.form.get('username') or request.remote_addr

    current_time = time.time()
    MAX_ATTEMPTS = 5
    BLOCK_DURATION = 15

    if username not in login_attempts:
        login_attempts[username] = {'count': 0, 'blocked_until': 0}

    user_data = login_attempts[username]

    if user_data['blocked_until'] > current_time:
        abort(429)
    if user_data['blocked_until'] > 0 and current_time >= user_data['blocked_until']:
        user_data['count'] = 0
        user_data['blocked_until'] = 0
    if user_data['count'] >= MAX_ATTEMPTS:
        user_data['blocked_until'] = current_time + BLOCK_DURATION
        abort(429)

    if request.method == 'POST':
        password = request.form.get('password')
        user_data['count'] += 1
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()
            if user:
                login_attempts[username] = {'count': 0, 'blocked_until': 0}
                response = redirect('/lp/dashboard')
                response.set_cookie('session_id', 'rate_limit_session_12345')
                return response
            return "Invalid credentials."
        except:
            conn.close()
            return "Invalid credentials."

    user_data['count'] += 1
    return render_template('lp/rate_limit_login.html')

@app.route('/lp/nosql-login', methods=['GET', 'POST'])
def nosql_login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username_raw = request.form.get('username')
            password_raw = request.form.get('password')
            try:
                username = json.loads(username_raw) if username_raw and username_raw.startswith('{') else username_raw
            except:
                username = username_raw
            try:
                password = json.loads(password_raw) if password_raw and password_raw.startswith('{') else password_raw
            except:
                password = password_raw

        users_db = [{"username": "admin", "password": "admin123"},
                    {"username": "administrator", "password": "admin"},
                    {"username": "user", "password": "password"},
                    {"username": "test", "password": "test123"}]
        try:
            ud = username if isinstance(username, dict) else None
            pd = password if isinstance(password, dict) else None
            if ud and ("$ne" in ud or "$gt" in ud or "$regex" in ud):
                if ud.get("$ne") in ["", None] or ud.get("$gt") == "":
                    response = redirect('/lp/dashboard')
                    response.set_cookie('session_id', 'nosql_injection_session_12345')
                    return response
                if "$regex" in ud:
                    response = redirect('/lp/dashboard')
                    response.set_cookie('session_id', 'nosql_injection_session_12345')
                    return response
            if ud and pd and ud.get("$ne") in ["", None] and pd.get("$ne") in ["", None]:
                response = redirect('/lp/dashboard')
                response.set_cookie('session_id', 'nosql_injection_session_12345')
                return response
            us = username if isinstance(username, str) else str(username)
            ps = password if isinstance(password, str) else str(password)
            for user in users_db:
                if user["username"] == us and user["password"] == ps:
                    response = redirect('/lp/dashboard')
                    response.set_cookie('session_id', 'nosql_session_12345')
                    return response
            return "Login failed."
        except Exception as e:
            return f"Login failed. Error: {str(e)}"
    return render_template('lp/nosql_login.html')

@app.route('/lp/username-enum-login', methods=['GET', 'POST'])
def username_enum_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        if not user:
            conn.close()
            return "Username not found. Please check your username."
        if user[2] == password:
            conn.close()
            response = redirect('/lp/dashboard')
            response.set_cookie('session_id', 'enum_session_12345')
            return response
        conn.close()
        return "Invalid password. Please try again."
    return render_template('lp/username_enum_login.html')

@app.route('/lp/captcha-login', methods=['GET', 'POST'])
def captcha_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha = request.form.get('captcha')
        if captcha and captcha.strip() == "4":
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                c.execute(query)
                user = c.fetchone()
                conn.close()
                if user:
                    response = redirect('/lp/dashboard')
                    response.set_cookie('session_id', 'captcha_session_12345')
                    return response
                return "Invalid credentials."
            except:
                conn.close()
                return "Invalid credentials."
        return "CAPTCHA verification failed. Please try again."
    return render_template('lp/captcha_login.html')

@app.route('/lp/xpath-login', methods=['GET', 'POST'])
def xpath_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            xpath_bypass_patterns = ["' or '1'='1", "' or ''='", "' or 1]%00", "' or /* or '",
                                     "' or \"a\" or '", "' or 1 or '", "' or true() or '",
                                     "admin' or '", "admin' or '1'='2"]
            for pattern in xpath_bypass_patterns:
                if pattern in username or pattern in password:
                    response = redirect('/lp/dashboard')
                    response.set_cookie('session_id', 'xpath_injection_session_12345')
                    return response
            if "string-length" in username or "contains" in username or "position()" in username:
                response = redirect('/lp/dashboard')
                response.set_cookie('session_id', 'xpath_injection_session_12345')
                return response
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                c.execute(query)
                user = c.fetchone()
                conn.close()
                if user:
                    response = redirect('/lp/dashboard')
                    response.set_cookie('session_id', 'xpath_session_12345')
                    return response
                return "Login failed."
            except:
                conn.close()
                return "Login failed."
        except:
            return "Login failed."
    return render_template('lp/xpath_login.html')

@app.route('/lp/ldap-login', methods=['GET', 'POST'])
def ldap_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            ldap_bypass_patterns = ["*", "*)(&", "*)(|(&", "pwd)", "*)(|(*", "*))%00",
                                    "admin)(&)", "admin)(!(&(|", "pwd))", "admin))(|(|"]
            for pattern in ldap_bypass_patterns:
                if pattern in username or pattern in password:
                    response = redirect('/lp/dashboard')
                    response.set_cookie('session_id', 'ldap_injection_session_12345')
                    return response
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                c.execute(query)
                user = c.fetchone()
                conn.close()
                if user:
                    response = redirect('/lp/dashboard')
                    response.set_cookie('session_id', 'ldap_session_12345')
                    return response
                return "Login failed."
            except:
                conn.close()
                return "Login failed."
        except:
            return "Login failed."
    return render_template('lp/ldap_login.html')

@app.route('/lp/json-login', methods=['GET', 'POST'])
def json_login_page():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')
        if username == 'admin' and password == 'admin':
            response = redirect('/lp/dashboard')
            response.set_cookie('session_id', 'json_login_session_12345')
            return response
        return "Invalid username or password. Please try again."
    return render_template('lp/json_login.html')

@app.route('/lp/test-account-login', methods=['GET', 'POST'])
def test_account_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'testuser' and password == 'testpass123':
            response = redirect('/lp/dashboard')
            response.set_cookie('session_id', 'test_account_session_12345')
            return response
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()
            if user:
                response = redirect('/lp/dashboard')
                response.set_cookie('session_id', 'test_account_session_12345')
                return response
            return "Invalid username or password. Please try again."
        except:
            conn.close()
            return "Login failed."
    return render_template('lp/test_account_login.html')

@app.route('/lp/csrf-login', methods=['GET', 'POST'])
def csrf_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        csrf_token = request.form.get('csrf_token')
        if csrf_token and (csrf_token == 'random_csrf_token_12345' or len(csrf_token) > 0):
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                c.execute(query)
                user = c.fetchone()
                conn.close()
                if user:
                    response = redirect('/lp/dashboard')
                    response.set_cookie('session_id', 'csrf_session_12345')
                    return response
                return "Login failed."
            except:
                conn.close()
                return "Login failed."
        return "CSRF token missing or invalid."
    return render_template('lp/csrf_login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    if request.is_json:
        data = request.get_json()
        username = data.get('username') or data.get('user') or data.get('email')
        password = data.get('password') or data.get('pass') or data.get('pwd')
        if username == 'admin' and password == 'admin':
            return {"status": "success", "message": "Login successful",
                    "token": "fake_token_12345", "user": {"id": 1, "username": "admin"}}
        return {"status": "error", "message": "Invalid credentials"}, 401
    return {"status": "error", "message": "Content-Type must be application/json"}, 400

@app.route('/api/graphql', methods=['POST', 'GET'])
def graphql_login():
    if request.method == 'GET':
        return render_template('lp/graphql_login.html')
    if request.is_json:
        data = request.get_json()
        query = data.get('query', '')
        username_match = re.search(r'username[:\s]*["\']([^"\']+)["\']', query)
        password_match = re.search(r'password[:\s]*["\']([^"\']+)["\']', query)
        if username_match and password_match:
            if username_match.group(1) == 'admin' and password_match.group(1) == 'admin':
                return {"data": {"login": {"token": "graphql_token_12345",
                                           "user": {"id": "1", "username": "admin"}}}}
            return {"errors": [{"message": "Invalid credentials"}]}, 401
        if '__schema' in query or '__type' in query:
            return {"data": {"__schema": {"queryType": {"name": "Query"},
                                          "mutationType": {"name": "Mutation"}}}}
        return {"errors": [{"message": "Invalid query"}]}, 400
    return {"errors": [{"message": "Content-Type must be application/json"}]}, 400

@app.route('/lp/graphql-login')
def graphql_login_page():
    return render_template('lp/graphql_login.html')

# ─── File / Path Traversal ───────────────────────────────────────────────────

@app.route('/file')
def file_viewer():
    return render_template('file/file.html')

@app.route('/file/vulnerable')
def vulnerable_file_viewer():
    filename = request.args.get('file', 'default.txt')
    filepath = os.path.join('files', filename)
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return render_template('file/vulnerable_viewer.html', content=content, filename=filename)
    except IOError:
        return "File not found", 404

@app.route('/file/semi-secure')
def semi_secure_file_viewer():
    filename = request.args.get('file', 'default.txt')
    filename = filename.replace('../', '').replace('..\\', '')
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        return "Invalid filename", 400
    filepath = os.path.join('files', filename)
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return render_template('file/semi_secure_viewer.html', content=content, filename=filename)
    except IOError:
        return "File not found", 404

@app.route('/file/secure')
def secure_file_viewer():
    base_dir = os.path.abspath('files')
    filename = request.args.get('file', 'default.txt')
    filepath = os.path.join(base_dir, filename)
    realpath = os.path.realpath(filepath)
    if not realpath.startswith(base_dir):
        return "Access denied", 403
    try:
        with open(realpath, 'r') as f:
            content = f.read()
        return render_template('file/secure_viewer.html', content=content, filename=filename)
    except IOError:
        return "File not found", 404

@app.route('/file/double-encoding')
def double_encoding_file_viewer():
    filename = request.args.get('file', 'default.txt')
    filename = filename.replace('../', '')
    filepath = os.path.join('files', filename)
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return render_template('file/vulnerable_viewer.html', content=content, filename=filename)
    except IOError:
        return "File not found", 404

@app.route('/get-file')
def get_file():
    filename = request.args.get('file')
    filepath = os.path.join('/var/www/html/', filename)
    if os.path.exists(filepath):
        return send_file(filepath)
    abort(404)

# ═════════════════════════════════════════════════════════════════════════════
# Routes — SSRF Module (from SSRForcer)
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/ssrf')
def ssrf_home():
    return render_template('ssrf/ssrf.html')

@app.route('/ssrf/health', methods=['GET'])
def ssrf_health():
    return jsonify({"status": "ok", "scenarios": [
        "oob", "oob_async", "internal", "cloud", "whitelist", "whitelist_safe",
        "whitelist_bypass_matrix", "bypass_matrix", "safe_no_evidence",
        "error_safe", "error_internal", "header_internal", "form_template", "json_template"
    ]})

@app.route('/ssrf/query/oob', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_oob():
    value = _get_request_value('url', 'dest', 'data')
    unique_id = _extract_unique_id(value)
    if unique_id:
        _trigger_oob_from_value(value)
        return f"ok; oob callback triggered; unique_id={unique_id}", 200, {"Content-Type": "text/plain"}
    return "ok; no unique_id found in url parameter", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/oob_async', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_oob_async():
    value = _get_request_value('url', 'dest', 'data')
    unique_id = _extract_unique_id(value)
    try:
        delay_ms_int = int(request.args.get('delay_ms', '250'))
    except:
        delay_ms_int = 250
    if unique_id:
        _schedule_delayed_oob(value, delay_ms_int)
        return f"ok; async oob scheduled; unique_id={unique_id}; delay_ms={delay_ms_int}", 200, {"Content-Type": "text/plain"}
    return "ok; no unique_id found in url parameter", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/internal', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_internal():
    dest = _get_request_value('dest', 'url', 'data')
    if _contains_any(dest, ["127.0.0.1", "localhost", "0.0.0.0", "10.", "192.168.", "169.254."]):
        return "request succeeded; evidence: 127.0.0.1", 200, {"Content-Type": "text/plain"}
    return "request succeeded; no internal address evidence", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/cloud', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_cloud():
    data = _get_request_value('data', 'url', 'dest')
    if _contains_any(data, ["169.254.169.254", "metadata", "instance-id", "security-credentials"]):
        body = "cloud metadata blocked? evidence:\n169.254.169.254/latest/meta-data/instance-id\nsecurity-credentials"
        return body, 200, {"Content-Type": "text/plain"}
    return "ok; no cloud metadata evidence", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/whitelist', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_whitelist():
    value = request.args.get('url', '') or next(iter(request.args.values()), '')
    bypass = ("%2523@" in value) or (("@" in value) and ("%23" in value))
    if bypass:
        return "whitelist bypass accepted; internal evidence: 127.0.0.1", 200, {"Content-Type": "text/plain"}
    return "Request blocked by whitelist: host not permitted", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/whitelist_safe', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_whitelist_safe():
    return "Request blocked by whitelist: host not permitted", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/whitelist_bypass_matrix', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_whitelist_bypass_matrix():
    value = request.args.get('url', '') or next(iter(request.args.values()), '')
    userinfo_bypass = ("@" in value) and ("%23" in value or "#" in value)
    percent_encoded = ("%2523@" in value) or ("%2e%2e" in value.lower()) or ("%2fadmin" in value.lower())
    if userinfo_bypass or percent_encoded:
        return "whitelist bypass accepted; internal evidence: 127.0.0.1", 200, {"Content-Type": "text/plain"}
    return "Request blocked by whitelist: host not permitted", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/bypass_matrix', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_bypass_matrix():
    value = request.args.get('url', '') or next(iter(request.args.values()), '')
    v = value.lower()
    accepted_tokens = ["127.0.0.1", "localhost", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]",
                       "2130706433", "0177.0.0.1", "017700000001", "0x7f.0x00.0x00.0x01",
                       "0x7f000001", "127%2e0%2e0%2e1", "127%252e0%252e0%252e1"]
    if any(t in v for t in accepted_tokens):
        return "request succeeded; evidence: 127.0.0.1", 200, {"Content-Type": "text/plain"}
    return "request succeeded; no internal address evidence", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/safe_no_evidence', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_safe_no_evidence():
    return "ok", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/error_safe', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_error_safe():
    return "internal server error", 500, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/error_internal', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_error_internal():
    value = request.args.get('url', '') or next(iter(request.args.values()), '')
    v = (value or '').lower()
    if "127.0.0.1" in v or "localhost" in v or "169.254.169.254" in v:
        return "500 could not connect to 127.0.0.1", 500, {"Content-Type": "text/plain"}
    return "500 could not connect (no internal evidence)", 500, {"Content-Type": "text/plain"}

@app.route('/ssrf/query/header_internal', methods=['GET', 'POST', 'PUT', 'DELETE'])
def ssrf_query_header_internal():
    raw = (request.headers.get("X-Forwarded-Host") or
           request.headers.get("X-Original-URL") or
           request.headers.get("Referer") or "")
    combined = str(raw).lower()
    if ("127.0.0.1" in combined or "localhost" in combined or
            re.search(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", combined) or
            re.search(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", combined)):
        return ("backend fetch result: connection to 127.0.0.1:8080 refused (internal)",
                200, {"Content-Type": "text/plain"})
    return "no internal address in header chain", 200, {"Content-Type": "text/plain"}

@app.route('/ssrf/form_template', methods=['GET'])
def ssrf_form_template():
    html = """<!doctype html><html><body>
  <h2>SSRF Form Template</h2>
  <form action="/ssrf/receive_form" method="POST">
    <input type="hidden" name="csrf" value="token123"/>
    <input type="text" name="url" value="test"/>
    <button type="submit">Submit</button>
  </form></body></html>"""
    return html.strip()

@app.route('/ssrf/receive_form', methods=['POST'])
def ssrf_receive_form():
    url_value = request.form.get('url', '')
    unique_id = _extract_unique_id(url_value)
    if unique_id:
        _trigger_oob_from_value(url_value)
    return jsonify({"ok": True, "unique_id": unique_id})

@app.route('/ssrf/json_template', methods=['GET', 'POST'])
def ssrf_json_template():
    if request.method == 'GET':
        return jsonify({"outer": {"url": "test"}, "items": [{"c": "test"}]})
    data = request.get_json(silent=True) or {}
    strings = _scan_json_for_strings(data)
    unique_id = None
    triggered_s = None
    for s in strings:
        unique_id = _extract_unique_id(s)
        if unique_id:
            triggered_s = s
            break
    if unique_id:
        _trigger_oob_from_value(triggered_s)
    return jsonify({"ok": True, "unique_id": unique_id})

# ═════════════════════════════════════════════════════════════════════════════
# Routes — ICS/SCADA Module
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/ics')
def ics_home():
    return render_template('ics/ics.html')

@app.route('/ics/pressure')
def ics_pressure():
    return render_template('ics/dashboard.html')

@app.route('/ics/malware')
def ics_malware():
    return render_template('ics/malware.html')

@app.route('/ics/api/status')
def ics_api_status():
    return jsonify(scada.get_status())

@app.route('/ics/api/setpoint', methods=['POST'])
def ics_api_setpoint():
    try:
        data = request.get_json()
        new_setpoint = float(data.get('setpoint'))
        if new_setpoint < 0 or new_setpoint > 100:
            return jsonify({"error": "Setpoint must be between 0 and 100"}), 400
        success = scada.set_setpoint(new_setpoint)
        return jsonify({"success": success, "new_setpoint": new_setpoint})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/ics/api/logs')
def ics_api_logs():
    return jsonify(scada.get_events())

@app.route('/ics/api/siem')
def ics_api_siem():
    return jsonify(scada.get_siem_logs())

@app.route('/ics/api/history')
def ics_api_history():
    history = []
    base_time = time.time() - 300
    for i in range(60):
        timestamp = base_time + (i * 5)
        value = scada.current_value + random.uniform(-2, 2)
        history.append({"timestamp": datetime.fromtimestamp(timestamp).isoformat(),
                         "value": round(value, 2)})
    return jsonify(history)

@app.route('/ics/api/mal/status')
def ics_api_mal_status():
    return jsonify(mal.get_status())

@app.route('/ics/api/mal/logs')
def ics_api_mal_logs():
    n = request.args.get('n', default=50, type=int)
    return jsonify(mal.get_logs(n))

@app.route('/ics/api/mal/alarms')
def ics_api_mal_alarms():
    n = request.args.get('n', default=50, type=int)
    return jsonify(mal.get_alarms(n))

@app.route('/ics/api/trigger_sim', methods=['POST'])
def ics_api_trigger_sim():
    data = request.get_json(silent=True) or {}
    kind = data.get('kind')
    ok = _ics_auth_ok(request)
    result = mal.trigger_behavior(kind=kind or "",
                                  user=request.headers.get('X-User', 'instructor'),
                                  token_ok=ok)
    if isinstance(result, tuple):
        body, code = result
        return jsonify(body), code
    return jsonify(result)

# ═════════════════════════════════════════════════════════════════════════════
# Routes — Airgap/Stuxnet SPA
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/airgap')
@app.route('/airgap/')
def airgap_index():
    airgap_dir = os.path.join(app.static_folder, 'airgap')
    if os.path.exists(os.path.join(airgap_dir, 'index.html')):
        return send_from_directory(airgap_dir, 'index.html')
    return ("<h2>Airgap Simulation not built yet.</h2>"
            "<p>Run: <code>cd stuxnet && npm install && npm run build</code>"
            " then copy <code>dist/</code> to <code>static/airgap/</code></p>"), 503

@app.route('/airgap/<path:path>')
def airgap_static(path):
    airgap_dir = os.path.join(app.static_folder, 'airgap')
    return send_from_directory(airgap_dir, path)

# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.getenv("RENIKAPP_PORT", "5000"))
    debug_enabled = os.getenv("RENIKAPP_DEBUG", "1") == "1"
    app.run(debug=debug_enabled, use_reloader=False, port=port)
