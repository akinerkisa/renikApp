from flask import Flask, request, render_template, abort, url_for
from jinja2 import Template
from markupsafe import escape
import sqlite3

app = Flask(__name__)

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin')")
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('secure_user', 'password123')")
    conn.commit()
    conn.close()

init_db()

# Dictionary to track login attempts for rate limiting
login_attempts = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ssti')
def ssti():
    return render_template('ssti/ssti.html')

@app.route('/403')
def forbidden():
    return render_template('403/403.html')

# 403 Forbidden section
@app.route('/403/secret')
def secret():
    # Header bypass
    if request.headers.get('X-Custom-IP-Authorization') == "127.0.0.1":
        return "Bypassed using X-Custom-IP-Authorization header"

    if request.headers.get('X-Forwarded-Host') == "localhost":
        return "Bypassed using X-Forwarded-Host header"

    if request.headers.get('X-Forwarded-For') == "127.0.0.1":
        return "Bypassed using X-Forwarded-For header"

    # 403
    abort(403)

# Vulnerable SSTI section
@app.route('/vulnerable-ssti', methods=['GET', 'POST'])
def vulnerable_ssti():
    name = request.form.get('name', '') if request.method == 'POST' else ''
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vulnerable SSTI Page</title>
        <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
    </head>
    <body>
        <h2>Vulnerable SSTI Form</h2>
        <form method="POST">
            <input type="text" name="name">
            <input type="submit" value="Submit">
        </form>
        {% if name %}
        <h3>Hello, ''' + name + '''!</h3>
        {% endif %}
        <a href="../ssti">Back to the SSTI Examples</a>
        <p>
        <a href="../">Back to the main menu</a>
    </body>
    </html>
    '''
    return Template(template).render(name=name, url_for=url_for)

# Safe SSTI section
@app.route('/safe-ssti', methods=['GET', 'POST'])
def safe_ssti():
    name = escape(request.form.get('name', '')) if request.method == 'POST' else ''
    return render_template('ssti/ssti_safe.html', name=name)

# Template Engine example
@app.route('/template-engine')
def template_engine():
    name = "Akiner"
    return render_template('ssti/template_engine.html', name=name)

# LP section
@app.route('/lp')
def lp():
    return render_template('lp/lp.html')

@app.route('/lp/insecure-login', methods=['GET', 'POST'])
def insecure_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Vulnerable SQL query
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            return "Insecure login successful."
        return "Login failed."
    
    return render_template('lp/insecure_login.html')

@app.route('/lp/secure-login', methods=['GET', 'POST'])
def secure_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Secure SQL query using parameterization
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            return "Secure login successful."
        return "Login failed."
    
    return render_template('lp/secure_login.html')

@app.route('/lp/default-login', methods=['GET', 'POST'])
def default_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'admin':
            return "Default login successful."
        return "Login failed."
    return render_template('lp/default_login.html')

@app.route('/lp/rate-limit-login', methods=['GET', 'POST'])
def rate_limit_login():
    username = request.form.get('username')
    user_attempts = login_attempts.get(username, 0)

    if request.method == 'POST':
        if user_attempts >= 5:
            return "Rate limit exceeded. Try again later."

        password = request.form.get('password')

        # Vulnerable SQL query for rate limit login
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            login_attempts[username] = 0  # Reset attempts on success
            return "Login successful."

        login_attempts[username] = user_attempts + 1
        return "Invalid credentials."

    return render_template('lp/rate_limit_login.html')

if __name__ == '__main__':
    app.run(debug=True)
