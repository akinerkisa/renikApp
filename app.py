import os
import re
import json
import sqlite3
from flask import Flask, request, render_template, abort, url_for, send_file, redirect
from jinja2 import Template
from markupsafe import escape

app = Flask(__name__)

def init_db():
  conn = sqlite3.connect('users.db')
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

@app.route('/')
def index():
  return render_template('index.html')

@app.route('/ssti')
def ssti():
  return render_template('ssti/ssti.html')

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
      <div class="container">
          <h2 class="text-center">Vulnerable SSTI Form</h2>
          <div class="card">
              <form method="POST">
                  <div class="form-group">
                      <input type="text" name="name" placeholder="Enter your name">
                  </div>
                  <input type="submit" value="Submit">
              </form>
              {% if name %}
              <div class="message warning mt-4">
                  <h3>Hello, ''' + name + '''!</h3>
              </div>
              {% endif %}
          </div>
          <div class="flex gap-4 mt-4">
              <a href="../ssti" class="card">Back to the SSTI Examples</a>
              <a href="../" class="card">Back to the main menu</a>
          </div>
      </div>
  </body>
  </html>
  '''
  return Template(template).render(name=name, url_for=url_for)

@app.route('/safe-ssti', methods=['GET', 'POST'])
def safe_ssti():
  name = escape(request.form.get('name', '')) if request.method == 'POST' else ''
  return render_template('ssti/ssti_safe.html', name=name)

@app.route('/template-engine')
def template_engine():
  name = "Akiner"
  return render_template('ssti/template_engine.html', name=name)

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
      
      conn = sqlite3.connect('users.db')
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
      
      conn = sqlite3.connect('users.db')
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
  import time
  
  if request.method == 'GET':
      username = request.remote_addr
  else:
      username = request.form.get('username')
      if not username:
          username = request.remote_addr
  
  current_time = time.time()
  MAX_ATTEMPTS = 5
  BLOCK_DURATION = 15
  
  if username not in login_attempts:
      login_attempts[username] = {
          'count': 0,
          'blocked_until': 0  # Timestamp when block expires
      }
  
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
      
      conn = sqlite3.connect('users.db')
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
  
  if request.method == 'GET':
      user_data['count'] += 1
      return render_template('lp/rate_limit_login.html')

  return render_template('lp/rate_limit_login.html')

@app.route('/lp/nosql-login', methods=['GET', 'POST'])
def nosql_login():
  if request.method == 'POST':
      username = None
      password = None
      
      if request.is_json:
          data = request.get_json()
          username = data.get('username')
          password = data.get('password')
      else:
          username_raw = request.form.get('username')
          password_raw = request.form.get('password')
          
          if username_raw and (username_raw.startswith('{') or username_raw.startswith('[')):
              try:
                  username = json.loads(username_raw)
              except:
                  username = username_raw
          else:
              username = username_raw
          
          if password_raw and (password_raw.startswith('{') or password_raw.startswith('[')):
              try:
                  password = json.loads(password_raw)
              except:
                  password = password_raw
          else:
              password = password_raw
      
      users_db = [
          {"username": "admin", "password": "admin123"},
          {"username": "administrator", "password": "admin"},
          {"username": "user", "password": "password"},
          {"username": "test", "password": "test123"}
      ]
      
      try:
          username_dict = username if isinstance(username, dict) else None
          password_dict = password if isinstance(password, dict) else None
          
          if username_dict or password_dict:
              if username_dict and ("$ne" in username_dict or "$gt" in username_dict or "$regex" in username_dict):
                  if username_dict.get("$ne") in ["", None] or username_dict.get("$gt") == "":
                      response = redirect('/lp/dashboard')
                      response.set_cookie('session_id', 'nosql_injection_session_12345')
                      return response
                  if "$regex" in username_dict:
                      pattern = username_dict.get("$regex", "")
                      for user in users_db:
                          import re
                          try:
                              if re.search(pattern, user["username"], re.IGNORECASE):
                                  response = redirect('/lp/dashboard')
                                  response.set_cookie('session_id', 'nosql_injection_session_12345')
                                  return response
                          except:
                              pass
                      response = redirect('/lp/dashboard')
                      response.set_cookie('session_id', 'nosql_injection_session_12345')
                      return response
              
              if username_dict and password_dict:
                  if (username_dict.get("$ne") in ["", None] and 
                      password_dict.get("$ne") in ["", None]):
                      response = redirect('/lp/dashboard')
                      response.set_cookie('session_id', 'nosql_injection_session_12345')
                      return response
              
              if username_dict and "$regex" in username_dict:
                  pattern = username_dict.get("$regex", "")
                  if "admin" in pattern.lower():
                      response = redirect('/lp/dashboard')
                      response.set_cookie('session_id', 'nosql_injection_session_12345')
                      return response
          
          username_str = username if isinstance(username, str) else str(username)
          password_str = password if isinstance(password, str) else str(password)
          
          for user in users_db:
              if user["username"] == username_str and user["password"] == password_str:
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
      
      conn = sqlite3.connect('users.db')
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
      else:
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
          conn = sqlite3.connect('users.db')
          c = conn.cursor()
          query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
          try:
              c.execute(query)
              user = c.fetchone()
              conn.close()
              
              if user:
                  # Successful login - redirect
                  response = redirect('/lp/dashboard')
                  response.set_cookie('session_id', 'captcha_session_12345')
                  return response
              return "Invalid credentials."
          except:
              conn.close()
              return "Invalid credentials."
      else:
          return "CAPTCHA verification failed. Please try again."
  
  return render_template('lp/captcha_login.html')

@app.route('/lp/xpath-login', methods=['GET', 'POST'])
def xpath_login():
  if request.method == 'POST':
      username = request.form.get('username')
      password = request.form.get('password')
      
      try:
          xpath_bypass_patterns = [
              "' or '1'='1",
              "' or ''='",
              "' or 1]%00",
              "' or /* or '",
              "' or \"a\" or '",
              "' or 1 or '",
              "' or true() or '",
              "admin' or '",
              "admin' or '1'='2"
          ]
          
          for pattern in xpath_bypass_patterns:
              if pattern in username or pattern in password:
                  response = redirect('/lp/dashboard')
                  response.set_cookie('session_id', 'xpath_injection_session_12345')
                  return response
          
          if "string-length" in username or "contains" in username or "position()" in username:
              response = redirect('/lp/dashboard')
              response.set_cookie('session_id', 'xpath_injection_session_12345')
              return response
          
          conn = sqlite3.connect('users.db')
          c = conn.cursor()
          query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
          try:
              c.execute(query)
              user = c.fetchone()
              conn.close()
              
              if user:
                  # Successful login - redirect
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
          ldap_bypass_patterns = [
              "*",
              "*)(&",
              "*)(|(&",
              "pwd)",
              "*)(|(*",
              "*))%00",
              "admin)(&)",
              "admin)(!(&(|",
              "pwd))",
              "admin))(|(|"
          ]
          
          for pattern in ldap_bypass_patterns:
              if pattern in username or pattern in password:
                  response = redirect('/lp/dashboard')
                  response.set_cookie('session_id', 'ldap_injection_session_12345')
                  return response
          
          conn = sqlite3.connect('users.db')
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

@app.route('/api/login', methods=['POST'])
def api_login():
  if request.is_json:
      data = request.get_json()
      username = data.get('username') or data.get('user') or data.get('email')
      password = data.get('password') or data.get('pass') or data.get('pwd')
      
      if username == 'admin' and password == 'admin':
          return {
              "status": "success", 
              "message": "Login successful", 
              "token": "fake_token_12345",
              "user": {
                  "id": 1,
                  "username": "admin"
              }
          }
      return {"status": "error", "message": "Invalid credentials"}, 401
  else:
      return {"status": "error", "message": "Content-Type must be application/json"}, 400

@app.route('/api/graphql', methods=['POST', 'GET'])
def graphql_login():
  if request.method == 'GET':
      return render_template('lp/graphql_login.html')
  
  if request.is_json:
      data = request.get_json()
      query = data.get('query', '')
      
      import re
      username_match = re.search(r'username[:\s]*["\']([^"\']+)["\']', query)
      password_match = re.search(r'password[:\s]*["\']([^"\']+)["\']', query)
      
      if username_match and password_match:
          username = username_match.group(1)
          password = password_match.group(1)
          
          if username == 'admin' and password == 'admin':
              return {
                  "data": {
                      "login": {
                          "token": "graphql_token_12345",
                          "user": {
                              "id": "1",
                              "username": "admin"
                          }
                      }
                  }
              }
          return {"errors": [{"message": "Invalid credentials"}]}, 401
      
      if '__schema' in query or '__type' in query:
          return {
              "data": {
                  "__schema": {
                      "queryType": {"name": "Query"},
                      "mutationType": {"name": "Mutation"}
                  }
              }
          }
      
      return {"errors": [{"message": "Invalid query"}]}, 400
  else:
      return {"errors": [{"message": "Content-Type must be application/json"}]}, 400

@app.route('/lp/graphql-login')
def graphql_login_page():
  return render_template('lp/graphql_login.html')

@app.route('/lp/test-account-login', methods=['GET', 'POST'])
def test_account_login():
  if request.method == 'POST':
      username = request.form.get('username')
      password = request.form.get('password')
      
      if username == 'testuser' and password == 'testpass123':
          response = redirect('/lp/dashboard')
          response.set_cookie('session_id', 'test_account_session_12345')
          return response
      
      conn = sqlite3.connect('users.db')
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
          conn = sqlite3.connect('users.db')
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
      else:
          return "CSRF token missing or invalid."
  
  return render_template('lp/csrf_login.html')

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

@app.route('/get-file')
def get_file():
  filename = request.args.get('file')
  filepath = os.path.join('/var/www/html/', filename)
  if os.path.exists(filepath):
      return send_file(filepath)
  else:
      abort(404)

@app.route('/file/double-encoding')
def double_encoding_file_viewer():
  filename = request.args.get('file', 'default.txt')
  filename = filename.replace('../', '')
  filepath = os.path.join('files', filename)
def double_encoding_file_viewer():
  filename = request.args.get('file', 'default.txt')
  # Filtering
  filename = filename.replace('../', '')
  filepath = os.path.join('files', filename)
  
  try:
      with open(filepath, 'r') as f:
          content = f.read()
      return render_template('file/double_encoding_viewer.html', content=content, filename=filename)
  except IOError:
      return "File not found", 404

if __name__ == '__main__':
  app.run(debug=True)