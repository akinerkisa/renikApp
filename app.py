from flask import Flask, request, render_template, abort, url_for
from jinja2 import Template
from markupsafe import escape

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(debug=True)