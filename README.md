## renikApp
renikApp is a vulnerable web application designed to demonstrate Python web application vulnerabilities. It contains code examples and test scenarios for security testing tools like HTLogin, NoMoreForbidden., and also contains code examples in the articles I write (<a href="https://akiner.medium.com/">link(TR)</a>) and contains the applications I use in my presentations.

## Installation
```bash
git clone https://github.com/akinerkisa/renikApp
cd "renikApp"
pip install -r requirements.txt
```

## Run The Application
```bash
python app.py
```

The application will run on `http://127.0.0.1:5000`

## Features

### Login Bypass Scenarios
Comprehensive login bypass test scenarios for HTLogin and other security testing tools:

- **SQL Injection** (`/lp/insecure-login`) - Vulnerable SQL query with f-string injection
- **NoSQL Injection** (`/lp/nosql-login`) - MongoDB-like NoSQL injection with progressive testing support
- **XPath Injection** (`/lp/xpath-login`) - XPath injection vulnerability patterns
- **LDAP Injection** (`/lp/ldap-login`) - LDAP injection vulnerability patterns
- **Default Credentials** (`/lp/default-login`) - Default credential testing (admin:admin)
- **Rate Limiting** (`/lp/rate-limit-login`) - Rate limit protection (5 attempts, 15 second block)
- **Username Enumeration** (`/lp/username-enum-login`) - Different error messages reveal username existence
- **CAPTCHA Protection** (`/lp/captcha-login`) - CAPTCHA field detection (static answer: 4)
- **CSRF Protection** (`/lp/csrf-login`) - CSRF token detection and handling (broken — accepts any non-empty token)
- **Test Account** (`/lp/test-account-login`) - Baseline login analysis support
- **JSON API Login** (`/lp/json-login`) - JSON format login endpoint
- **Secure Login** (`/lp/secure-login`) - Secure implementation (parameterized queries)

### API Endpoints
- **JSON API** (`/api/login`) - REST API endpoint for JSON authentication
- **GraphQL API** (`/api/graphql`) - GraphQL mutation endpoint for authentication

### Other Web Vulnerabilities
- **SSTI** - Server-Side Template Injection demonstration (vulnerable + safe)
- **403 Forbidden Bypass** - Header-based bypass techniques (X-Forwarded-For, X-Forwarded-Host, X-Custom-IP-Authorization)
- **Path Traversal / File Inclusion** - File inclusion vulnerabilities (vulnerable, semi-secure, secure, double-encoding)

### SSRF Test Scenarios

- **OOB Confirm** (`/ssrf/query/oob`) - Triggers OOB callback via Interactsh/OAST
- **OOB Async** (`/ssrf/query/oob_async`) - Delayed async OOB callback
- **Internal IP** (`/ssrf/query/internal`) - Evidence for 127.0.0.1 / 10.x / 192.168.x
- **Cloud Metadata** (`/ssrf/query/cloud`) - Evidence for 169.254.169.254 patterns
- **Whitelist Bypass** (`/ssrf/query/whitelist`) - Whitelist filter with bypass simulation
- **Bypass Matrix** (`/ssrf/query/bypass_matrix`) - Octal, hex, decimal, IPv6-mapped IP bypass
- **Header SSRF** (`/ssrf/query/header_internal`) - X-Forwarded-Host / X-Original-URL injection
- **Form Template** (`/ssrf/form_template`) - HTML form-based SSRF target
- **JSON Template** (`/ssrf/json_template`) - Nested JSON recursive OOB scan

### ICS / SCADA Simulation
Industrial control system simulation — lab-only, no real protocols or hardware:

- **Pressure Dashboard** (`/ics/pressure`) - Real-time pressure control with setpoint, alarm threshold and SIEM log feed
- **Malware Behavior Sim** (`/ics/malware`) - Audit feed, alarm list and triggerable malware behavior scenarios
- **Trigger API** (`/ics/api/trigger_sim`) - Requires `Authorization: Bearer demo-token`

Available trigger kinds: `unexpected_process_start`, `file_integrity_change`, `high_cpu`, `memory_spike`, `outbound_connection_attempt`, `data_exfil_sim`

### Air-Gap Simulation
Stuxnet-style OT/ICS attack chain simulation (`/airgap`). Step-by-step scenario:

1. Maintenance personnel entry
2. USB/HID device vector
3. Engineering station PLC modification
4. HMI display appears normal
5. Independent sensors reveal deviation
6. OT incident response decision
7. System isolation checklist
8. Incident report

Keyboard shortcuts: `F8` start · `F9` next step · `F10` reset

## HTLogin Testing

This application is designed to work with [HTLogin](https://github.com/akinerkisa/HTLogin) for comprehensive login bypass testing.

### Test Scenarios
All login bypass scenarios are available at:
- Main page: `http://127.0.0.1:5000/lp`
- Individual scenarios: `http://127.0.0.1:5000/lp/{scenario-name}`

### Testing with HTLogin
```bash
# Test all scenarios
python main.py -l test_scenarios.txt -v on

# Test single scenario
python main.py -u http://127.0.0.1:5000/lp/insecure-login

# Test with custom credentials
python main.py -u http://127.0.0.1:5000/lp/default-login -cl credentials.txt
```

## SSRF Scenarios

```bash
# Run SSRF suite against the local lab
python main.py -u http://127.0.0.1:5000/ssrf/query/oob --oob interactsh

# Test whitelist bypass
python main.py -u http://127.0.0.1:5000/ssrf/query/whitelist --mode bypass
```

## Default Credentials
- `admin:admin` - Default admin credentials
- `testuser:testpass123` - Test account for baseline analysis
- `secure_user:password123` - Secure login reference account

## Rate Limiting
Rate limit protection is implemented on `/lp/rate-limit-login`:
- Maximum 5 attempts per user/IP
- 15 second block after 5 failed attempts
- Returns HTTP 429 (Too Many Requests) when blocked

## Security Note
⚠️ **This application contains intentional vulnerabilities for educational and testing purposes only. Do not deploy in production environments.**

