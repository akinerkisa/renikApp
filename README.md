## renikApp
renikApp is a vulnerable web application designed to demonstrate Python web application vulnerabilities. It contains code examples and test scenarios for security testing tools like HTLogin also contains code examples in the articles I write (<a href="https://akiner.medium.com/">link(TR)</a>).

## Installation
```bash
git clone https://github.com/akinerkisa/renikApp
cd renikApp
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
- **CAPTCHA Protection** (`/lp/captcha-login`) - CAPTCHA field detection
- **CSRF Protection** (`/lp/csrf-login`) - CSRF token detection and handling
- **Test Account** (`/lp/test-account-login`) - Baseline login analysis support
- **JSON API Login** (`/lp/json-login`) - JSON format login endpoint
- **Secure Login** (`/lp/secure-login`) - Secure implementation (parameterized queries)

### API Endpoints
- **JSON API** (`/api/login`) - REST API endpoint for JSON authentication
- **GraphQL API** (`/api/graphql`) - GraphQL mutation endpoint for authentication

### Other Vulnerabilities
- **SSTI** - Server-Side Template Injection demonstration
- **403 Forbidden Bypass** - Header-based bypass techniques
- **Path Traversal/File Inclusion** - File inclusion vulnerabilities (vulnerable, semi-secure, secure)

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

## Default Credentials
- `admin:admin` - Default admin credentials
- `testuser:testpass123` - Test account for baseline analysis

## Rate Limiting
Rate limit protection is implemented on `/lp/rate-limit-login`:
- Maximum 5 attempts per user/IP
- 15 second block after 5 failed attempts
- Returns HTTP 429 (Too Many Requests) when blocked

## Security Note
⚠️ **This application contains intentional vulnerabilities for educational and testing purposes only. Do not deploy in production environments.**

## Image
![Image.](https://github.com/akinerkisa/renikApp/blob/main/rnkapp.png)
