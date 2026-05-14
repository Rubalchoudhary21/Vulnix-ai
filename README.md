# 🛡️ Vulnix AI — Enterprise Vulnerability Scanner v2.0

An AI-powered web vulnerability scanner built with Python and Streamlit.  
Point it at any domain you own and get a full security report in minutes.

---

## What it scans for

### 🔎 Web Security (Passive)
| Check | Description |
|---|---|
| Header Analysis | Flags missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| Cookie Security | Detects cookies missing Secure, HttpOnly or SameSite flags |
| Clickjacking Check | Verifies X-Frame-Options and CSP frame-ancestors |
| Server Banner Disclosure | Catches version strings in Server / X-Powered-By headers |
| Mixed Content Detection | Finds HTTP resources loaded on HTTPS pages |
| JS Secret Scanner | Regex-scans source for API keys, tokens and credentials |

### ⚡ Active Tests
| Check | Description |
|---|---|
| XSS Injection Test | Injects a marker and checks for unescaped reflection |
| SQL Injection Probe | Appends a quote and detects database error strings |
| Open Redirect Test | Tests 9 common redirect params for external destinations |
| CORS Misconfiguration | Sends a crafted Origin and inspects the ACAO header |
| Dangerous HTTP Methods | Probes PUT, DELETE, TRACE and the Allow header |
| Rate Limit Detection | Fires 10 rapid requests and checks for HTTP 429 |

### 🖥️ Infrastructure
| Check | Description |
|---|---|
| SSL/TLS Inspection | TLS version, cipher, certificate expiry and issuer |
| WAF Detection | Fingerprints Cloudflare, Akamai, Imperva, Sucuri |
| Technology Fingerprinting | Identifies server stack, frameworks, JS libraries |
| Robots.txt Leak Scanner | Flags sensitive Disallow paths |
| Subdomain Enumeration | Resolves common subdomains (admin, api, dev, staging…) |
| Directory Discovery | Probes /admin, /.env, /swagger, /graphql and more |
| Nmap Port Scan | Fast -F scan for open ports |
| Website Screenshot | Full-resolution capture via headless Chrome |

### 🌐 Threat Intelligence
| Check | Description |
|---|---|
| WHOIS Intelligence | Registrar, creation and expiration dates |
| ASN Lookup | Maps IP to autonomous system |
| DNS Security | Checks SPF, DMARC and MX records |
| Email Harvesting | Extracts exposed email addresses from page source |

### 📄 Reporting
- Full PDF report with CVSS scores, CWE IDs and remediation steps
- Overall risk rating (Critical / High / Medium / Low)
- Per-finding impact and fix guidance

---

## Installation

**Requirements:** Python 3.9+, Google Chrome installed

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/vulnix-ai.git
cd vulnix-ai

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
streamlit run app.py
```

The app opens automatically at `http://localhost:8501`

---

## Usage

1. Open the app in your browser
2. Check the authorization consent box
3. Enter a target URL you own (e.g. `https://yourdomain.com`)
4. Click **Start AI Scan**
5. Browse the results across the 5 tabs
6. Download the PDF report from the Reporting tab

> ⚠️ Only scan systems you own or have explicit written permission to test.  
> Unauthorized scanning may violate computer crime laws in your jurisdiction.

---

## Tech stack

- **Frontend / UI** — Streamlit
- **HTTP scanning** — Requests, Selenium (screenshot)
- **Network** — Socket, SSL, Nmap
- **DNS / WHOIS** — dnspython, python-whois, ipwhois
- **Reporting** — ReportLab (PDF)

---

## License

MIT License — free to use, modify and distribute.
