# Vulnix AI Scanner — v2.0 Enterprise Edition

import streamlit as st
import requests
import socket
import ssl
import re
import subprocess
import time
import whois
import dns.resolver
import ipaddress

from urllib.parse import urlparse, quote
from datetime import datetime
from ipwhois import IPWhois

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter

# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------

st.set_page_config(
    page_title="Vulnix AI",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------------------------------------
# SESSION
# ---------------------------------------------------

session = requests.Session()

# ---------------------------------------------------
# CSS
# ---------------------------------------------------

st.markdown("""
<style>

.stApp {
    background: #020617;
    color: white;
}
#MainMenu, footer, header { visibility: hidden; }
section[data-testid="stSidebar"] { background: #030712; }

/* ── Hero ── */
.hero-card {
    background: linear-gradient(135deg, #0f172a 0%, #020617 60%, #0c1a3a 100%);
    border: 1px solid rgba(99,102,241,0.2);
    padding: 48px 48px 36px;
    border-radius: 28px;
    margin-bottom: 10px;
    position: relative;
    overflow: hidden;
}
.hero-card::before {
    content: '';
    position: absolute;
    top: -60px; right: -60px;
    width: 320px; height: 320px;
    background: radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 70%);
    pointer-events: none;
}
.hero-title {
    font-size: 52px;
    font-weight: 800;
    letter-spacing: -1px;
    background: linear-gradient(90deg, #fff 40%, #818cf8 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
.hero-sub {
    color: #64748b;
    margin-top: 8px;
    font-size: 15px;
    letter-spacing: 0.5px;
}
.hero-badges {
    margin-top: 20px;
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.badge {
    background: rgba(99,102,241,0.12);
    border: 1px solid rgba(99,102,241,0.3);
    color: #a5b4fc;
    padding: 4px 14px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.3px;
}

/* ── Feature overview table ── */
.feature-section {
    margin: 28px 0 20px;
}
.feature-section-title {
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #475569;
    margin-bottom: 16px;
}
.feature-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 10px;
}
.feature-card {
    background: #0f172a;
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 14px;
    padding: 14px 18px;
    display: flex;
    align-items: flex-start;
    gap: 14px;
    transition: border-color 0.2s;
}
.feature-card:hover { border-color: rgba(99,102,241,0.35); }
.feature-icon {
    font-size: 20px;
    flex-shrink: 0;
    margin-top: 2px;
}
.feature-name {
    font-size: 13px;
    font-weight: 700;
    color: #e2e8f0;
}
.feature-desc {
    font-size: 12px;
    color: #64748b;
    margin-top: 2px;
    line-height: 1.4;
}
.feature-tag {
    display: inline-block;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.5px;
    padding: 2px 8px;
    border-radius: 999px;
    margin-top: 6px;
}
.tag-active   { background: rgba(239,68,68,0.15);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
.tag-passive  { background: rgba(59,130,246,0.12); color: #93c5fd; border: 1px solid rgba(59,130,246,0.3); }
.tag-infra    { background: rgba(16,185,129,0.12); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.3); }
.tag-intel    { background: rgba(234,179,8,0.12);  color: #fde047; border: 1px solid rgba(234,179,8,0.3); }

/* ── Metrics ── */
.metric-box {
    background: #0f172a;
    padding: 25px;
    border-radius: 20px;
    text-align: center;
    border: 1px solid rgba(255,255,255,0.06);
}
.metric-title { color: #94a3b8; font-size: 13px; }
.metric-value { font-size: 26px; font-weight: 700; margin-top: 10px; }

/* ── Button ── */
.stButton > button {
    width: 100%;
    background: linear-gradient(90deg, #6d28d9, #2563eb);
    color: white;
    border: none;
    border-radius: 14px;
    padding: 14px;
    font-size: 16px;
    font-weight: bold;
    letter-spacing: 0.5px;
}
.stButton > button:hover { opacity: 0.9; }

/* ── Findings ── */
.severity-critical {
    background: rgba(239,68,68,0.12);
    border-left: 4px solid #ef4444;
    padding: 15px 18px;
    border-radius: 12px;
    margin-bottom: 12px;
}
.severity-high {
    background: rgba(249,115,22,0.12);
    border-left: 4px solid #f97316;
    padding: 15px 18px;
    border-radius: 12px;
    margin-bottom: 12px;
}
.severity-medium {
    background: rgba(234,179,8,0.12);
    border-left: 4px solid #eab308;
    padding: 15px 18px;
    border-radius: 12px;
    margin-bottom: 12px;
}
.severity-low {
    background: rgba(59,130,246,0.12);
    border-left: 4px solid #3b82f6;
    padding: 15px 18px;
    border-radius: 12px;
    margin-bottom: 12px;
}
.remediation-box {
    background: rgba(16,185,129,0.10);
    border-left: 4px solid #10b981;
    padding: 14px;
    border-radius: 10px;
    margin-top: 10px;
    font-size: 13px;
}
.impact-box {
    background: rgba(168,85,247,0.10);
    border-left: 4px solid #a855f7;
    padding: 14px;
    border-radius: 10px;
    margin-top: 10px;
    font-size: 13px;
}
.info-box {
    background: rgba(14,165,233,0.08);
    border-left: 4px solid #0ea5e9;
    padding: 14px;
    border-radius: 10px;
    margin-top: 8px;
    margin-bottom: 8px;
    font-size: 13px;
}

/* ── Not-found pill ── */
.not-found-box {
    background: rgba(15,23,42,0.8);
    border: 1px dashed rgba(100,116,139,0.4);
    border-radius: 12px;
    padding: 14px 18px;
    color: #475569;
    font-size: 13px;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 10px;
}

/* ── Section label ── */
.section-label {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: #334155;
    margin: 24px 0 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------
# HERO
# ---------------------------------------------------

st.markdown("""
<div class="hero-card">
    <div class="hero-title">🛡️ Vulnix AI</div>
    <div class="hero-sub">Enterprise AI-Powered Vulnerability Scanner — v2.0 Enterprise Edition</div>
    <div class="hero-badges">
        <span class="badge">23 Security Checks</span>
        <span class="badge">Active + Passive</span>
        <span class="badge">PDF Reporting</span>
        <span class="badge">CVSS Scoring</span>
        <span class="badge">CWE Mapped</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------
# SESSION STATE
# ---------------------------------------------------

if "scanning" not in st.session_state:
    st.session_state.scanning = False

# ---------------------------------------------------
# WARNING + INPUT  (above feature cards)
# ---------------------------------------------------

st.warning(
    "⚠️  Only scan systems you own or are explicitly authorized to test. "
    "Unauthorized scanning may violate laws or service policies."
)

consent = st.checkbox("✅ I confirm I am authorized to scan this target")
url = st.text_input("Target URL", placeholder="https://example.com")

SEVERITY_CLASS = {
    "Critical": "severity-critical",
    "High":     "severity-high",
    "Medium":   "severity-medium",
    "Low":      "severity-low"
}

scan_clicked = st.button("🚀 Start AI Scan")

# ---------------------------------------------------
# FEATURE OVERVIEW TABLE (hidden once scan starts)
# ---------------------------------------------------

FEATURES = [
    # (icon, name, description, tag_class, tag_label)
    # ── Web Security / Passive ──
    ("🔒", "Header Analysis",          "Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.)", "tag-passive", "Passive"),
    ("🍪", "Cookie Security",           "Flags cookies lacking Secure, HttpOnly or SameSite attributes",          "tag-passive", "Passive"),
    ("🔍", "Clickjacking Check",        "Detects missing iframe protections (X-Frame-Options / CSP frame-ancestors)", "tag-passive", "Passive"),
    ("📢", "Server Banner Disclosure",  "Detects version strings leaked in Server / X-Powered-By headers",        "tag-passive", "Passive"),
    ("🌐", "Mixed Content Detection",   "Finds HTTP resources embedded in HTTPS pages",                           "tag-passive", "Passive"),
    ("🔑", "JS Secret Scanner",         "Regex-scans page source for API keys, tokens and credentials",          "tag-passive", "Passive"),
    # ── Active Tests ──
    ("💉", "XSS Injection Test",        "Injects a benign marker and checks for unescaped reflection",           "tag-active", "Active"),
    ("🗄️", "SQL Injection Probe",       "Appends a quote payload and detects database error patterns",           "tag-active", "Active"),
    ("↪️", "Open Redirect Test",        "Tests common redirect params for arbitrary external destination",       "tag-active", "Active"),
    ("🌍", "CORS Misconfiguration",     "Sends a crafted Origin and inspects Access-Control-Allow-Origin",       "tag-active", "Active"),
    ("⚡", "Dangerous HTTP Methods",    "Probes PUT, DELETE and TRACE; cross-checks the Allow header",           "tag-active", "Active"),
    ("🚦", "Rate Limit Detection",      "Fires 10 rapid requests and checks for HTTP 429 or rate-limit headers", "tag-active", "Active"),
    # ── Infrastructure ──
    ("🔐", "SSL/TLS Inspection",        "Verifies TLS version, cipher strength and certificate expiry",          "tag-infra", "Infra"),
    ("🧱", "WAF Detection",             "Fingerprints Cloudflare, Akamai, Imperva and Sucuri headers",           "tag-infra", "Infra"),
    ("🖥️", "Technology Fingerprinting", "Identifies server stack, frameworks and JS libraries",                  "tag-infra", "Infra"),
    ("🤖", "Robots.txt Leak Scanner",   "Flags Disallow paths that reveal sensitive internal routes",            "tag-infra", "Infra"),
    ("🌳", "Subdomain Enumeration",     "Resolves common subdomains (admin, api, dev, staging, etc.)",           "tag-infra", "Infra"),
    ("📁", "Directory Discovery",       "Probes for exposed paths like /admin, /.env, /swagger, /graphql",      "tag-infra", "Infra"),
    ("🗺️", "Nmap Port Scan",            "Runs a fast (-F) Nmap scan to enumerate open ports",                   "tag-infra", "Infra"),
    ("📸", "Website Screenshot",        "Captures a full-resolution screenshot via headless Chrome",             "tag-infra", "Infra"),
    # ── Threat Intelligence ──
    ("🏢", "WHOIS Intelligence",        "Retrieves registrar, creation and expiration date records",             "tag-intel", "Intel"),
    ("🌐", "ASN Lookup",                "Maps the server IP to its autonomous system and description",           "tag-intel", "Intel"),
    ("📧", "DNS Security",              "Checks SPF, DMARC and MX records for email security posture",          "tag-intel", "Intel"),
    ("📬", "Email Harvesting",          "Extracts email addresses exposed in the page HTML source",             "tag-intel", "Intel"),
    ("📄", "PDF Reporting",             "Generates a full findings report with CVSS scores and remediations",   "tag-intel", "Intel"),
]

cards_html = '<div class="feature-section"><div class="feature-section-title">What Vulnix AI checks for you</div><div class="feature-grid">'
for icon, name, desc, tag_cls, tag_lbl in FEATURES:
    cards_html += f"""
    <div class="feature-card">
        <div class="feature-icon">{icon}</div>
        <div>
            <div class="feature-name">{name}</div>
            <div class="feature-desc">{desc}</div>
            <span class="feature-tag {tag_cls}">{tag_lbl}</span>
        </div>
    </div>"""
cards_html += '</div></div>'

if not st.session_state.scanning:
    st.markdown(cards_html, unsafe_allow_html=True)

# ===================================================
# HELPER / UTILITY FUNCTIONS
# ===================================================

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def validate_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            st.error("Invalid URL: could not extract domain.")
            return None, None
        resolved_ip = socket.gethostbyname(domain)
        if is_private_ip(resolved_ip):
            st.error("Private/Internal IP scanning blocked.")
            return None, None
        response = session.get(
            url, timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True
        )
        return response, url
    except Exception as error:
        st.error(f"Connection error: {error}")
        return None, None


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Unable to Resolve"


def not_found(message: str):
    """Render a consistent 'nothing detected' pill."""
    st.markdown(
        f'<div class="not-found-box">✓ &nbsp;{message}</div>',
        unsafe_allow_html=True
    )


def render_finding(finding, severity_class):
    css = severity_class.get(finding["severity"], "severity-low")
    st.markdown(
        f'''<div class="{css}">
        <h4 style="margin:0 0 4px">{finding["title"]}</h4>
        <p style="margin:0;font-size:13px;color:#94a3b8"><b>Severity:</b> {finding["severity"]}
        &nbsp;|&nbsp; <b>CWE:</b> {finding["cwe"]}
        &nbsp;|&nbsp; <b>CVSS:</b> {finding["cvss"]}</p>
        </div>''',
        unsafe_allow_html=True
    )
    with st.expander(f"View Details — {finding['title']}"):
        st.write(finding.get("description", ""))
        st.markdown(
            f'<div class="impact-box"><b>Impact:</b><br>{finding["impact"]}</div>',
            unsafe_allow_html=True
        )
        st.markdown(
            f'<div class="remediation-box"><b>Remediation:</b><br>{finding["remediation"]}</div>',
            unsafe_allow_html=True
        )
        st.code(f"CWE: {finding['cwe']}   |   CVSS: {finding['cvss']}")


# ===================================================
# SCAN FUNCTIONS
# ===================================================

def check_headers(headers):
    findings = []
    required = {
        "Content-Security-Policy": {
            "severity": "High",
            "impact": "XSS attacks may become easier.",
            "remediation": "Implement a strict Content-Security-Policy.",
            "cwe": "CWE-693", "cvss": "6.5"
        },
        "Strict-Transport-Security": {
            "severity": "Medium",
            "impact": "Users may be downgraded to insecure HTTP.",
            "remediation": "Enable HSTS with long max-age.",
            "cwe": "CWE-319", "cvss": "5.3"
        },
        "X-Frame-Options": {
            "severity": "Medium",
            "impact": "Application may be vulnerable to clickjacking.",
            "remediation": "Use SAMEORIGIN or DENY.",
            "cwe": "CWE-1021", "cvss": "4.3"
        },
        "X-Content-Type-Options": {
            "severity": "Low",
            "impact": "Browser MIME sniffing may occur.",
            "remediation": "Use X-Content-Type-Options: nosniff.",
            "cwe": "CWE-16", "cvss": "3.1"
        }
    }
    for header, details in required.items():
        if header not in headers:
            findings.append({
                "title": f"Missing {header}",
                "severity": details["severity"],
                "description": f"The HTTP response does not contain the {header} header.",
                "impact": details["impact"],
                "remediation": details["remediation"],
                "cwe": details["cwe"],
                "cvss": details["cvss"]
            })
    return findings


def ssl_check(domain):
    result = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_socket:
                cert = secure_socket.getpeercert()
                result["TLS Version"] = secure_socket.version()
                cipher_tuple = secure_socket.cipher()
                result["Cipher"] = {
                    "name": cipher_tuple[0],
                    "protocol": cipher_tuple[1],
                    "bits": cipher_tuple[2]
                }
                result["Certificate Expiry"] = cert.get("notAfter", "Unknown")
                issuer_raw = cert.get("issuer", ())
                result["Issuer"] = {k: v for pair in issuer_raw for k, v in [pair[0]]}
    except ssl.SSLError as e:
        result["SSL Error"] = str(e)
    except ConnectionRefusedError:
        result["Error"] = "Port 443 not open or connection refused."
    except Exception as error:
        result["Error"] = str(error)
    return result


def detect_waf(headers):
    wafs = []
    server = headers.get("Server", "").lower()
    if "cloudflare" in server:
        wafs.append("Cloudflare")
    if "akamai" in server:
        wafs.append("Akamai")
    if "imperva" in server:
        wafs.append("Imperva")
    header_keys_lower = [h.lower() for h in headers]
    if "cf-ray" in header_keys_lower and "Cloudflare" not in wafs:
        wafs.append("Cloudflare")
    if "x-sucuri-id" in header_keys_lower:
        wafs.append("Sucuri")
    return wafs


def detect_technologies(headers, html):
    technologies = []
    server = headers.get("Server")
    if server:
        technologies.append(server)
    powered_by = headers.get("X-Powered-By")
    if powered_by:
        technologies.append(powered_by)
    html_lower = html.lower()
    if "wordpress" in html_lower:
        technologies.append("WordPress")
    if "react" in html_lower:
        technologies.append("React")
    if "jquery" in html_lower:
        technologies.append("jQuery")
    if "vue" in html_lower:
        technologies.append("Vue.js")
    if "angular" in html_lower:
        technologies.append("Angular")
    return list(set(technologies))


def sensitive_scan(html):
    findings = []
    patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"AIza[0-9A-Za-z_-]{35}",
        r"-----BEGIN RSA PRIVATE KEY-----",
        r"(?i)password\s*=\s*['\"][^'\"]+",
    ]
    for pattern in patterns:
        matches = re.findall(pattern, html)
        for match in matches:
            findings.append(match)
    return findings


def cookie_analysis(response):
    findings = []
    for cookie in response.cookies:
        issues = []
        if not cookie.secure:
            issues.append("Secure Flag Missing")
        rest_keys_lower = {k.lower() for k in getattr(cookie, "_rest", {}).keys()}
        if "httponly" not in rest_keys_lower:
            issues.append("HttpOnly Missing")
        if "samesite" not in rest_keys_lower:
            issues.append("SameSite Missing")
        if issues:
            findings.append({"cookie": cookie.name, "issues": issues})
    return findings


def subdomain_enum(domain):
    base = domain.lower()
    if base.startswith("www."):
        base = base[4:]
    common = ["www", "mail", "api", "admin", "dev", "test", "staging", "vpn"]
    found = []
    for sub in common:
        full = f"{sub}.{base}"
        try:
            socket.gethostbyname(full)
            found.append(full)
        except Exception:
            pass
    return found


def directory_bruteforce(url):
    directories = ["/admin", "/backup", "/uploads", "/swagger", "/graphql", "/.env", "/config"]
    findings = []
    for path in directories:
        try:
            target = url.rstrip("/") + path
            response = session.get(target, timeout=5, allow_redirects=False)
            if response.status_code in [200, 401, 403]:
                findings.append({"path": target, "status": response.status_code})
            time.sleep(0.5)
        except Exception:
            pass
    return findings


def whois_lookup(domain):
    try:
        data = whois.whois(domain)
        return {
            "Registrar": data.registrar,
            "Creation Date": str(data.creation_date),
            "Expiration Date": str(data.expiration_date)
        }
    except Exception as error:
        return {"Error": str(error)}


def asn_lookup(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return {
            "ASN": result.get("asn"),
            "Description": result.get("asn_description")
        }
    except Exception as error:
        return {"Error": str(error)}


def dns_security(domain):
    findings = {}
    try:
        mx = dns.resolver.resolve(domain, "MX")
        findings["MX"] = [str(x.exchange) for x in mx]
    except Exception:
        findings["MX"] = []
    try:
        txt = dns.resolver.resolve(domain, "TXT")
        records = [str(x) for x in txt]
        findings["SPF"] = any("spf1" in r.lower() for r in records)
    except Exception:
        findings["SPF"] = False
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_txt = " ".join(str(r) for r in dmarc_records)
        findings["DMARC"] = "v=DMARC1" in dmarc_txt
    except Exception:
        findings["DMARC"] = False
    return findings


def run_nmap(domain):
    try:
        command = ["nmap", "-Pn", "-F", domain]
        result = subprocess.check_output(
            command, text=True, timeout=60, stderr=subprocess.STDOUT
        )
        return result
    except FileNotFoundError:
        return "⚠️  nmap is not installed or not found in PATH."
    except subprocess.TimeoutExpired:
        return "⚠️  nmap scan timed out after 60 seconds."
    except subprocess.CalledProcessError as e:
        return f"nmap error (exit {e.returncode}):\n{e.output}"
    except Exception as error:
        return f"Unexpected error: {error}"


def capture_screenshot(url):
    try:
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        service = Service()
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_window_size(1920, 1080)
        driver.get(url)
        time.sleep(3)
        filename = "screenshot.png"
        driver.save_screenshot(filename)
        driver.quit()
        return filename
    except Exception:
        return None


# ── Active checks ──────────────────────────────────

def test_xss(url):
    findings = []
    payload = "<script>vulnixXSS</script>"
    sep = "&" if "?" in url else "?"
    test_url = url + sep + "q=" + quote(payload)
    try:
        resp = session.get(test_url, timeout=8,
                           headers={"User-Agent": "Mozilla/5.0"},
                           allow_redirects=True)
        if "vulnixXSS" in resp.text and "<script>" in resp.text:
            findings.append({
                "title": "Reflected XSS Detected",
                "severity": "High",
                "description": (
                    "The injected script marker was reflected unescaped in the response body, "
                    "indicating the application does not sanitise user input before rendering it."
                ),
                "impact": (
                    "An attacker can craft a malicious URL that executes arbitrary JavaScript "
                    "in a victim's browser, enabling session hijacking, credential theft, "
                    "or drive-by malware delivery."
                ),
                "remediation": (
                    "HTML-encode all user-supplied values before rendering them in responses. "
                    "Use a templating engine with auto-escaping. Enforce a strict "
                    "Content-Security-Policy to limit script execution."
                ),
                "cwe": "CWE-79", "cvss": "7.2"
            })
    except Exception:
        pass
    return findings


def test_sqli(url):
    findings = []
    sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg::syntaxerror",
        "sqlite3::exception",
        "ora-01756",
        "microsoft ole db",
        "odbc microsoft access",
        "syntax error at or near",
    ]
    sep = "&" if "?" in url else "?"
    test_url = url + sep + "id=" + quote("'")
    try:
        resp = session.get(test_url, timeout=8,
                           headers={"User-Agent": "Mozilla/5.0"},
                           allow_redirects=True)
        body_lower = resp.text.lower()
        matched = [e for e in sql_errors if e in body_lower]
        if matched:
            findings.append({
                "title": "SQL Injection Vulnerability Detected",
                "severity": "Critical",
                "description": (
                    f"The application returned a database error after a quote injection. "
                    f"Matched error pattern: '{matched[0]}'."
                ),
                "impact": (
                    "An attacker can extract, modify, or delete database contents, "
                    "bypass authentication, read server files, or execute OS commands."
                ),
                "remediation": (
                    "Use parameterised queries / prepared statements exclusively. "
                    "Never concatenate user input into SQL strings. "
                    "Apply strict input validation and a least-privilege database account."
                ),
                "cwe": "CWE-89", "cvss": "9.8"
            })
    except Exception:
        pass
    return findings


def test_open_redirect(url):
    findings = []
    canary = "https://evil.vulnix-test.com"
    params = [
        "next", "url", "redirect", "return",
        "returnUrl", "goto", "dest", "destination", "location"
    ]
    sep = "&" if "?" in url else "?"
    for param in params:
        test_url = url + sep + f"{param}={quote(canary)}"
        try:
            resp = session.get(test_url, timeout=6,
                               headers={"User-Agent": "Mozilla/5.0"},
                               allow_redirects=False)
            location = resp.headers.get("Location", "")
            if "evil.vulnix-test.com" in location:
                findings.append({
                    "title": f"Open Redirect via '{param}' Parameter",
                    "severity": "Medium",
                    "description": (
                        f"The server issued a redirect to an attacker-controlled URL "
                        f"when '{param}' was set to an external domain."
                    ),
                    "impact": (
                        "Attackers can craft phishing URLs that appear to originate from "
                        "the legitimate domain, bypassing spam filters and deceiving users."
                    ),
                    "remediation": (
                        "Validate redirect targets against a strict allowlist of trusted "
                        "internal paths or domains. Reject absolute URLs in redirect params."
                    ),
                    "cwe": "CWE-601", "cvss": "6.1"
                })
                break
        except Exception:
            pass
    return findings


def check_cors(url):
    findings = []
    evil_origin = "https://evil.attacker.com"
    try:
        resp = session.get(url, timeout=8,
                           headers={"User-Agent": "Mozilla/5.0", "Origin": evil_origin},
                           allow_redirects=True)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*":
            findings.append({
                "title": "CORS Wildcard Origin (*) Misconfiguration",
                "severity": "Medium",
                "description": "The server responds with 'Access-Control-Allow-Origin: *'.",
                "impact": "Any web page can read API responses from this server via cross-origin XHR.",
                "remediation": "Restrict ACAO to a specific allowlist of trusted origins.",
                "cwe": "CWE-942", "cvss": "6.5"
            })
        elif acao == evil_origin:
            sev = "Critical" if acac == "true" else "High"
            findings.append({
                "title": "CORS Origin Reflection Detected",
                "severity": sev,
                "description": (
                    "The server blindly echoes the attacker-supplied Origin header"
                    + (" with credentials enabled." if acac == "true" else ".")
                ),
                "impact": (
                    "Any website can make credentialed cross-origin requests and read "
                    "authenticated responses." if acac == "true" else
                    "Any website can read cross-origin responses from this server."
                ),
                "remediation": (
                    "Maintain a strict allowlist of permitted origins. "
                    "Never reflect arbitrary origins."
                ),
                "cwe": "CWE-942",
                "cvss": "8.1" if sev == "Critical" else "6.8"
            })
    except Exception:
        pass
    return findings


def check_clickjacking(headers):
    findings = []
    xfo = headers.get("X-Frame-Options", "").upper()
    csp = headers.get("Content-Security-Policy", "").lower()
    has_xfo = xfo in ("DENY", "SAMEORIGIN")
    has_frame_ancestors = "frame-ancestors" in csp
    if not has_xfo and not has_frame_ancestors:
        findings.append({
            "title": "Clickjacking Protection Missing",
            "severity": "Medium",
            "description": (
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is present."
            ),
            "impact": (
                "Attackers can overlay the site in a transparent iframe to trick users "
                "into clicking hidden buttons (UI redress / clickjacking attack)."
            ),
            "remediation": (
                "Add 'X-Frame-Options: SAMEORIGIN' or "
                "'frame-ancestors 'self'' in your Content-Security-Policy."
            ),
            "cwe": "CWE-1021", "cvss": "4.3"
        })
    return findings


def check_http_methods(url):
    findings = []
    dangerous = ["PUT", "DELETE", "TRACE"]
    allowed_found = []
    for method in dangerous:
        try:
            resp = session.request(method, url, timeout=6,
                                   headers={"User-Agent": "Mozilla/5.0"},
                                   allow_redirects=False)
            if resp.status_code not in [405, 501, 403]:
                allowed_found.append(f"{method} (HTTP {resp.status_code})")
        except Exception:
            pass
    try:
        opts = session.options(url, timeout=6,
                               headers={"User-Agent": "Mozilla/5.0"},
                               allow_redirects=False)
        allow_header = opts.headers.get("Allow", "")
        for method in dangerous:
            already = any(method in m for m in allowed_found)
            if method in allow_header and not already:
                allowed_found.append(f"{method} (via Allow header)")
    except Exception:
        pass
    if allowed_found:
        method_list = ", ".join(allowed_found)
        findings.append({
            "title": f"Dangerous HTTP Methods Enabled: {method_list}",
            "severity": "High",
            "description": f"The server accepts one or more dangerous HTTP methods: {method_list}.",
            "impact": (
                "PUT allows arbitrary file uploads. DELETE allows resource removal. "
                "TRACE enables Cross-Site Tracing (XST) which may expose HttpOnly cookies."
            ),
            "remediation": (
                "Disable all unnecessary HTTP methods at the web server level. "
                "A standard web app typically needs only GET and POST."
            ),
            "cwe": "CWE-650", "cvss": "7.5"
        })
    return findings


def check_robots(url):
    result = {"paths": [], "sensitive": [], "raw": ""}
    sensitive_kw = [
        "admin", "backup", "config", "secret", "private",
        "upload", "api", "login", "dashboard", "db", "database",
        "test", "dev", "staging", "internal", "hidden"
    ]
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        resp = session.get(robots_url, timeout=8,
                           headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and "disallow" in resp.text.lower():
            result["raw"] = resp.text
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        result["paths"].append(path)
                        if any(kw in path.lower() for kw in sensitive_kw):
                            result["sensitive"].append(path)
        elif resp.status_code == 404:
            result["raw"] = "robots.txt not found (404)."
        else:
            result["raw"] = f"HTTP {resp.status_code} — no parseable content."
    except Exception as e:
        result["raw"] = f"Error: {e}"
    return result


def check_server_banner(headers):
    findings = []
    version_pattern = re.compile(r"\d+\.\d+")
    disclosure_headers = [
        "Server", "X-Powered-By",
        "X-AspNet-Version", "X-AspNetMvc-Version"
    ]
    for header_name in disclosure_headers:
        value = headers.get(header_name, "")
        if value and version_pattern.search(value):
            findings.append({
                "title": f"Version Disclosure via '{header_name}' Header",
                "severity": "Low",
                "description": (
                    f"The response header '{header_name}: {value}' reveals "
                    f"software version information."
                ),
                "impact": (
                    "Attackers can quickly identify known CVEs for the disclosed "
                    "version without active probing."
                ),
                "remediation": (
                    f"Suppress the '{header_name}' header. "
                    "In Apache use 'ServerTokens Prod'; in Nginx use 'server_tokens off'."
                ),
                "cwe": "CWE-200", "cvss": "5.3"
            })
    return findings


def check_rate_limit(url):
    findings = []
    got_limited = False
    limit_header_names = {
        "x-ratelimit-limit", "x-rate-limit-limit",
        "ratelimit-limit", "retry-after", "x-ratelimit-remaining"
    }
    try:
        for _ in range(10):
            resp = session.get(url, timeout=5,
                               headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 429:
                got_limited = True
                break
            resp_headers_lower = {k.lower() for k in resp.headers}
            if resp_headers_lower & limit_header_names:
                got_limited = True
                break
    except Exception:
        pass
    if not got_limited:
        findings.append({
            "title": "No Rate Limiting Detected",
            "severity": "Medium",
            "description": (
                "10 rapid requests were sent with no HTTP 429 response "
                "or standard rate-limit headers observed."
            ),
            "impact": (
                "Attackers can brute-force login credentials, abuse API endpoints, "
                "scrape data at scale, or overwhelm the server."
            ),
            "remediation": (
                "Implement request rate limiting at the application or reverse-proxy level. "
                "Return HTTP 429 with a Retry-After header when limits are exceeded."
            ),
            "cwe": "CWE-770", "cvss": "5.8"
        })
    return findings


def detect_mixed_content(html, url):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return findings
    http_resources = re.findall(
        r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']',
        html, re.IGNORECASE
    )
    if http_resources:
        sample = http_resources[:3]
        findings.append({
            "title": f"Mixed Content Detected ({len(http_resources)} resource(s))",
            "severity": "Medium",
            "description": (
                f"The HTTPS page loads {len(http_resources)} resource(s) over plain HTTP. "
                f"Sample URLs: {sample}"
            ),
            "impact": (
                "A network attacker can intercept and tamper with HTTP sub-resources "
                "even on an HTTPS page."
            ),
            "remediation": (
                "Update all embedded resource URLs to HTTPS. "
                "Enable HSTS and use a CSP 'upgrade-insecure-requests' directive."
            ),
            "cwe": "CWE-319", "cvss": "5.4"
        })
    return findings


def harvest_emails(html):
    email_pattern = re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    )
    false_positive_domains = {
        "example.com", "test.com", "sentry.io",
        "w3.org", "schema.org", "domain.com"
    }
    all_emails = set(email_pattern.findall(html))
    filtered = [
        e for e in all_emails
        if e.split("@")[-1].lower() not in false_positive_domains
    ]
    return sorted(filtered)


# ===================================================
# PDF REPORT
# ===================================================

def generate_pdf(domain, risk, cvss, findings):
    filename = "vulnix_report.pdf"
    document = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("Vulnix AI Security Report", styles["Title"]))
    content.append(Spacer(1, 12))
    content.append(Paragraph(f"Target: {domain}", styles["BodyText"]))
    content.append(Paragraph(f"Risk Level: {risk}", styles["BodyText"]))
    content.append(Paragraph(f"CVSS Score: {cvss}", styles["BodyText"]))
    content.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["BodyText"]
    ))
    content.append(Spacer(1, 20))

    if findings:
        content.append(Paragraph("Vulnerability Summary", styles["Heading2"]))
        content.append(Spacer(1, 8))
        table_data = [["#", "Title", "Severity", "CWE", "CVSS"]]
        for i, f in enumerate(findings, 1):
            table_data.append([
                str(i), f.get("title", ""), f.get("severity", ""),
                f.get("cwe", ""), f.get("cvss", "")
            ])
        tbl = Table(table_data, colWidths=[25, 230, 65, 70, 50])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        content.append(tbl)
        content.append(Spacer(1, 20))

        content.append(Paragraph("Detailed Findings", styles["Heading2"]))
        content.append(Spacer(1, 8))
        for i, f in enumerate(findings, 1):
            content.append(Paragraph(
                f"{i}. {f.get('title', '')} [{f.get('severity', '')}]",
                styles["Heading3"]
            ))
            content.append(Paragraph(f"Description: {f.get('description', '')}", styles["BodyText"]))
            content.append(Paragraph(f"Impact: {f.get('impact', '')}", styles["BodyText"]))
            content.append(Paragraph(f"Remediation: {f.get('remediation', '')}", styles["BodyText"]))
            content.append(Paragraph(
                f"CWE: {f.get('cwe', '')}  |  CVSS: {f.get('cvss', '')}",
                styles["BodyText"]
            ))
            content.append(Spacer(1, 12))
    else:
        content.append(Paragraph("No vulnerabilities detected.", styles["BodyText"]))

    document.build(content)
    return filename


# ===================================================
# SIDEBAR
# ===================================================

st.sidebar.title("🛡️ Vulnix AI")
st.sidebar.markdown("### Checks Included")
for icon, name, _, tag_cls, tag_lbl in FEATURES:
    tag_color = {
        "tag-active":  "#f87171",
        "tag-passive": "#93c5fd",
        "tag-infra":   "#6ee7b7",
        "tag-intel":   "#fde047",
    }.get(tag_cls, "#94a3b8")
    st.sidebar.markdown(
        f'<span style="color:{tag_color}">●</span> {icon} {name}',
        unsafe_allow_html=True
    )

# ===================================================
# MAIN SCAN FLOW
# ===================================================

if scan_clicked:

    if not consent:
        st.error("You must confirm authorization before scanning.")
        st.stop()
    if not url.strip():
        st.error("Please enter a target URL.")
        st.stop()

    # Hide the feature overview table for the rest of this run
    st.session_state.scanning = True

    progress = st.progress(0)
    status = st.empty()

    normalized_url = url if url.startswith(("http://", "https://")) else "https://" + url
    parsed = urlparse(normalized_url)
    domain = parsed.hostname

    status.write("🔌 Connecting to target…")
    progress.progress(5)

    response, final_url = validate_url(url)
    if not response:
        st.stop()

    headers = response.headers
    html = response.text

    # ── Top metrics ────────────────────────────────
    progress.progress(12)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f'''<div class="metric-box">
            <div class="metric-title">Target</div>
            <div class="metric-value">{domain}</div></div>''',
            unsafe_allow_html=True)
    with col2:
        st.markdown(f'''<div class="metric-box">
            <div class="metric-title">IP Address</div>
            <div class="metric-value">{get_ip(domain)}</div></div>''',
            unsafe_allow_html=True)
    with col3:
        st.markdown(f'''<div class="metric-box">
            <div class="metric-title">HTTP Status</div>
            <div class="metric-value">{response.status_code}</div></div>''',
            unsafe_allow_html=True)

    # ── Tabs ───────────────────────────────────────
    main_tab, active_tab, infra_tab, intel_tab, report_tab = st.tabs([
        "🔎 Web Security",
        "⚡ Active Tests",
        "🖥️ Infrastructure",
        "🌐 Threat Intelligence",
        "📄 Reporting"
    ])

    all_findings = []

    # ─────────────────────────────────────────────────────────
    # TAB 1 — WEB SECURITY
    # ─────────────────────────────────────────────────────────
    status.write("🔍 Checking security headers…")
    progress.progress(20)

    header_findings      = check_headers(headers)
    clickjack_findings   = check_clickjacking(headers)
    banner_findings      = check_server_banner(headers)
    cookie_findings      = cookie_analysis(response)
    secrets              = sensitive_scan(html)
    mixed_content_findings = detect_mixed_content(html, final_url)

    all_findings.extend(header_findings)
    all_findings.extend(clickjack_findings)
    all_findings.extend(banner_findings)
    all_findings.extend(mixed_content_findings)

    with main_tab:

        # Header Analysis
        st.markdown('<div class="section-label">🔒 Header Analysis</div>', unsafe_allow_html=True)
        if header_findings:
            for f in header_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("All major security headers are present — no issues detected.")

        # Clickjacking
        st.markdown('<div class="section-label">🔍 Clickjacking Check</div>', unsafe_allow_html=True)
        if clickjack_findings:
            for f in clickjack_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("Clickjacking protection is in place (X-Frame-Options or CSP frame-ancestors found).")

        # Server Banner
        st.markdown('<div class="section-label">📢 Server Banner Disclosure</div>', unsafe_allow_html=True)
        if banner_findings:
            for f in banner_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("No version strings found in response headers — banner is clean.")

        # Mixed Content
        st.markdown('<div class="section-label">🌐 Mixed Content Detection</div>', unsafe_allow_html=True)
        if mixed_content_findings:
            for f in mixed_content_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("No mixed content detected — all resources are loaded over HTTPS.")

        # Cookie Security
        st.markdown('<div class="section-label">🍪 Cookie Security Analysis</div>', unsafe_allow_html=True)
        if cookie_findings:
            for cf in cookie_findings:
                st.warning(f"🍪 **{cf['cookie']}** → Issues: {', '.join(cf['issues'])}")
        else:
            not_found("No cookies found, or all cookies carry Secure / HttpOnly / SameSite flags.")

        # JS Secret Scanner
        st.markdown('<div class="section-label">🔑 JS Secret Scanner</div>', unsafe_allow_html=True)
        if secrets:
            for s in secrets:
                st.error(f"⚠️ Potential secret: `{s[:80]}`")
        else:
            not_found("No API keys, tokens or credentials detected in page source.")

    # ─────────────────────────────────────────────────────────
    # TAB 2 — ACTIVE TESTS
    # ─────────────────────────────────────────────────────────
    status.write("⚡ Running active injection tests…")
    progress.progress(40)

    xss_findings      = test_xss(final_url)
    sqli_findings     = test_sqli(final_url)
    redirect_findings = test_open_redirect(final_url)
    cors_findings     = check_cors(final_url)
    method_findings   = check_http_methods(final_url)
    rate_findings     = check_rate_limit(final_url)

    all_findings.extend(xss_findings)
    all_findings.extend(sqli_findings)
    all_findings.extend(redirect_findings)
    all_findings.extend(cors_findings)
    all_findings.extend(method_findings)
    all_findings.extend(rate_findings)

    with active_tab:

        # XSS
        st.markdown('<div class="section-label">💉 XSS Injection Test</div>', unsafe_allow_html=True)
        if xss_findings:
            for f in xss_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("No reflected XSS detected — injected marker was not echoed unescaped.")

        # SQLi
        st.markdown('<div class="section-label">🗄️ SQL Injection Probe</div>', unsafe_allow_html=True)
        if sqli_findings:
            for f in sqli_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("No SQL error patterns detected after quote-injection probe.")

        # Open Redirect
        st.markdown('<div class="section-label">↪️ Open Redirect Test</div>', unsafe_allow_html=True)
        if redirect_findings:
            for f in redirect_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("No open redirect behaviour detected across all common redirect parameters.")

        # CORS
        st.markdown('<div class="section-label">🌍 CORS Misconfiguration</div>', unsafe_allow_html=True)
        if cors_findings:
            for f in cors_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("CORS policy appears correctly configured — no wildcard or reflected origin found.")

        # HTTP Methods
        st.markdown('<div class="section-label">⚡ Dangerous HTTP Methods</div>', unsafe_allow_html=True)
        if method_findings:
            for f in method_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("No dangerous HTTP methods (PUT / DELETE / TRACE) were accepted by the server.")

        # Rate Limit
        st.markdown('<div class="section-label">🚦 Rate Limit Detection</div>', unsafe_allow_html=True)
        if rate_findings:
            for f in rate_findings:
                render_finding(f, SEVERITY_CLASS)
        else:
            not_found("Rate limiting is active — HTTP 429 or rate-limit headers were observed.")

    # ─────────────────────────────────────────────────────────
    # TAB 3 — INFRASTRUCTURE
    # ─────────────────────────────────────────────────────────
    status.write("🖥️ Running infrastructure analysis…")
    progress.progress(65)

    robots_data = check_robots(final_url)

    with infra_tab:

        # SSL/TLS
        st.markdown('<div class="section-label">🔐 SSL / TLS Inspection</div>', unsafe_allow_html=True)
        ssl_result = ssl_check(domain)
        if "Error" in ssl_result or "SSL Error" in ssl_result:
            not_found(f"SSL check returned an error: {ssl_result.get('Error') or ssl_result.get('SSL Error')}")
        else:
            st.json(ssl_result)

        # WAF
        st.markdown('<div class="section-label">🧱 WAF Detection</div>', unsafe_allow_html=True)
        wafs = detect_waf(headers)
        if wafs:
            for waf in wafs:
                st.success(f"✅ WAF Detected: **{waf}**")
        else:
            not_found("No WAF layer detected in response headers — site may be unprotected or using a custom layer.")

        # Technology Fingerprinting
        st.markdown('<div class="section-label">🖥️ Technology Fingerprinting</div>', unsafe_allow_html=True)
        techs = detect_technologies(headers, html)
        if techs:
            for tech in techs:
                st.success(f"🔧 {tech}")
        else:
            not_found("No specific technologies could be fingerprinted from headers or page source.")

        # Robots.txt
        st.markdown('<div class="section-label">🤖 Robots.txt Leak Scanner</div>', unsafe_allow_html=True)
        if robots_data["paths"]:
            st.info(f"Found **{len(robots_data['paths'])}** Disallow path(s) in robots.txt.")
            if robots_data["sensitive"]:
                st.error(
                    f"⚠️ **{len(robots_data['sensitive'])} sensitive path(s)** exposed: "
                    + ", ".join(f"`{p}`" for p in robots_data["sensitive"])
                )
            else:
                not_found("No sensitive keywords in any Disallow path.")
            with st.expander("View all Disallow paths"):
                for p in robots_data["paths"]:
                    label = "🔴" if p in robots_data["sensitive"] else "⚪"
                    st.write(f"{label} `{p}`")
            with st.expander("View raw robots.txt"):
                st.code(robots_data["raw"], language="text")
        else:
            not_found("robots.txt not found or contains no Disallow paths.")

        # Subdomain Enumeration
        st.markdown('<div class="section-label">🌳 Subdomain Enumeration</div>', unsafe_allow_html=True)
        subdomains = subdomain_enum(domain)
        if subdomains:
            for sub in subdomains:
                st.success(f"🌐 {sub}")
        else:
            not_found("No common subdomains (www, api, admin, dev, staging…) resolved successfully.")

        # Directory Discovery
        st.markdown('<div class="section-label">📁 Directory Discovery</div>', unsafe_allow_html=True)
        directories = directory_bruteforce(final_url)
        if directories:
            for item in directories:
                st.warning(f"`{item['path']}` — HTTP {item['status']}")
        else:
            not_found("No sensitive directories (/admin, /.env, /swagger…) returned 200 / 401 / 403.")

        # Nmap
        st.markdown('<div class="section-label">🗺️ Nmap Port Scan</div>', unsafe_allow_html=True)
        nmap_result = run_nmap(domain)
        if nmap_result.startswith("⚠️"):
            not_found(nmap_result)
        else:
            st.code(nmap_result, language="text")

        # Screenshot
        st.markdown('<div class="section-label">📸 Website Screenshot</div>', unsafe_allow_html=True)
        screenshot = capture_screenshot(final_url)
        if screenshot:
            st.image(screenshot, use_container_width=True)
        else:
            not_found("Screenshot capture failed — Chrome / ChromeDriver may not be installed in this environment.")

    # ─────────────────────────────────────────────────────────
    # TAB 4 — THREAT INTELLIGENCE
    # ─────────────────────────────────────────────────────────
    status.write("🌐 Collecting threat intelligence…")
    progress.progress(85)

    emails = harvest_emails(html)

    with intel_tab:

        # WHOIS
        st.markdown('<div class="section-label">🏢 WHOIS Intelligence</div>', unsafe_allow_html=True)
        whois_data = whois_lookup(domain)
        if "Error" in whois_data:
            not_found(f"WHOIS lookup failed: {whois_data['Error']}")
        else:
            st.json(whois_data)

        # ASN
        st.markdown('<div class="section-label">🌐 ASN Lookup</div>', unsafe_allow_html=True)
        asn_data = asn_lookup(get_ip(domain))
        if "Error" in asn_data:
            not_found(f"ASN lookup failed: {asn_data['Error']}")
        else:
            st.json(asn_data)

        # DNS Security
        st.markdown('<div class="section-label">📧 DNS Security (SPF / DMARC / MX)</div>', unsafe_allow_html=True)
        dns_data = dns_security(domain)
        st.json(dns_data)
        if not dns_data.get("SPF"):
            st.warning("⚠️ SPF record not found — email spoofing may be possible.")
        if not dns_data.get("DMARC"):
            st.warning("⚠️ DMARC record not found — no email authentication policy enforced.")
        if not dns_data.get("MX"):
            not_found("No MX records found for this domain.")

        # Email Harvesting
        st.markdown('<div class="section-label">📬 Email Harvesting</div>', unsafe_allow_html=True)
        if emails:
            st.warning(f"⚠️ **{len(emails)} email address(es)** found exposed in page source:")
            for email in emails:
                st.markdown(f'<div class="info-box">📧 {email}</div>', unsafe_allow_html=True)
        else:
            not_found("No email addresses found exposed in page source.")

    # ─────────────────────────────────────────────────────────
    # TAB 5 — REPORTING
    # ─────────────────────────────────────────────────────────
    total = len(all_findings)
    severity_counts = {s: 0 for s in ["Critical", "High", "Medium", "Low"]}
    for f in all_findings:
        sev = f.get("severity", "Low")
        if sev in severity_counts:
            severity_counts[sev] += 1

    risk = "Low"
    if severity_counts["Critical"] > 0:
        risk = "Critical"
    elif severity_counts["High"] > 0:
        risk = "High"
    elif severity_counts["Medium"] >= 2:
        risk = "Medium"

    cvss = min(round(total * 1.5, 1), 10.0)

    with report_tab:

        st.markdown('<div class="section-label">📊 Risk Assessment</div>', unsafe_allow_html=True)
        rc1, rc2, rc3, rc4, rc5 = st.columns(5)
        rc1.metric("Overall Risk", risk)
        rc2.metric("CVSS Score", cvss)
        rc3.metric("🔴 Critical", severity_counts["Critical"])
        rc4.metric("🟠 High", severity_counts["High"])
        rc5.metric("🟡 Med + Low",
                   severity_counts["Medium"] + severity_counts["Low"])

        st.markdown('<div class="section-label">📋 All Findings Summary</div>', unsafe_allow_html=True)
        if all_findings:
            for i, f in enumerate(all_findings, 1):
                css = SEVERITY_CLASS.get(f["severity"], "severity-low")
                st.markdown(
                    f'<div class="{css}"><b>{i}. {f["title"]}</b> '
                    f'— {f["severity"]} &nbsp;|&nbsp; CWE: {f["cwe"]} '
                    f'&nbsp;|&nbsp; CVSS: {f["cvss"]}</div>',
                    unsafe_allow_html=True
                )
        else:
            not_found("No vulnerabilities detected across all 23 checks — clean scan!")

        st.markdown('<div class="section-label">⬇️ Download Report</div>', unsafe_allow_html=True)
        pdf = generate_pdf(domain, risk, cvss, all_findings)
        with open(pdf, "rb") as file:
            st.download_button(
                label="⬇️ Download Full PDF Report",
                data=file,
                file_name=f"vulnix_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf"
            )

    progress.progress(100)
    status.success(
        f"✅ Vulnix AI Scan Complete — "
        f"{total} finding(s): "
        f"{severity_counts['Critical']} Critical, "
        f"{severity_counts['High']} High, "
        f"{severity_counts['Medium']} Medium, "
        f"{severity_counts['Low']} Low"
    )

# ---------------------------------------------------
# INSTALL & RUN
# pip install streamlit requests selenium python-whois dnspython ipwhois reportlab
# streamlit run app.py
# ---------------------------------------------------
