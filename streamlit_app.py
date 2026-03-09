import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import time
import socket
import base64
import json
import importlib
from core import scanners

# Force reload scanners module to prevent caching issues
importlib.reload(scanners)
from core.scanners import SecurityScanners

# --- Configuration & Browser Tab Branding ---
st.set_page_config(
    page_title="DEVPULSE | Enterprise Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# JavaScript for Animated Favicon
JS_FAVICON_ANIMATION = """
<script>
    const icons = ["🛡️", "🔍", "🕵️", "⚡"];
    let i = 0;
    let interval = null;

    window.parent.document.addEventListener('start_scan', () => {
        if (interval) clearInterval(interval);
        interval = setInterval(() => {
            const link = window.parent.document.querySelector("link[rel*='icon']");
            if (link) {
                link.href = `data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>${icons[i]}</text></svg>`;
            }
            i = (i + 1) % icons.length;
        }, 500);
    });

    window.parent.document.addEventListener('stop_scan', () => {
        if (interval) {
            clearInterval(interval);
            const link = window.parent.document.querySelector("link[rel*='icon']");
            if (link) {
                link.href = `data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>`;
            }
        }
    });
</script>
"""
st.markdown(JS_FAVICON_ANIMATION, unsafe_allow_html=True)

# Load Custom CSS
if os.path.exists("styles/main.css"):
    with open("styles/main.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# --- Startup Animated Loader ---
if 'startup_done' not in st.session_state:
    startup_placeholder = st.empty()
    with startup_placeholder:
        st.markdown("""
        <div class="startup-overlay">
            <div class="ripple-container">
                <div class="ripple"></div>
                <div class="ripple"></div>
                <div class="ripple"></div>
                <div class="shield-pulse">🛡️</div>
            </div>
            <div class="loading-text">DevPulse Platform Initializing...</div>
        </div>
        """, unsafe_allow_html=True)
        time.sleep(1.2)
    startup_placeholder.empty()
    st.session_state.startup_done = True

# --- Shared State ---
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {
        "secrets": [],
        "vulns": [],
        "packages": [],
        "deps": [],
        "network": [],
        "risk_score": 100,
        "risk_status": "SAFE",
        "last_scan": None
    }

if 'security_logs' not in st.session_state:
    st.session_state.security_logs = []

def add_log(msg, type="INFO"):
    st.session_state.security_logs.append({
        "Time": pd.Timestamp.now().strftime('%H:%M:%S'),
        "Type": type,
        "Message": msg
    })

# --- UI Components ---

def render_premium_loader(text="Synchronizing Data..."):
    st.markdown(f"""
    <div class="startup-overlay" style="background: rgba(15, 23, 42, 0.8);">
        <div class="ripple-container">
            <div class="ripple"></div>
            <div class="ripple"></div>
            <div class="ripple"></div>
            <div class="shield-pulse">🛡️</div>
        </div>
        <div class="loading-text">{text}</div>
    </div>
    """, unsafe_allow_html=True)

def render_how_it_works():
    st.markdown("### 🛠️ PLATFORM OVERVIEW")
    st.markdown("""
    <div class="how-it-works-container">
        <div class="step-card">
            <div class="step-icon">💻</div>
            <h4>DevSec</h4>
            <p>SAST, Secret Detection, and SCA for your local project.</p>
        </div>
        <div class="step-card">
            <div class="step-icon">🌐</div>
            <h4>NetSec</h4>
            <p>Infrastructure audits including Port Scanning and DNS analysis.</p>
        </div>
        <div class="step-card">
            <div class="step-icon">🔨</div>
            <h4>Utilities</h4>
            <p>Essential crypto tools: Hashing, Encoders, and JWT Decoder.</p>
        </div>
        <div class="step-card">
            <div class="step-icon">📊</div>
            <h4>Observe</h4>
            <p>Unified risk scoring and real-time threat intelligence.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_top_vulnerabilities():
    st.markdown("### 🚨 TOP 10 GLOBAL VULNERABILITIES")
    vulns = [
        {"id": "CVE-2024-21626", "title": "RunC Container Breakout", "severity": "CRITICAL"},
        {"id": "CVE-2024-23131", "title": "Linux Kernel Privilege Escalation", "severity": "HIGH"},
        {"id": "CVE-2023-46604", "title": "Apache ActiveMQ RCE", "severity": "CRITICAL"},
        {"id": "CVE-2024-21413", "title": "Outlook RCE (MonikerLink)", "severity": "HIGH"},
        {"id": "CVE-2023-22527", "title": "Confluence RCE", "severity": "CRITICAL"},
        {"id": "CVE-2024-20272", "title": "Cisco Unity File Upload", "severity": "HIGH"}
    ]
    for v in vulns:
        color = "#EF4444" if v['severity'] == "CRITICAL" else "#F59E0B"
        st.markdown(f"""
        <div class="vuln-item">
            <span class="vuln-tag" style="background: {color}">{v['severity']}</span>
            <strong>{v['id']}</strong>: {v['title']}
        </div>
        """, unsafe_allow_html=True)

def render_risk_meter(score, status):
    status_colors = {"SAFE": "#22C55E", "WARNING": "#F59E0B", "CRITICAL": "#EF4444"}
    color = status_colors.get(status, "#3B82F6")
    st.markdown(f"""
    <div class="risk-meter-container fade-in">
        <div style="font-size: 0.9rem; text-transform: uppercase; color: #94a3b8; letter-spacing: 2px;">Security Health Index</div>
        <div class="risk-value" style="color: {color}; text-shadow: 0 0 15px {color}44;">{score} / 100</div>
        <div style="font-size: 1.2rem; font-weight: 700;">Status: <span style="color: {color}">{status}</span></div>
    </div>
    """, unsafe_allow_html=True)

def perform_platform_scan():
    loader_placeholder = st.empty()
    with loader_placeholder:
        render_premium_loader("Performing Comprehensive Platform Audit...")
        time.sleep(1.0)
    
    # Use direct class calls to avoid instance attribute lookup issues
    secrets = SecurityScanners.deep_scan_secrets(".")
    packages = SecurityScanners.scan_manifests(".")
    deps = SecurityScanners.get_dependency_data(".")
    net_findings = SecurityScanners.port_scanner("localhost", [80, 443, 8501])
    
    risk_score, risk_status = SecurityScanners.calculate_risk_score(secrets + packages, net_findings)
    
    st.session_state.scan_results = {
        "secrets": secrets,
        "packages": packages,
        "deps": deps,
        "network": net_findings,
        "risk_score": risk_score,
        "risk_status": risk_status,
        "last_scan": pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    add_log(f"Global audit complete. Risk Score: {risk_score}", risk_status)
    loader_placeholder.empty()

# --- Sidebar ---

with st.sidebar:
    st.markdown("""
    <div class="sidebar-logo">
        <div style="font-size: 2.2rem; margin-bottom: 5px;">🛡️</div>
        <h1>DEVPULSE</h1>
        <div style="font-size: 0.7rem; color: #3b82f6; letter-spacing: 2px;">ENTERPRISE EDITION</div>
    </div>
    """, unsafe_allow_html=True)
    
    if 'active_tab' not in st.session_state:
        st.session_state.active_tab = "Command Center"

    if 'active_tab' not in st.session_state:
        st.session_state.active_tab = "Command Center"
    
    # Categorize tools
    tool_map = {
        "📊 MONITORING": ["Command Center", "Security Logs"],
        "💻 DEVELOPER SUITE": ["Secret Scanner", "Package Auditor", "Code Analyzer", "Dependency Graph"],
        "🌐 NETWORK SUITE": ["Port Scanner", "DNS Lookup", "IP Reputation", "SSL Checker"],
        "🔨 SECURITY UTILS": ["Password Strength", "Hash Generator", "Base64 Tool", "JWT Decoder"]
    }
    
    # Find active category if it exists
    current_cat = "📊 MONITORING"
    for cat, tools in tool_map.items():
        if st.session_state.active_tab in tools:
            current_cat = cat
            break

    st.markdown('<div class="nav-category">Select Security Suite</div>', unsafe_allow_html=True)
    selected_suite = st.selectbox("Suite", list(tool_map.keys()), index=list(tool_map.keys()).index(current_cat), label_visibility="collapsed")

    def render_nav_item(label, icon):
        is_active = st.session_state.active_tab == label
        btn_type = "primary" if is_active else "secondary"
        if st.button(f"{icon} {label}", key=f"nav_{label}", width="stretch", type=btn_type):
            st.session_state.active_tab = label
            st.rerun()
            
    st.markdown(f'<div class="sidebar-section-header">{selected_suite[2:]} MODULES</div>', unsafe_allow_html=True)
    
    # Map icons for sub-items (to maintain the premium feel)
    icons = {
        "Command Center": "🏠", "Security Logs": "📜",
        "Secret Scanner": "🔐", "Package Auditor": "📦", "Code Analyzer": "💻", "Dependency Graph": "🖇️",
        "Port Scanner": "📡", "DNS Lookup": "🌐", "IP Reputation": "🕵️", "SSL Checker": "📜",
        "Password Strength": "🔑", "Hash Generator": "🔢", "Base64 Tool": "🧬", "JWT Decoder": "🎟️"
    }
    
    for tool in tool_map[selected_suite]:
        render_nav_item(tool, icons.get(tool, "⚡"))

    active_tab = st.session_state.active_tab

    st.markdown("---")
    if st.button("🚀 INITIATE FULL AUDIT", width="stretch"):
        perform_platform_scan()

    st.markdown(f"""
    <div class="system-pulse-container">
        <div style="margin-bottom: 8px;">
            <span class="pulse-dot"></span>
            <strong>SYSTEM ONLINE</strong>
        </div>
        <div style="color: #94a3b8; font-size: 0.7rem;">
            Node: {socket.gethostname()}<br>
            Uptime: {pd.Timestamp.now().strftime('%H:%M:%S')}<br>
            Risk Score: {st.session_state.scan_results['risk_score']}/100
        </div>
    </div>
    """, unsafe_allow_html=True)

    # JS to inject classes to Streamlit buttons for styling
    st.markdown(f"""
    <script>
        const activeTab = "{active_tab}";
        const buttons = window.parent.document.querySelectorAll('button[p-testid="baseButton-secondary"], button[p-testid="baseButton-primary"]');
        buttons.forEach(btn => {{
            const text = btn.innerText;
            // Check if it's a nav button by checking for icons
            const isNav = text.match(/[🏠📜🔐📦💻🖇️📡🌐🕵️🔑🔢🧬🎟️]/);
            if (isNav) {{
                btn.classList.add('nav-btn');
                // Active state check
                if (text.includes(activeTab)) {{
                    btn.classList.add('nav-btn-active');
                }} else {{
                    btn.classList.remove('nav-btn-active');
                }}
            }}
        }});
    </script>
    """, unsafe_allow_html=True)

# --- Content Routing ---

if active_tab == "Command Center":
    st.title("🛡️ COMMAND CENTER")
    render_how_it_works()
    st.markdown("---")
    c1, c2 = st.columns([1, 1.5])
    with c1:
        render_risk_meter(st.session_state.scan_results['risk_score'], st.session_state.scan_results['risk_status'])
        st.markdown("<br>", unsafe_allow_html=True)
        render_top_vulnerabilities()
    with c2:
        st.markdown("### 🧬 Real-time Security Posture")
        m1, m2, m3 = st.columns(3)
        m1.metric("Secrets", len(st.session_state.scan_results['secrets']))
        m2.metric("Net Risks", len(st.session_state.scan_results['network']))
        m3.metric("Integrity", "FAIL" if st.session_state.scan_results['packages'] else "PASS")
        
        df_trend = pd.DataFrame({'Time': range(10), 'Risk': [100, 95, 90, 85, 80, 75, 70, 72, 72, 72]})
        st.plotly_chart(px.line(df_trend, x='Time', y='Risk', title="Security Evolution").update_layout(template='plotly_dark', height=300, yaxis_range=[0,100]), width="stretch")

elif active_tab == "Security Logs":
    st.title("📜 Security Event Logs")
    if not st.session_state.security_logs:
        st.info("No logs generated yet. Run an audit to see events.")
    else:
        st.table(pd.DataFrame(st.session_state.security_logs))

elif active_tab == "Secret Scanner":
    st.title("🔐 Secret Leak Detector")
    st.write("Deep scan for API keys, AWS secrets, and JWT tokens.")
    if st.button("Run Secret Crawl", width="stretch"):
        secrets = SecurityScanners.deep_scan_secrets(".")
        st.session_state.scan_results['secrets'] = secrets
        if secrets:
            for s in secrets: st.error(f"Leak: {s['type']} in {s['file']}")
            add_log(f"Found {len(secrets)} leaked secrets", "CRITICAL")
        else: st.success("No secrets detected.")

elif active_tab == "Package Auditor":
    st.title("📦 Supply Chain Auditor")
    if st.button("Audit Manifests", width="stretch"):
        findings = SecurityScanners.scan_manifests(".")
        if findings:
            for f in findings: st.error(f)
        else: st.success("Root manifests look clean.")

elif active_tab == "Code Analyzer":
    st.title("💻 Code Security SAST")
    snippet = st.text_area("Plain Code Snippet", height=150)
    if st.button("Analyze Logic", width="stretch"):
        findings = SecurityScanners.code_security_analyzer(snippet)
        if findings:
            for f in findings: st.error(f)
        else: st.success("No common vulnerabilities detected in snippet.")

elif active_tab == "Dependency Graph":
    st.title("🖇️ Dependency Topology")
    deps = SecurityScanners.get_dependency_data(".")
    if deps:
        df = pd.DataFrame(deps)
        st.plotly_chart(px.bar(df, x="name", y=[1]*len(df), color="name", title="Ecosystem Map").update_layout(template="plotly_dark"), width="stretch")
    else:
        st.warning("No requirements.txt found in root.")

elif active_tab == "Port Scanner":
    st.title("📡 Infrastructure Port Scanner")
    host = st.text_input("Target Host", "localhost")
    if st.button("Scan Host", width="stretch"):
        open_ports = SecurityScanners.port_scanner(host)
        if open_ports:
            st.warning(f"Open Ports Detected on {host}: {', '.join(map(str, open_ports))}")
            add_log(f"Exposed ports found on {host}: {open_ports}", "WARNING")
        else: st.success("No critical ports exposed.")

elif active_tab == "DNS Lookup":
    st.title("🌐 DNS Intelligence")
    domain = st.text_input("Enter Domain", "google.com")
    if st.button("Lookup Records", width="stretch"):
        res = SecurityScanners.dns_lookup(domain)
        if res.get("IP"): st.success(f"IP: {res['IP']}")
        else: st.error(res["Status"])

elif active_tab == "SSL Checker":
    st.title("📜 SSL Certificate Audit")
    target = st.text_input("Target Host", "google.com")
    if st.button("Check SSL", width="stretch"):
        res = SecurityScanners.ssl_checker(target)
        if res["Status"] == "VALID":
            st.success(f"SSL Status: VALID | Expires: {res['Expiry']}")
            st.write(f"Issuer: {res['Issuer']}")
        else: st.error(res["Status"])

elif active_tab == "IP Reputation":
    st.title("🕵️ IP Reputation Checker")
    ip = st.text_input("Enter IP Address", "8.8.8.8")
    if st.button("Check Reputation", width="stretch"):
        res = SecurityScanners.ip_reputation_check(ip)
        if "THREAT" in res: st.error(res)
        else: st.success(res)

elif active_tab == "Password Strength":
    st.title("🔑 Password Entropy Analyzer")
    pwd = st.text_input("Input Password", type="password")
    if pwd:
        strength = SecurityScanners.password_strength(pwd)
        if "EXCELLENT" in strength: st.success(strength)
        elif "STRONG" in strength: st.info(strength)
        else: st.warning(strength)

elif active_tab == "Hash Generator":
    st.title("🔢 Hash Generator")
    text = st.text_area("Plaintext")
    algo = st.selectbox("Algorithm", ["sha256", "sha512", "md5"])
    if text:
        st.code(SecurityScanners.generate_hash(text, algo))

elif active_tab == "Base64 Tool":
    st.title("🧬 Base64 Encoder / Decoder")
    mode = st.radio("Mode", ["Encode", "Decode"])
    data = st.text_input("Data")
    if data:
        try:
            if mode == "Encode": st.code(base64.b64encode(data.encode()).decode())
            else: st.code(base64.b64decode(data.encode()).decode())
        except: st.error("Invalid data for operation.")

elif active_tab == "JWT Decoder":
    st.title("🎟️ JWT Token Inspector")
    token = st.text_area("Enter JWT")
    if token:
        try:
            parts = token.split(".")
            decoded_payload = base64.b64decode(parts[1] + "===").decode()
            st.json(json.loads(decoded_payload))
        except Exception as e:
            st.error(f"Error decoding token: {str(e)}")

st.markdown("""
<div style="position: fixed; bottom: 10px; right: 10px; font-size: 0.7rem; color: #94a3b8; opacity: 0.5;">
    DEVPULSE SEC-OPS | ENCRYPTED SESSION | v3.1.2
</div>
""", unsafe_allow_html=True)
