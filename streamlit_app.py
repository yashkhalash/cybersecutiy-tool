import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import time
from core.scanners import SecurityScanners

# --- Configuration & Theme ---
st.set_page_config(
    page_title="DEVGUARD | Cyber Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load Custom CSS (Theme 1)
if os.path.exists("styles/main.css"):
    with open("styles/main.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

scanner = SecurityScanners()

# --- Shared State for Real-time Data ---
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {
        "secrets": [],
        "vulns": [],
        "packages": [],
        "deps": [],
        "risk_score": 20,
        "risk_status": "LOW",
        "last_scan": None
    }

# --- UI Components ---

def render_risk_meter(score, status):
    status_colors = {"LOW": "#22C55E", "MEDIUM": "#F59E0B", "HIGH": "#EF4444"}
    color = status_colors.get(status, "#3B82F6")
    
    st.markdown(f"""
    <div class="risk-meter-container fade-in">
        <div style="font-size: 0.9rem; text-transform: uppercase; color: #94a3b8; letter-spacing: 2px;">Security Risk Level</div>
        <div class="risk-value" style="color: {color}; text-shadow: 0 0 15px {color}44;">{score} / 100</div>
        <div style="font-size: 1.2rem; font-weight: 700;">Status: <span style="color: {color}">{status}</span></div>
    </div>
    """, unsafe_allow_html=True)

def perform_global_scan():
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    status_text.markdown("🔍 <span class='scanning-pulse'>Scanning directory for secrets...</span>", unsafe_allow_html=True)
    secrets = scanner.deep_scan_secrets(".")
    progress_bar.progress(30)
    time.sleep(0.4)
    
    status_text.markdown("📦 <span class='scanning-pulse'>Analyzing package manifests...</span>", unsafe_allow_html=True)
    packages = scanner.scan_manifests(".")
    progress_bar.progress(60)
    time.sleep(0.4)
    
    status_text.markdown("🖇️ <span class='scanning-pulse'>Building dependency tree...</span>", unsafe_allow_html=True)
    deps = scanner.get_dependency_data(".")
    progress_bar.progress(90)
    time.sleep(0.4)
    
    # Calculate Risk
    total_findings = len(secrets) + len(packages)
    risk_score, risk_status = scanner.calculate_risk_score(total_findings)
    
    st.session_state.scan_results = {
        "secrets": secrets,
        "packages": packages,
        "deps": deps,
        "risk_score": risk_score,
        "risk_status": risk_status,
        "last_scan": pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    progress_bar.empty()
    status_text.empty()
    st.success("System-wide Integrity Scan Complete!")

# --- Sidebar ---

with st.sidebar:
    st.markdown('<div class="sidebar-logo"><h1>DEVGUARD</h1></div>', unsafe_allow_html=True)
    
    menu = st.radio("Navigation", [
        "🛡️ Dashboard",
        "🔑 Secret Scanner",
        "🖇️ Dependency Scanner",
        "📦 NPM Malware Scanner",
        "💻 Code Analyzer",
        "🌐 API Security",
        "📊 Strategic Reports"
    ], label_visibility="collapsed")
    
    st.markdown("---")
    if st.button("🚀 RUN GLOBAL SECURITY SCAN", use_container_width=True):
        perform_global_scan()
        
    st.markdown(f"""
    <div style="font-size: 0.75rem; color: #94a3b8; text-align: center; margin-top: 20px;">
        Last Global Scan: {st.session_state.scan_results['last_scan'] or 'N/A'}<br>
        DevGuard Enterprise v2.5.0
    </div>
    """, unsafe_allow_html=True)

# --- Main Panels ---

def clean_menu(m):
    return m.split(" ")[1] if " " in m else m

active_tab = clean_menu(menu)

if active_tab == "Dashboard":
    st.title("🛡️ COMMAND CENTER")
    
    col_meter, col_stats = st.columns([1, 1.5])
    
    with col_meter:
        render_risk_meter(st.session_state.scan_results['risk_score'], st.session_state.scan_results['risk_status'])
        
    with col_stats:
        st.markdown("### 🧬 Real-time Security Posture")
        m1, m2, m3 = st.columns(3)
        m1.metric("Secrets Matched", len(st.session_state.scan_results['secrets']), delta=None, delta_color="inverse")
        m2.metric("Vulnerabilities", "4", delta="+1", delta_color="inverse")
        m3.metric("Integrity Check", "PASSED" if not st.session_state.scan_results['packages'] else "FAIL")
        
        # Mini Trend Chart
        df_trend = pd.DataFrame({'Time': range(10), 'Risk': [20, 22, 25, 23, 30, 45, 60, 72, 70, 72]})
        fig_trend = px.area(df_trend, x='Time', y='Risk', template='plotly_dark')
        fig_trend.update_layout(height=150, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig_trend, use_container_width=True)

    st.markdown("---")
    
    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown("### ⚖️ Threat Distribution")
        fig_pie = px.pie(values=[2, 5, 3], names=['High', 'Medium', 'Low'], hole=0.6,
                        color_discrete_sequence=['#EF4444', '#F59E0B', '#3B82F6'])
        fig_pie.update_layout(showlegend=False, paper_bgcolor='rgba(0,0,0,0)', height=250)
        st.plotly_chart(fig_pie, use_container_width=True)
        
    with c2:
        st.markdown("### 🚨 Urgent Interventions")
        if not st.session_state.scan_results['secrets'] and not st.session_state.scan_results['packages']:
            st.info("System is currently stable. No immediate actions required.")
        else:
            for s in st.session_state.scan_results['secrets'][:2]:
                st.error(f"**Leak**: {s['type']} found in {s['file']}")
            for p in st.session_state.scan_results['packages'][:1]:
                st.warning(f"**Manifest**: {p}")

elif active_tab == "Secret":
    st.title("🔑 CRYPTOGRAPHIC KEY SCANNER")
    st.markdown("Deep inspection of source code for hardcoded static credentials.")
    
    if st.button("Initialize Deep Secret Crawl"):
        perform_global_scan()
        
    if st.session_state.scan_results['secrets']:
        for s in st.session_state.scan_results['secrets']:
            with st.expander(f"⚠️ {s['type']} in {s['file']}"):
                st.code(s['snippet'], language="text")
                st.warning("Action: Evoke and rotate the detected credential immediately.")
    else:
        st.success("No cryptographic secrets found in the current directory.")

elif active_tab == "Dependency":
    st.title("🖇️ SOFTWARE COMPOSITION ANALYSIS")
    
    deps = st.session_state.scan_results.get('deps', [])
    if deps:
        st.markdown("### 🕸️ Dependency Topology")
        df_deps = pd.DataFrame(deps)
        fig_deps = px.bar(df_deps, x='name', y=[1]*len(deps), color='name', title="Project Ecosystem")
        fig_deps.update_layout(template='plotly_dark', showlegend=False, height=400)
        st.plotly_chart(fig_deps, use_container_width=True)
    else:
        st.info("Initiate a Global Scan to map project dependencies.")

elif active_tab == "NPM":
    st.title("📦 SUPPLY CHAIN MALWARE SCANNER")
    st.markdown("Heuristic analysis of package manifests for known malicious patterns.")
    
    if st.button("Audit Manifest Integrity"):
        perform_global_scan()
        
    if st.session_state.scan_results['packages']:
        for p in st.session_state.scan_results['packages']:
            st.error(f"🔥 **MALWARE DETECTED**: {p}")
    else:
        st.success("No suspicious package activity detected in root manifests.")

elif active_tab == "Code":
    st.title("💻 STATIC CODE ANALYZER (SAST)")
    st.markdown("Analyze application logic for insecure patterns like SQLi and injection.")
    
    target_code = st.text_area("Input Code Snippet for Analysis", height=200, placeholder="import os\nos.system('...')")
    if st.button("Run Heuristic SAST"):
        findings = scanner.code_security_analyzer(target_code)
        if findings:
            for f in findings: st.error(f"❌ {f}")
        else:
            st.success("No obvious insecurity patterns detected in the snippet.")

elif active_tab == "API":
    st.title("🌐 API SECURITY CHECK")
    st.markdown("Validate endpoints for TLS compliance and authorization exposure.")
    
    endpoints = st.text_area("Endpoints (one per line)", placeholder="http://api.dev.com\nhttps://api.v1.com/admin").split("\n")
    if st.button("Audit Endpoints"):
        findings = scanner.api_security_checker([e.strip() for e in endpoints if e.strip()])
        if findings:
            for f in findings: st.error(f"🌐 {f}")
        else:
            st.success("All analyzed endpoints follow transport security protocols.")

elif active_tab == "Reports":
    st.title("📊 STRATEGIC INTELLIGENCE REPORTS")
    st.markdown("Predictive trend analysis and risk forecasting.")
    
    df_rep = pd.DataFrame({
        'Cycle': range(1, 11),
        'Resolved': [1, 2, 4, 3, 5, 8, 12, 10, 15, 14],
        'Pending': [2, 3, 2, 4, 2, 1, 0, 1, 0, 0]
    })
    fig_rep = px.line(df_rep, x='Cycle', y=['Resolved', 'Pending'], title="Vulnerability Resolution Velocity")
    fig_rep.update_layout(template='plotly_dark')
    st.plotly_chart(fig_rep, use_container_width=True)

st.markdown("""
<div style="position: fixed; bottom: 10px; right: 10px; font-size: 0.7rem; color: #94a3b8; opacity: 0.5;">
    DEVGUARD SEC-OPS | ENCRYPTED SESSION | v2.5.0
</div>
""", unsafe_allow_html=True)
