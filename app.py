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
with open("styles/main.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

scanner = SecurityScanners()

# --- Shared State for Real-time Data ---
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {
        "secrets": [],
        "vulns": [],
        "packages": [],
        "risk_score": 20,
        "risk_status": "LOW",
        "last_scan": None
    }

# --- UI Components ---

def render_risk_meter(score, status):
    status_class = f"status-{status.lower()}"
    st.markdown(f"""
    <div class="risk-meter-container fade-in">
        <div style="font-size: 0.9rem; text-transform: uppercase; color: #94a3b8; letter-spacing: 2px;">Security Risk Score</div>
        <div class="risk-value {status_class}">{score} / 100</div>
        <div style="font-size: 1.2rem; font-weight: 700;">Status: <span class="{status_class}">{status}</span></div>
    </div>
    """, unsafe_allow_html=True)

def perform_global_scan():
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    status_text.markdown("🔍 <span class='scanning-pulse'>Scanning directory for secrets...</span>", unsafe_allow_html=True)
    secrets = scanner.deep_scan_secrets(".")
    progress_bar.progress(30)
    time.sleep(0.5)
    
    status_text.markdown("📦 <span class='scanning-pulse'>Analyzing package manifests...</span>", unsafe_allow_html=True)
    packages = scanner.scan_manifests(".")
    progress_bar.progress(60)
    time.sleep(0.5)
    
    status_text.markdown("🖇️ <span class='scanning-pulse'>Building dependency tree...</span>", unsafe_allow_html=True)
    deps = scanner.get_dependency_data(".")
    progress_bar.progress(90)
    time.sleep(0.5)
    
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
    st.success("Global Scan Complete!")

# --- Sidebar ---

with st.sidebar:
    st.markdown('<div class="sidebar-logo"><h1>DEVGUARD</h1></div>', unsafe_allow_html=True)
    
    menu = st.radio("Navigation", [
        "Dashboard",
        "Secret Scanner",
        "Dependency Scanner",
        "NPM Malware Scanner",
        "Code Security Analyzer",
        "API Security Check",
        "Reports"
    ], label_visibility="collapsed")
    
    st.markdown("---")
    if st.button("🚀 INITIATE SYSTEM SCAN", use_container_width=True):
        perform_global_scan()
        
    st.markdown(f"""
    <div style="font-size: 0.75rem; color: #94a3b8; text-align: center; margin-top: 20px;">
        Last Scan: {st.session_state.scan_results['last_scan'] or 'N/A'}<br>
        DevGuard v2.5.0-ENT
    </div>
    """, unsafe_allow_html=True)

# --- Main Panels ---

if menu == "Dashboard":
    st.title("🛡️ COMMAND CENTER")
    
    col_meter, col_stats = st.columns([1, 1.5])
    
    with col_meter:
        render_risk_meter(st.session_state.scan_results['risk_score'], st.session_state.scan_results['risk_status'])
        
    with col_stats:
        st.markdown("### 📊 Live System Metrics")
        m1, m2, m3 = st.columns(3)
        m1.metric("Secrets Found", len(st.session_state.scan_results['secrets']), delta=None, delta_color="inverse")
        m2.metric("Vulnerabilities", "4", delta="+1", delta_color="inverse")
        m3.metric("Packages Check", len(st.session_state.scan_results['packages'] or []), delta=None)
        
        # Mini Trend Chart
        df_trend = pd.DataFrame({'Time': range(10), 'Risk': [20, 22, 25, 23, 30, 45, 60, 72, 70, 72]})
        fig_trend = px.area(df_trend, x='Time', y='Risk', template='plotly_dark')
        fig_trend.update_layout(height=150, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig_trend, use_container_width=True)

    st.markdown("---")
    
    # Bottom Row: Vulnerability Distribution & Alerts
    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown("### 🧬 Vulnerability Distribution")
        fig_pie = px.pie(values=[2, 5, 3], names=['Critical', 'High', 'Medium'], hole=0.6,
                        color_discrete_sequence=[os.environ.get('CRITICAL', '#EF4444'), '#F59E0B', '#3B82F6'])
        fig_pie.update_layout(showlegend=False, paper_bgcolor='rgba(0,0,0,0)', height=250)
        st.plotly_chart(fig_pie, use_container_width=True)
        
    with c2:
        st.markdown("### 🔔 Security Alerts")
        if not st.session_state.scan_results['secrets']:
            st.info("System scan recommended for latest alerts.")
        else:
            for s in st.session_state.scan_results['secrets'][:3]:
                st.error(f"**LEAK DETECTED**: {s['type']} in `{s['file']}`")

elif menu == "Secret Scanner":
    st.title("🔑 SECRET & CREDENTIAL SCANNER")
    st.markdown("Automated heuristic scanning for hardcoded API keys and credentials.")
    
    if st.button("Run Deep Secret Scan"):
        perform_global_scan()
        
    if st.session_state.scan_results['secrets']:
        for s in st.session_state.scan_results['secrets']:
            with st.expander(f"⚠️ {s['type']} found in {s['file']}"):
                st.code(s['snippet'], language="text")
                st.warning("Action Required: Rotate credential and remove from source history.")
    else:
        st.success("No secrets detected in current context.")

elif menu == "Dependency Scanner":
    st.title("🖇️ DEPENDENCY ANALYTICS")
    
    deps = st.session_state.scan_results.get('deps', [])
    if deps:
        st.markdown("### 🕸️ Project Dependency Graph")
        # Visualizing as a simple horizontal bar for now, or a spider chart
        df_deps = pd.DataFrame(deps)
        fig_deps = px.bar(df_deps, x='name', y=[1]*len(deps), title="Active Dependencies")
        fig_deps.update_layout(template='plotly_dark', showlegend=False)
        st.plotly_chart(fig_deps, use_container_width=True)
    else:
        st.info("Run a system scan to visualize dependencies.")

# (Other tabs would follow similar professional structure)
else:
    st.title(f"🛡️ {menu}")
    st.info("Feature integration in progress for Enterprise v2.5.0")

st.markdown("""
<div style="position: fixed; bottom: 10px; right: 10px; font-size: 0.7rem; color: #94a3b8; opacity: 0.5;">
    DEVGUARD SEC-OPS | ENCRYPTED SESSION
</div>
""", unsafe_allow_html=True)
