# DEVGUARD: Enterprise Cyber Security Suite 🛡️

DEVGUARD is a high-performance, enterprise-grade security dashboard built for developers and security operations (SecOps). It leverages real-time filesystem scanning to identify vulnerabilities, leaked secrets, and supply chain risks.

## 🌌 Theme: Cyber Security Dark (Theme 1)

Designed for maximum focus and visual clarity in high-pressure security environments:
- **Background**: Dark Navy (`#0F172A`)
- **Primary Accent**: Neon Blue (`#3B82F6`)
- **Status Indicators**: Consistently themed (Green: Safe, Yellow: Warning, Red: Critical)

## ✨ Enterprise Features

- **🛡️ Command Center**: Centralized dashboard with a dynamic **Risk Score Meter**.
- **🔑 Real-time Secret Scanning**: Crawls your project tree for AWS keys, Google API tokens, and credentials.
- **📦 Supply Chain Analytics**: Monitors `package.json` and `requirements.txt` for suspicious package activity.
- **🖇️ Dependency Intelligence**: Generates live dependency maps and vulnerability distribution charts.
- **🔄 Live Scan Engine**: Integrated `st.progress` feedback during deep-analysis cycles.

## 🚀 Quick Start (Enterprise Deployment)

### 1. Configure Streamlit
Ensure `.streamlit/config.toml` is present with the branding configuration.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Dashboard
```bash
streamlit run streamlit_app.py
```

## 📁 Architecture (Enterprise)

```text
dev_pulse/
├── .streamlit/
│   └── config.toml       # Global Branding (Theme 1)
├── streamlit_app.py      # Main Command Center UI
├── core/
│   └── scanners.py       # Enterprise Scan Engine (Real-time)
├── styles/
│   └── main.css          # Custom CSS Overrides
└── README.md             # Systems documentation
```
# cybersecutiy-tool
