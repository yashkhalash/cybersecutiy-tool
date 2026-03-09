import re
import os
import glob
import socket
import hashlib
import base64
import json
import ssl
from datetime import datetime

class SecurityScanners:
    # --- Developer Security Suite ---
    
    @staticmethod
    def deep_scan_secrets(directory):
        """Real-time scan of the filesystem for secrets"""
        findings = []
        patterns = {
            "Generic API Key": r"(?i)(?:key|api|token|secret|pass|pwd)[-|_]*[:=]\s*['\"]([a-zA-Z0-9\-_]{16,})['\"]",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"secret[-|_]*key[:=]\s*['\"]([a-zA-Z0-9\/+]{40})['\"]",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
            "JWT Secret": r"jwt[-|_]*secret[:=]\s*['\"]([a-zA-Z0-9\-_]{32,})['\"]"
        }
        
        ignore_dirs = {'.git', 'node_modules', '__pycache__', 'venv', '.streamlit'}
        
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.env', '.txt', '.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                            for name, pattern in patterns.items():
                                matches = re.findall(pattern, content)
                                for m in matches:
                                    findings.append({
                                        "type": name,
                                        "file": os.path.relpath(file_path, directory),
                                        "snippet": f"Found potential leak: {m[:4] if isinstance(m, str) else m[0][:4]}****"
                                    })
                    except:
                        continue
        return findings

    @staticmethod
    def scan_manifests(directory):
        """Scans package.json or requirements.txt for malicious indicators"""
        findings = []
        suspicious_pkgs = ["crypto-miner", "reverse-shell-plz", "totally-not-malware"]
        
        for manifest in ['package.json', 'requirements.txt']:
            path = os.path.join(directory, manifest)
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                        for pkg in suspicious_pkgs:
                            if pkg in content:
                                findings.append(f"Malicious indicator: '{pkg}' found in {manifest}")
                        if manifest == 'package.json':
                            data = json.loads(content)
                            scripts = data.get('scripts', {})
                            if 'postinstall' in scripts:
                                findings.append(f"Security Warning: Post-install script detected in package.json. Audit manually.")
                except:
                    pass
        return findings

    @staticmethod
    def code_security_analyzer(code):
        """Heuristic SAST against OWASP Top 10"""
        patterns = {
            "Insecure eval()": r"eval\(",
            "Unsafe Execution (os.system)": r"os\.system\(",
            "Unsafe Subprocess": r"subprocess\.Popen\(.*shell=True",
            "SQL Injection Risk": r"execute\(.*%.*\)",
            "XSS Risk (innerHTML)": r"\.innerHTML\s*=",
            "Hardcoded IP Address": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        }
        findings = []
        for name, pattern in patterns.items():
            if re.search(pattern, code):
                findings.append(f"Vulnerability Detected: {name}")
        return findings

    # --- Network Security Suite ---

    @staticmethod
    def port_scanner(host, ports=[21, 22, 80, 443, 3306, 8080]):
        """Fast TCP port scanner"""
        open_ports = []
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            try:
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except:
                continue
        return open_ports

    @staticmethod
    def dns_lookup(domain):
        """Standard DNS resolving"""
        try:
            addr = socket.gethostbyname(domain)
            return {"IP": addr, "Status": "Success"}
        except:
            return {"Status": "DNS Resolving Failed"}

    @staticmethod
    def ssl_checker(host):
        """Basic SSL Expiry and Metadata Checker"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    expiry = cert.get('notAfter')
                    issuer = dict(x[0] for x in cert.get('issuer'))
                    return {
                        "Status": "VALID",
                        "Expiry": expiry,
                        "Issuer": issuer.get('commonName', 'Unknown')
                    }
        except Exception as e:
            return {"Status": f"SSL Error: {str(e)}"}

    @staticmethod
    def ip_reputation_check(ip):
        """Mocked IP reputation for UI demo"""
        suspicious_list = ["192.168.1.100", "10.0.0.50"] 
        if ip in suspicious_list:
            return "THREAT DETECTED: Known malware source"
        return "CLEAN: No malicious history found in DevPulse Database"

    # --- General Security Tools ---

    @staticmethod
    def password_strength(password):
        """Calculates password entropy and strength"""
        if len(password) < 8: return "WEAK: Minimum 8 characters required"
        score = 0
        if re.search("[a-z]", password): score += 1
        if re.search("[A-Z]", password): score += 1
        if re.search("[0-9]", password): score += 1
        if re.search("[!@#$%^&*()]", password): score += 1
        
        if score == 1: return "WEAK: Simple characters only"
        if score == 2: return "MEDIUM: Complexity needed"
        if score == 3: return "STRONG: Secure choice"
        return "EXCELLENT: High entropy password"

    @staticmethod
    def generate_hash(text, algo="sha256"):
        if algo == "sha256": return hashlib.sha256(text.encode()).hexdigest()
        if algo == "md5": return hashlib.md5(text.encode()).hexdigest()
        if algo == "sha512": return hashlib.sha512(text.encode()).hexdigest()
        return None

    # --- Reporting ---

    @staticmethod
    def get_dependency_data(directory):
        """Extracts data for dependency graph from requirements.txt"""
        req_path = os.path.join(directory, 'requirements.txt')
        deps = []
        if os.path.exists(req_path):
            with open(req_path, 'r') as f:
                for line in f:
                    if '==' in line:
                        name, ver = line.strip().split('==')
                        deps.append({"name": name, "version": ver})
        return deps

    @staticmethod
    def calculate_risk_score(dev_findings, net_findings):
        """Weighted risk score aggregator"""
        # Starting from 100 (Safe) and subtracting for each threat
        score = 100 - (len(dev_findings) * 8) - (len(net_findings) * 15)
        score = max(5, min(100, score))
        
        status = "SAFE"
        if score < 40: status = "CRITICAL"
        elif score < 75: status = "WARNING"
        
        return score, status
