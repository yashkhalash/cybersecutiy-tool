import re
import os
import glob

class SecurityScanners:
    @staticmethod
    def deep_scan_secrets(directory):
        """Real-time scan of the filesystem for secrets"""
        findings = []
        patterns = {
            "Generic API Key": r"(?i)(?:key|api|token|secret|pass|pwd)[-|_]*[:=]\s*['\"]([a-zA-Z0-9\-_]{16,})['\"]",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}"
        }
        
        # Avoid scanning large ignored directories
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
                                        "snippet": f"Found potential leak: {m[:4]}****"
                                    })
                    except Exception as e:
                        continue
        return findings

    @staticmethod
    def scan_manifests(directory):
        """Scans real package.json or requirements.txt files"""
        findings = []
        suspicious = ["crypto-miner", "reverse-shell-plz", "totally-not-malware"]
        
        for manifest in ['package.json', 'requirements.txt']:
            path = os.path.join(directory, manifest)
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                        for pkg in suspicious:
                            if pkg in content:
                                findings.append(f"Suspicious package '{pkg}' detected in {manifest}")
                except:
                    pass
        return findings

    @staticmethod
    def get_dependency_data(directory):
        """Extracts data for dependency graph"""
        # Simplistic version for the demo - parsing requirements.txt
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
    def calculate_risk_score(findings_count):
        """Calculates a risk score from findings"""
        # Exponential curve for risk
        base_risk = 20
        penalty = findings_count * 15
        score = min(98, base_risk + penalty)
        
        status = "LOW"
        if score > 70: status = "HIGH"
        elif score > 40: status = "MEDIUM"
        
        return score, status
