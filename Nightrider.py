#!/usr/bin/env python3
"""
NightRider - JavaScript Token Vulnerability Scanner
Authorized Security Assessment Tool
Version 1.0.0
"""

import os
import sys
import json
import time
import re
import requests
from datetime import datetime
from urllib.parse import urlparse, urljoin
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

# Initialize Rich console
console = Console()

# ============================================================
# BANNER
# ============================================================

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗██████╗            ║
║     ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔══██╗           ║
║     ██╔██╗ ██║██║██║  ███╗███████║   ██║   ██████╔╝           ║
║     ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══██╗           ║
║     ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║  ██║           ║
║     ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝           ║
║                                                               ║
║     ██████╗ ██╗██████╗ ███████╗██████╗                        ║
║     ██╔══██╗██║██╔══██╗██╔════╝██╔══██╗                       ║
║     ██████╔╝██║██████╔╝█████╗  ██████╔╝                       ║
║     ██╔══██╗██║██╔══██╗██╔══╝  ██╔══██╗                       ║
║     ██║  ██║██║██║  ██║███████╗██║  ██║                       ║
║     ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                       ║
║                                                               ║
║     [ JAVASCRIPT TOKEN VULNERABILITY SCANNER v1.0 ]           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║              [Coded:Desmued]                                  ║
║  [ linkdin:https://www.linkedin.com/in/dom-jones-5a3411413/ ] ║
╚═══════════════════════════════════════════════════════════════╝

"""

# ============================================================
# VULNERABILITY DATABASE
# ============================================================

TOKEN_PATTERNS = {
    "jwt_token": {
        "patterns": [
            r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            r'Bearer\s+[A-Za-z0-9\-._~+/]+={0,2}',
            r'access_token["\']?\s*[:=]\s*["\'][A-Za-z0-9\-._~+/]+={0,2}["\']',
            r'refresh_token["\']?\s*[:=]\s*["\'][A-Za-z0-9\-._~+/]+={0,2}["\']',
        ],
        "severity": "CRITICAL",
        "description": "JWT tokens exposed in client-side code. Attackers can decode JWTs to extract user identity, roles, and session information.",
        "impact": "Complete account takeover. Attacker can impersonate any user whose JWT is exposed. If the JWT contains admin claims, full system compromise follows. Refresh tokens allow persistent access even after the short-lived token expires.",
        "exploitation": "Decode the JWT at jwt.io or using base64 decode on each segment. Extract claims (sub, role, exp). If the token is not expired, it can be used to impersonate the user. If secret is 'none' algorithm, forge arbitrary tokens.",
        "remediation": "Never store JWTs in JavaScript source code. Use server-side sessions. Set HttpOnly, Secure, SameSite flags on cookies. Implement short expiration times.",
    },
    "api_key": {
        "patterns": [
            r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,64}["\']',
            r'API[_-]?KEY["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,64}["\']',
            r'x-api-key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,64}["\']',
        ],
        "severity": "CRITICAL",
        "description": "Hardcoded API keys in JavaScript expose backend services to unauthorized access.",
        "impact": "Direct unauthorized access to backend APIs. Attacker can abuse rate limits, exfiltrate data, perform actions on behalf of the application, and potentially incur financial costs through API usage billing. Many API keys grant broad permissions without IP restriction.",
        "exploitation": "Extract the API key and use it directly against the API endpoints. Test rate limits, data access scopes, and billing implications.",
        "remediation": "Proxy API calls through a backend service. Use environment variables. Implement key rotation and IP whitelisting.",
    },
    "aws_key": {
        "patterns": [
            r'AKIA[0-9A-Z]{16}',
            r'ASIA[0-9A-Z]{16}',
            r'secretAccessKey["\']?\s*[:=]\s*["\'][A-Za-z0-9/+]{40}["\']',
            r'aws_secret_access_key["\']?\s*[:=]\s*["\'][A-Za-z0-9/+]{40}["\']',
        ],
        "severity": "CRITICAL",
        "description": "AWS credentials exposed in JavaScript. Can lead to cloud account compromise and massive resource abuse.",
        "impact": "Complete AWS account compromise. Attacker gains full access to S3 buckets (data exfiltration), EC2 instances (cryptomining), IAM roles (privilege escalation), and Lambda functions. Financial damage can reach hundreds of thousands of dollars through resource abuse. Data breaches of stored customer data may result in regulatory fines.",
        "exploitation": "Use AWS CLI with exposed keys. Attempt s3 ls, ec2 describe-instances, iam list-roles. Check for privilege escalation paths.",
        "remediation": "Use AWS Cognito or temporary STS credentials. Never embed IAM user keys in frontend code. Use Web Identity Federation.",
    },
    "firebase_config": {
        "patterns": [
            r'apiKey["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{30,}["\']',
            r'authDomain["\']?\s*[:=]\s*["\'][A-Za-z0-9.\-]+firebaseapp\.com["\']',
            r'databaseURL["\']?\s*[:=]\s*["\']https://[A-Za-z0-9\-]+\.firebaseio\.com["\']',
            r'projectId["\']?\s*[:=]\s*["\'][A-Za-z0-9\-]{5,}["\']',
            r'storageBucket["\']?\s*[:=]\s*["\'][A-Za-z0-9.\-]+\.appspot\.com["\']',
            r'messagingSenderId["\']?\s*[:=]\s*["\'][0-9]{10,}["\']',
            r'appId["\']?\s*[:=]\s*["\']1:[0-9]+:web:[a-f0-9]+["\']',
        ],
        "severity": "HIGH",
        "description": "Firebase configuration exposed. While some exposure is normal, misconfigured Firebase security rules can allow data access.",
        "impact": "Complete database exposure if security rules allow public read/write. Attacker can dump all Firestore/Realtime Database contents (user PII, messages, payment data), upload malicious files to Storage, and create new user accounts via Auth. Regulatory violations (GDPR, CCPA) from exposed user data.",
        "exploitation": "Use the exposed config to initialize Firebase SDK. Attempt to access Firestore, Realtime Database, Auth, and Storage. Check if security rules are open (read: true, write: true).",
        "remediation": "Lock down Firebase Security Rules. Implement App Check. Never expose admin SDK credentials. Use custom claims for fine-grained access.",
    },
    "stripe_key": {
        "patterns": [
            r'sk_live_[A-Za-z0-9]{20,}',
            r'pk_live_[A-Za-z0-9]{20,}',
            r'sk_test_[A-Za-z0-9]{20,}',
            r'pk_test_[A-Za-z0-9]{20,}',
        ],
        "severity": "CRITICAL",
        "description": "Stripe API keys exposed in JavaScript. Secret keys allow full payment processing capabilities.",
        "impact": "Direct financial theft. With a live secret key (sk_live_), attacker can create charges, refund transactions, and access customer PII including credit card metadata. Ability to exfiltrate full customer database, create fraudulent charges, and drain connected accounts. PCI DSS compliance violations and potential blacklisting by payment processors.",
        "exploitation": "Use Stripe CLI or API to list customers, charges, refunds. Secret keys (sk_) can create charges, refund transactions, and access PII.",
        "remediation": "Never embed secret keys in frontend code. Use publishable keys (pk_) only client-side. Implement Stripe Elements or Checkout. Rotate compromised keys immediately.",
    },
    "github_token": {
        "patterns": [
            r'ghp_[A-Za-z0-9]{36}',
            r'gho_[A-Za-z0-9]{36}',
            r'ghu_[A-Za-z0-9]{36}',
            r'ghs_[A-Za-z0-9]{36}',
            r'ghr_[A-Za-z0-9]{36}',
            r'github_pat_[A-Za-z0-9_]{60,}',
        ],
        "severity": "CRITICAL",
        "description": "GitHub tokens (PAT, OAuth, or installation tokens) exposed in JavaScript. Can lead to repository compromise.",
        "impact": "Complete source code and secrets compromise. Attacker can read/write to all accessible repositories, exfiltrate proprietary source code, inject backdoors into production code, access Actions secrets (which often contain cloud credentials), and modify CI/CD pipelines to distribute malware to users.",
        "exploitation": "Use GitHub API to test token scope. List repos, access private repos, modify code, exfiltrate secrets from other repos.",
        "remediation": "Use OAuth device flow for CLI tools. Never embed tokens in frontend. Use GitHub Actions environment secrets for backend flows.",
    },
    "auth_token_generic": {
        "patterns": [
            r'token["\']?\s*[:=]\s*["\'][A-Za-z0-9\-._~+/]{20,}["\']',
            r'session_token["\']?\s*[:=]\s*["\'][A-Za-z0-9\-._~+/]{20,}["\']',
            r'csrf_token["\']?\s*[:=]\s*["\'][A-Za-z0-9\-._~+/]{10,}["\']',
            r'localStorage\.setItem\(["\']token["\']',
            r'sessionStorage\.setItem\(["\']token["\']',
        ],
        "severity": "HIGH",
        "description": "Authentication tokens, session identifiers, or CSRF tokens found in JavaScript source. Direct disclosure of active session tokens.",
        "impact": "Immediate session hijacking. Attacker can impersonate the user whose token was leaked, access all authenticated functionality, exfiltrate user-specific data, perform actions as the victim. CSRF token leakage enables cross-site request forgery attacks against other users. Persistent session tokens allow long-term unauthorized access.",
        "exploitation": "Capture the token value, intercept browser traffic, replay requests with the stolen token. For CSRF tokens, craft cross-site request forgery attacks.",
        "remediation": "Store session tokens in HttpOnly cookies, not in JavaScript variables or localStorage. Implement token binding. Rotate tokens on each request.",
    },
    "oauth_callback": {
        "patterns": [
            r'client_id["\']?\s*[:=]\s*["\'][A-Za-z0-9\-._~]{10,}["\']',
            r'client_secret["\']?\s*[:=]\s*["\'][A-Za-z0-9\-._~]{20,}["\']',
            r'redirect_uri["\']?\s*[:=]\s*["\'][A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,}["\']',
        ],
        "severity": "HIGH",
        "description": "OAuth client credentials or redirect URIs exposed. Can enable authorization code interception and token theft.",
        "impact": "Authorization code interception attack. Attacker can modify the redirect_uri to their own server, capture authorization codes from legitimate users, exchange them for access tokens using the exposed client_id/secret, and gain persistent access to victim accounts on the OAuth provider. Widespread account compromise across the user base.",
        "exploitation": "Modify redirect_uri to attacker-controlled server. Intercept authorization codes. Exchange codes for tokens using exposed client_id/secret.",
        "remediation": "Use PKCE (Proof Key for Code Exchange). Validate redirect_uri strictly server-side. Never expose client_secret in frontend code.",
    },
    "password_field": {
        "patterns": [
            r'password["\']?\s*[:=]\s*["\'][A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{4,}["\']',
            r'passwd["\']?\s*[:=]\s*["\'][A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{4,}["\']',
            r'pwd["\']?\s*[:=]\s*["\'][A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{4,}["\']',
            r'secret["\']?\s*[:=]\s*["\'][A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{4,}["\']',
        ],
        "severity": "CRITICAL",
        "description": "Plaintext passwords or secrets hardcoded in JavaScript source code.",
        "impact": "Direct credential exposure leading to system compromise. Attacker can use passwords to access user accounts, admin panels, databases, SSH servers, email servers, or third-party services. Credential stuffing across other platforms using the same password. If database credentials are exposed, complete data breach of all stored information.",
        "exploitation": "Use the credentials directly. Test against login endpoints, SSH, databases, or third-party services. Try credential stuffing.",
        "remediation": "Never hardcode credentials. Use server-side environment variables. Implement proper authentication flows with token exchange.",
    },
    "internal_endpoint": {
        "patterns": [
            r'["\']https?://(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})["\']',
            r'["\']https?://[A-Za-z0-9\-\.]*internal[A-Za-z0-9\-\.]*["\']',
            r'["\']https?://[A-Za-z0-9\-\.]*admin[A-Za-z0-9\-\.]*["\']',
        ],
        "severity": "HIGH",
        "description": "Internal network endpoints exposed in JavaScript. Can reveal infrastructure topology and internal services.",
        "impact": "Network mapping and lateral movement. Attacker learns your internal network structure, server naming conventions, and service locations. SSRF (Server-Side Request Forgery) attacks can target these internal endpoints. Admin interfaces without proper authentication become directly accessible. Pivot point for deeper infrastructure compromise.",
        "exploitation": "Probe discovered internal endpoints. Check for missing authentication. Attempt SSRF through exposed endpoints. Map internal network.",
        "remediation": "Never embed internal IPs/hostnames in frontend code. Use API gateways. Implement proper network segmentation.",
    },
    "debug_code": {
        "patterns": [
            r'console\.log\(["\'][^"\']*(?:token|key|secret|password|auth|credential|jwt|session)[^"\']*["\']',
            r'//\s*(TODO|FIXME|HACK|BUG|XXX|DEV|TEMP)\s*:?\s*[^\n]*',
        ],
        "severity": "MEDIUM",
        "description": "Debug code, leftover development comments, or console.log statements leaking sensitive information.",
        "impact": "Information disclosure to end users. Anyone with browser devtools can view leaked sensitive data in the console. Debug comments reveal API endpoints, authentication flows, bypass techniques, and internal architecture. TODO/FIXME comments indicate incomplete security implementations that attackers can exploit. Hardcoded test credentials in debug code enable direct system access.",
        "exploitation": "Open browser console to view logged data. Debug strings may reveal API structures, parameter names, or authentication flows.",
        "remediation": "Remove all debug code before production. Use build tools to strip console.log statements. Implement proper logging levels.",
    },
    "hash_salt": {
        "patterns": [
            r'salt["\']?\s*[:=]\s*["\'][A-Za-z0-9+/=]{10,}["\']',
            r'hash_secret["\']?\s*[:=]\s*["\'][A-Za-z0-9+/=]{10,}["\']',
            r'encryption_key["\']?\s*[:=]\s*["\'][A-Za-z0-9+/=]{10,}["\']',
            r'hmac_secret["\']?\s*[:=]\s*["\'][A-Za-z0-9+/=]{10,}["\']',
        ],
        "severity": "CRITICAL",
        "description": "Cryptographic salts, HMAC secrets, or encryption keys hardcoded in JavaScript. Compromises the entire encryption scheme.",
        "impact": "Complete cryptographic failure. Attacker can decrypt all data that was encrypted with the exposed key, forge valid HMAC signatures to bypass integrity checks, crack password hashes using the exposed salt, and decrypt stored user data including PII and payment information. All security guarantees of the encryption system are nullified.",
        "exploitation": "Extract the key/salt. Decrypt data that was encrypted with these keys. Forge HMAC signatures. If symmetric encryption, decrypt all traffic.",
        "remediation": "Use key management services (KMS, Vault). Rotate keys regularly. Never store encryption keys in frontend code.",
    },
    "graphql_endpoint": {
        "patterns": [
            r'["\']https?://[^"\']*graphql["\']',
            r'["\']https?://[^"\']*/graphql["\']',
            r'["\']https?://[^"\']*/v1/graphql["\']',
            r'["\']https?://[^"\']*/query["\']',
        ],
        "severity": "MEDIUM",
        "description": "GraphQL endpoint discovered. May be exploitable via introspection queries, batching attacks, or injection.",
        "impact": "API abuse and data harvesting. Introspection exposes the entire API schema, allowing attackers to discover all available queries, mutations, and data types. Batch queries bypass rate limiting to extract large datasets. Injection attacks (SQL, NoSQL) can access restricted data. Missing depth limiting enables recursive queries that cause denial of service.",
        "exploitation": "Query __schema for full API introspection. Use batch queries for rate limit bypass. Attempt SQL injection in GraphQL arguments. Check for missing depth limiting.",
        "remediation": "Disable introspection in production. Implement query depth limiting, rate limiting, and authentication. Use persisted queries.",
    },
    "s3_bucket": {
        "patterns": [
            r'["\']https?://[A-Za-z0-9\-\.]*s3[.\-][A-Za-z0-9\-\.]*amazonaws\.com["\']',
            r'["\']https?://s3[.\-][A-Za-z0-9\-\.]*amazonaws\.com/[A-Za-z0-9\-_.]+["\']',
            r'["\']https?://[A-Za-z0-9\-_]+\.s3[.\-][A-Za-z0-9\-\.]*amazonaws\.com["\']',
        ],
        "severity": "HIGH",
        "description": "S3 bucket references found in JavaScript. Buckets may be misconfigured for public read/write.",
        "impact": "Massive data breach. If buckets allow public listing, attacker can enumerate and download all stored objects including user uploads, backups, configuration files, and sensitive documents. If write access is enabled, attacker can plant malicious files (malware, ransomware) or deface the application. Compliance violations under GDPR, HIPAA, PCI DSS for exposed customer data.",
        "exploitation": "List bucket contents using AWS CLI or HTTP. Attempt to upload files. Check for directory listing enabled. Access sensitive data files.",
        "remediation": "Block all public access. Use bucket policies with least privilege. Enable encryption. Enable CloudTrail for auditing.",
    }
}

# ============================================================
# CORE SCANNING ENGINE
# ============================================================

class NightRiderScanner:
    """Core scanning engine for JavaScript token vulnerability detection."""

    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NightRider-Scanner/1.0 (Security Assessment Tool)',
        })
        self.results = []
        self.scanned_urls = set()
        self.start_time = None
        self.end_time = None

    def scan(self):
        """Main scan entry point."""
        self.start_time = datetime.now()

        scan_header = Panel(
            f"[bold cyan]Target:[/] [yellow]{self.target_url}[/]\n"
            f"[bold cyan]Started:[/] [white]{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}[/]",
            title="[bold green]SCANNING INITIATED[/]",
            border_style="green",
            padding=(1, 2)
        )
        console.print(scan_header)
        console.print()

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task1 = progress.add_task("[cyan]Discovering JavaScript files...", total=100)
            js_files = self._discover_javascript()
            progress.update(task1, completed=100)

            if js_files:
                task2 = progress.add_task("[magenta]Scanning tokens and secrets...", total=len(js_files))
                for js_url in js_files:
                    self._scan_javascript_file(js_url)
                    progress.update(task2, advance=1)

                task3 = progress.add_task("[green]Analyzing results...", total=100)
                self._analyze_results()
                progress.update(task3, completed=100)
            else:
                console.print("[yellow]No JavaScript files discovered to scan.[/]")

        self.end_time = datetime.now()
        return self.results

    def _discover_javascript(self):
        """Discover JavaScript files from the target."""
        js_files = set()
        try:
            console.print(f"[dim]  → Fetching: {self.target_url}[/]")
            resp = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                content = resp.text

                script_patterns = [
                    r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']',
                    r'<script[^>]*src=["\']([^"\']+)["\']',
                    r'import\(["\']([^"\']+\.js[^"\']*)["\']\)',
                    r'require\(["\']([^"\']+\.js[^"\']*)["\']\)',
                ]
                for pattern in script_patterns:
                    found = re.findall(pattern, content, re.IGNORECASE)
                    for js in found:
                        if js.endswith('.js') or '.js?' in js:
                            full_url = urljoin(self.target_url, js)
                            if full_url not in self.scanned_urls:
                                js_files.add(full_url)
                                self.scanned_urls.add(full_url)

                inline_patterns = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
                for i, inline in enumerate(inline_patterns, 1):
                    if inline.strip():
                        inline_url = f"{self.target_url}#inline-{i}"
                        js_files.add(inline_url)
                        self.scanned_urls.add(inline_url)
                        self._scan_raw_javascript(inline, inline_url, "Inline HTML")

            console.print(f"[green]✓[/] Discovered [bold]{len(js_files)}[/] JavaScript sources")

        except requests.exceptions.RequestException as e:
            console.print(f"[red]✗[/] Failed to fetch {self.target_url}: {e}")

        return list(js_files)

    def _scan_javascript_file(self, js_url):
        """Scan a JavaScript file for token vulnerabilities."""
        try:
            if '#inline-' in js_url:
                return

            resp = self.session.get(js_url, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                content = resp.text
                self._scan_raw_javascript(content, js_url, "External JS")

        except Exception:
            pass

    def _scan_raw_javascript(self, content, source, source_type):
        """Scan raw JavaScript content for token patterns."""
        for vuln_type, vuln_info in TOKEN_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                try:
                    matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        if len(match) < 4 or match in [r[0] for r in self.results]:
                            continue

                        line_no = self._find_line_number(content, match)
                        context = self._get_context(content, match)

                        finding = (
                            match[:80] + '...' if len(match) > 80 else match,
                            vuln_type,
                            vuln_info["severity"],
                            vuln_info["description"],
                            vuln_info["impact"],
                            vuln_info["exploitation"],
                            vuln_info["remediation"],
                            source,
                            source_type,
                            line_no,
                            context
                        )
                        self.results.append(finding)

                except Exception:
                    continue

    def _find_line_number(self, content, match_str):
        """Approximate line number of a match in content."""
        try:
            idx = content.index(match_str[:min(len(match_str), 50)])
            return content[:idx].count('\n') + 1
        except ValueError:
            return 0

    def _get_context(self, content, match_str, context_lines=2):
        """Get surrounding context for a match."""
        try:
            idx = content.index(match_str[:min(len(match_str), 50)])
            start = max(0, content.rfind('\n', 0, idx) - context_lines)
            start = content.find('\n', start) + 1 if start > 0 else 0
            end = content.find('\n', idx + len(match_str))
            end = content.find('\n', end + 1) + 1 if end > 0 else len(content)
            return content[start:end].strip()
        except:
            return ""

    def _analyze_results(self):
        """Post-scan analysis and summary."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.results.sort(key=lambda r: severity_order.get(r[2], 999))


# ============================================================
# DISPLAY FUNCTIONS
# ============================================================

def display_results_rich(results, target_url):
    """Display scanning results using Rich tables."""
    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold yellow",
        "MEDIUM": "bold blue",
        "LOW": "cyan"
    }

    if not results:
        console.print(Panel("[green]No token vulnerabilities found![/]", title="Results Summary", border_style="green"))
        return

    summary_table = Table(title=f"SCAN SUMMARY - {target_url}", box=box.DOUBLE_EDGE, border_style="cyan")
    summary_table.add_column("Severity", style="bold", width=12)
    summary_table.add_column("Count", justify="center", width=8)

    severity_counts = {}
    for r in results:
        sev = r[2]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_severities = sorted(severity_counts.keys(), key=lambda s: severity_order.get(s, 999))

    for sev in sorted_severities:
        color = severity_colors.get(sev, "white")
        summary_table.add_row(f"[{color}]{sev}[/]", str(severity_counts[sev]))

    summary_table.add_row("─" * 10, "─" * 8, style="dim")
    summary_table.add_row(f"[bold]TOTAL[/]", f"[bold]{len(results)}[/]")
    console.print(summary_table)
    console.print()

    for idx, (token, vuln_type, severity, description, impact, exploitation, remediation, source, source_type, line_no, context) in enumerate(results, 1):
        color = severity_colors.get(severity, "white")
        severity_badge = f"[{color}]{severity}[/]"
        border_map = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue"}
        border = border_map.get(severity, "cyan")

        detail_panel = Panel(
            f"""[bold]Token Detected:[/] {token}

[bold cyan]Vulnerability Type:[/] {vuln_type.replace('_', ' ').upper()}
[bold]Severity:[/] {severity_badge}
[bold]Found In:[/] {source}
[bold]Location:[/] {source_type} ~ Line {line_no}

[bold red]Description:[/]
{description}

[bold magenta]Business Impact:[/]
{impact}

[bold yellow]Exploitation:[/]
{exploitation}

[bold green]Remediation:[/]
{remediation}
            """,
            title=f"[{color}]Finding #{idx}[/]",
            border_style=border,
            padding=(1, 2),
            width=90
        )
        console.print(detail_panel)
        console.print()


def save_report(results, target_url, filename=None):
    """Save scan report to JSON file."""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = target_url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
        filename = f"nightrider_report_{safe_url}_{timestamp}.json"

    report = {
        "tool": "NightRider - JavaScript Token Vulnerability Scanner",
        "version": "1.0.0",
        "scan_target": target_url,
        "scan_timestamp": datetime.now().isoformat(),
        "total_findings": len(results),
        "vulnerabilities": []
    }

    for token, vuln_type, severity, description, impact, exploitation, remediation, source, source_type, line_no, context in results:
        report["vulnerabilities"].append({
            "token_preview": token,
            "vulnerability_type": vuln_type,
            "severity": severity,
            "description": description,
            "business_impact": impact,
            "exploitation": exploitation,
            "remediation": remediation,
            "source": source,
            "source_type": source_type,
            "line_number": line_no,
            "context_snippet": context
        })

    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)

    console.print(f"[green]✓[/] Report saved to [bold]{filename}[/]")
    return filename


def export_report_text(results, target_url, filename=None):
    """Export report as formatted text file."""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = target_url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
        filename = f"nightrider_report_{safe_url}_{timestamp}.txt"

    with open(filename, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("NIGHTRIDER - JAVASCRIPT TOKEN VULNERABILITY SCANNER\n")
        f.write("Authorized Security Assessment Tool\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Target: {target_url}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Findings: {len(results)}\n\n")
        f.write("-" * 80 + "\n\n")

        for idx, (token, vuln_type, severity, description, impact, exploitation, remediation, source, source_type, line_no, context) in enumerate(results, 1):
            f.write(f"[FINDING #{idx}]\n")
            f.write(f"Token: {token}\n")
            f.write(f"Type: {vuln_type.replace('_', ' ').upper()}\n")
            f.write(f"Severity: {severity}\n")
            f.write(f"Source: {source}\n")
            f.write(f"Location: {source_type} ~ Line {line_no}\n\n")
            f.write(f"Description:\n{description}\n\n")
            f.write(f"Business Impact:\n{impact}\n\n")
            f.write(f"Exploitation:\n{exploitation}\n\n")
            f.write(f"Remediation:\n{remediation}\n\n")
            f.write("Context Snippet:\n")
            f.write(f"{context}\n\n")
            f.write("-" * 40 + "\n\n")

        f.write("=" * 80 + "\n")
        f.write("END OF REPORT - NIGHTRIDER v1.0\n")
        f.write("=" * 80 + "\n")

    console.print(f"[green]✓[/] Report exported to [bold]{filename}[/]")
    return filename


def show_startup_glitch():
    """Animated glitch sequence that plays once on startup."""
    console.clear()

    frames = [
        "[red]░▒▓█ N!GHTR!DER █▓▒░ initializing kernel...[/]",
        "[yellow]Loading government-grade WAF bypass module... ▓░░░░░░░░░ 12%[/]",
        "[yellow]Loading government-grade WAF bypass module... █▓░░░░░░░░ 25%[/]",
        "[yellow]Decrypting black market token endpoints... ██▓░░░░░░░ 35%[/]",
        "[yellow]Mapping dark web JS repositories... ███▓░░░░░░ 45%[/]",
        "[red][!] TOKEN LEAK DETECTED: JWT session token in cleartext[/]",
        "[yellow]Bypassing CORS restrictions... ████▓░░░░░ 60%[/]",
        "[red][!] INTERNAL ENDPOINT: https://admin.internal.gov/api/v2/tokens[/]",
        "[yellow]Extracting Firebase configuration... █████▓░░░░ 75%[/]",
        "[red][!] FIREBASE DB OPEN: No security rules detected[/]",
        "[yellow]Injecting into government session store... ██████▓░░░ 85%[/]",
        "[red][!] AWS SECRET KEY FOUND: Full S3 bucket access granted[/]",
        "[yellow]Compiling evidence... ████████▓░ 95%[/]",
        "[green]█ N!GHTR!DER ACCESS GRANTED █ - System ready[/]",
    ]

    for frame in frames:
        console.clear()
        console.print("[bold red]" + "=" * 60 + "[/]")
        console.print("[bold red]!!! STARTUP SEQUENCE !!![/]")
        console.print("[bold red]" + "=" * 60 + "[/]")
        console.print()
        console.print(frame)
        console.print()
        console.print(Panel(
            "[bold green]N!GHTR!DER v1.0[/]\n"
            "[dim]JavaScript Token Vulnerability Scanner[/]\n"
            "[dim]Authorized Pentesting Tool[/]",
            border_style="red",
            width=50
        ))
        time.sleep(0.35)

    time.sleep(0.5)


def prompt_save_results(results, target_url):
    """Ask user if they want to save results after a scan."""
    if not results:
        return

    console.print()
    save_panel = Panel(
        "[bold yellow]Would you like to save the scan results?[/]\n\n"
        "[cyan]Options:[/]\n"
        "  [1] Save as JSON report\n"
        "  [2] Export as text file\n"
        "  [3] Save both (JSON + TXT)\n"
        "  [0] Skip, return to menu\n",
        title="[bold green]SAVE RESULTS[/]",
        border_style="green",
        padding=(1, 2)
    )
    console.print(save_panel)
    console.print()

    save_choice = input("[bold yellow]Save option [0-3]: [/]").strip()

    if save_choice == "1":
        fname = input("[bold green]JSON filename (Enter for auto-name): [/]").strip()
        if fname and not fname.endswith('.json'):
            fname += '.json'
        save_report(results, target_url, fname if fname else None)

    elif save_choice == "2":
        fname = input("[bold blue]Text filename (Enter for auto-name): [/]").strip()
        if fname and not fname.endswith('.txt'):
            fname += '.txt'
        export_report_text(results, target_url, fname if fname else None)

    elif save_choice == "3":
        fname_json = input("[bold green]JSON filename (Enter for auto-name): [/]").strip()
        if fname_json and not fname_json.endswith('.json'):
            fname_json += '.json'
        save_report(results, target_url, fname_json if fname_json else None)

        fname_txt = input("[bold blue]Text filename (Enter for auto-name): [/]").strip()
        if fname_txt and not fname_txt.endswith('.txt'):
            fname_txt += '.txt'
        export_report_text(results, target_url, fname_txt if fname_txt else None)

    elif save_choice == "0":
        console.print("[dim]Skipping save...[/]")

    else:
        console.print("[red]Invalid option. Skipping save.[/]")


# ============================================================
# MAIN MENU SYSTEM
# ============================================================

def show_banner():
    """Display NightRider banner."""
    console.clear()
    console.print("[bold cyan]" + BANNER + "[/]")
    console.print("[dim]Authorized Security Assessment Tool | For Pentesters & Security Researchers[/]")
    console.print("[dim]Use only on systems you own or have explicit written permission to test.[/]")
    console.print()


def main():
    """Main application entry point."""

    # Play glitch startup sequence once
    show_startup_glitch()

    results = []
    last_target = None

    while True:
        show_banner()

        if results:
            severity_colors = {
                "CRITICAL": "bold red",
                "HIGH": "bold yellow",
                "MEDIUM": "bold blue",
                "LOW": "cyan"
            }

            sev_counts = {}
            for r in results:
                sev = r[2]
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_sevs = sorted(sev_counts.keys(), key=lambda s: severity_order.get(s, 999))
            sev_parts = []
            for s in sorted_sevs:
                c = severity_colors.get(s, 'white')
                sev_parts.append(f"[{c}]{s}: {sev_counts[s]}[/]")
            sev_summary = " | ".join(sev_parts)

            status_table = Table(title="CURRENT SCAN STATUS", box=box.SIMPLE, border_style="green")
            status_table.add_column("Metric", style="bold", width=20)
            status_table.add_column("Value", width=60)
            status_table.add_row("Target", f"[cyan]{last_target}[/]")
            status_table.add_row("Total Findings", f"[bold]{len(results)}[/]")
            status_table.add_row("Severity", sev_summary)
            console.print(status_table)
            console.print()

        menu_table = Table(title="NIGHTRIDER MAIN MENU", box=box.HEAVY_EDGE, border_style="cyan", title_style="bold cyan")
        menu_table.add_column("#", style="bold yellow", width=4)
        menu_table.add_column("Action", style="white", width=28)
        menu_table.add_column("Description", style="dim", width=55)

        menu_table.add_row("[1]", "[bold cyan]START SCANNING[/]", "Enter a website URL and scan for token vulnerabilities")
        menu_table.add_row("[2]", "[bold magenta]VIEW REPORTS[/]", "Display results from the last scan")
        menu_table.add_row("[3]", "[bold green]SAVE REPORTS[/]", "Save scan results to JSON format")
        menu_table.add_row("[4]", "[bold blue]EXPORT REPORT[/]", "Export scan results as formatted text file")
        menu_table.add_row("[0]", "[bold white]EXIT[/]", "Exit NightRider")
        console.print(menu_table)
        console.print()

        try:
            choice = input("[bold yellow]Enter your choice [0-4]: [/]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[red]Exiting NightRider...[/]")
            break

        if choice == "1":
            console.clear()
            show_banner()
            console.print()

            target_panel = Panel(
                "[bold yellow]Enter the full URL of the website you want to scan[/]\n\n"
                "[cyan]Examples:[/]\n"
                "  • https://example.com\n"
                "  • https://app.example.com/login\n"
                "  • http://192.168.1.100:8080\n\n"
                "[dim]The scanner will fetch the page, discover all JavaScript files,[/]\n"
                "[dim]and scan them for exposed tokens, secrets, and credentials.[/]",
                title="[bold cyan]TARGET WEBSITE INPUT[/]",
                border_style="cyan",
                padding=(1, 2)
            )
            console.print(target_panel)
            console.print()

            target = input("[bold yellow]Website URL: [/]").strip()

            if not target:
                console.print("[red]No URL entered. Returning to menu.[/]")
                time.sleep(1.5)
                continue

            parsed = urlparse(target)
            if not parsed.scheme:
                target = f"https://{target}"
                console.print(f"[yellow]Defaulting to: [bold]{target}[/][/]")
                time.sleep(0.5)

            console.print()
            console.print(f"[bold green]✓ Target set to:[/] [bold cyan]{target}[/]")
            console.print()

            scanner = NightRiderScanner(target)
            scan_results = scanner.scan()

            console.print()
            console.print("[bold green]" + "═" * 50 + "[/]")
            console.print(f"[bold green]✓ SCAN COMPLETE[/] — Found [bold yellow]{len(scan_results)}[/] vulnerabilities")
            console.print("[bold green]" + "═" * 50 + "[/]")
            console.print()

            results = scan_results
            last_target = target

            if results:
                display_results_rich(results, target)
                prompt_save_results(results, target)

            input("[dim]Press Enter to return to main menu...[/]")

        elif choice == "2":
            if not results:
                console.print("[red]No scan results available. Run a scan first (Option 1).[/]")
                time.sleep(1.5)
                continue

            console.print()
            display_results_rich(results, last_target or "Unknown")
            input("[dim]Press Enter to return to menu...[/]")

        elif choice == "3":
            if not results:
                console.print("[red]No scan results to save. Run a scan first (Option 1).[/]")
                time.sleep(1.5)
                continue

            fname = input("[bold green]Filename (Enter for auto-name): [/]").strip()
            if fname and not fname.endswith('.json'):
                fname += '.json'
            save_report(results, last_target or "unknown", fname if fname else None)
            input("[dim]Press Enter to return to menu...[/]")

        elif choice == "4":
            if not results:
                console.print("[red]No scan results to export. Run a scan first (Option 1).[/]")
                time.sleep(1.5)
                continue

            fname = input("[bold blue]Filename (Enter for auto-name): [/]").strip()
            if fname and not fname.endswith('.txt'):
                fname += '.txt'
            export_report_text(results, last_target or "unknown", fname if fname else None)
            input("[dim]Press Enter to return to menu...[/]")

        elif choice == "0":
            console.print("[bold cyan]Thank you for using NightRider![/]")
            console.print("[dim]Stay ethical, stay authorized.[/]")
            break

        else:
            console.print("[red]Invalid option. Enter a number between 0 and 4.[/]")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]NightRider terminated by user.[/]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/]")
        sys.exit(1)
