# Nightrider

NightRider - JavaScript Token Vulnerability Scanner
Version Python License Pentesters

NightRider is a specialized JavaScript vulnerability scanner designed for authorized penetration testers and security researchers. It automates the discovery of sensitive tokens, hardcoded secrets, and cryptographic material leaked within client-side JavaScript bundles and inline scripts.

⚡ Features
Automated JS Discovery: Automatically crawls a target URL to find all linked .js files and extracts inline scripts from HTML.
Deep Pattern Analysis: Detects over 10+ categories of secrets including JWTs, AWS Keys, Stripe Secrets, Firebase Configs, and more.
Impact Assessment: Every finding includes a detailed Business Impact section, explaining exactly what an attacker could do with the leaked data.
Rich Terminal UI: Beautifully formatted tables, panels, and progress bars powered by the Rich library.
Glitch Startup Sequence: A unique, hacker-aesthetic startup animation.
Flexible Reporting: Save findings instantly as JSON for automated workflows or export as TXT for manual reporting.
🔍 Detection Capabilities

Vulnerability Type	Severity	Impact
JWT Tokens	CRITICAL	Account Takeover / Admin impersonation
AWS Credentials	CRITICAL	Cloud Infrastructure Hijacking
Stripe Secret Keys	CRITICAL	Financial Theft / Payment Processing Abuse
GitHub PATs	CRITICAL	Source Code Exfiltration / CI/CD Compromise
Firebase Configs	HIGH	Database Dumping / Unauthorized Auth
Auth Tokens	HIGH	Immediate Session Hijacking
Internal Endpoints	MEDIUM	Infrastructure Discovery / SSRF Targets

Vulnerability Type	Severity	Impact
JWT Tokens	CRITICAL	Account Takeover / Admin impersonation
AWS Credentials	CRITICAL	Cloud Infrastructure Hijacking
Stripe Secret Keys	CRITICAL	Financial Theft / Payment Processing Abuse
GitHub PATs	CRITICAL	Source Code Exfiltration / CI/CD Compromise
Firebase Configs	HIGH	Database Dumping / Unauthorized Auth
Auth Tokens	HIGH	Immediate Session Hijacking
Internal Endpoints	MEDIUM	Infrastructure Discovery / SSRF Targets
🚀 Installation
Clone the repository:
bash



git clone https://github.com/Desmued2/nightrider.git
cd nightrider
Install dependencies:
bash



pip install rich requests urllib3
Run the scanner:
sudo python3 Nightrider.py



python3 nightrider.py
🛠 Usage
Launch: Open the tool and watch the glitch initialization.
Scan: Select option 1 and enter your target URL (e.g., https://target-site.com).
Analyze: Review the detailed findings including the Description, Exploitation Vector, and Impact.
Report: Use the post-scan prompt to save your findings as a .json or .txt report.
🛡 Disclaimer
NightRider is intended for authorized security auditing purposes only. Accessing systems without explicit written permission is illegal. The developers of NightRider assume no liability and are not responsible for any misuse or damage caused by this program.

🤝 Contributing
Contributions are welcome! If you have a regex pattern for a common token or want to improve the UI:

Fork the repo.
Create your feature branch (git checkout -b feature/AmazingFeature).
Commit your changes.
Open a Pull Request.
📜 License
Distributed under the MIT License. See LICENSE for more information.
