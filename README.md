# Nightrider
<img width="90" height="20" alt="Version" src="https://github.com/user-attachments/assets/65ecdfd6-86cd-4d3d-b95e-5fa8382d872e" />
<svg xmlns="http://www.w3.org/2000/svg" width="90" height="20" role="img" aria-label="version: 1.0.0"><title>version: 1.0.0</title><filter id="blur"><feGaussianBlur stdDeviation="16"/></filter><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="90" height="20" rx="3"/></clipPath><g clip-path="url(#r)"><rect width="51" height="20" fill="#555"/><rect x="51" width="39" height="20" fill="blueviolet"/><rect width="90" height="20" fill="url(#s)"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110"><g transform="scale(.1)"><g aria-hidden="true" fill="#010101"><text x="265" y="150" fill-opacity=".8" filter="url(#blur)" textLength="410">version</text><text x="265" y="150" fill-opacity=".3" textLength="410">version</text></g><text x="265" y="140" textLength="410">version</text></g><g transform="scale(.1)"><g aria-hidden="true" fill="#010101"><text x="695" y="150" fill-opacity=".8" filter="url(#blur)" textLength="290">1.0.0</text><text x="695" y="150" fill-opacity=".3" textLength="290">1.0.0</text></g><text x="695" y="140" textLength="290">1.0.0</text></g></g></svg>
<img width="86" height="20" alt="Python" src="https://github.com/user-attachments/assets/62468b35-6671-4eef-8645-6feee731dff6" />
<svg xmlns="http://www.w3.org/2000/svg" width="86" height="20" role="img" aria-label="python: 3.8+"><title>python: 3.8+</title><filter id="blur"><feGaussianBlur stdDeviation="16"/></filter><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="86" height="20" rx="3"/></clipPath><g clip-path="url(#r)"><rect width="49" height="20" fill="#555"/><rect x="49" width="37" height="20" fill="#007ec6"/><rect width="86" height="20" fill="url(#s)"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110"><g transform="scale(.1)"><g aria-hidden="true" fill="#010101"><text x="255" y="150" fill-opacity=".8" filter="url(#blur)" textLength="390">python</text><text x="255" y="150" fill-opacity=".3" textLength="390">python</text></g><text x="255" y="140" textLength="390">python</text></g><g transform="scale(.1)"><g aria-hidden="true" fill="#010101"><text x="665" y="150" fill-opacity=".8" filter="url(#blur)" textLength="270">3.8+</text><text x="665" y="150" fill-opacity=".3" textLength="270">3.8+</text></g><text x="665" y="140" textLength="270">3.8+</text></g></g></svg>
<svg xmlns="http://www.w3.org/2000/svg" width="78" height="20" role="img" aria-label="license: MIT"><title>license: MIT</title><filter id="blur"><feGaussianBlur stdDeviation="16"/></filter><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="78" height="20" rx="3"/></clipPath><g clip-path="url(#r)"><rect width="47" height="20" fill="#555"/><rect x="47" width="31" height="20" fill="#67ac09"/><rect width="78" height="20" fill="url(#s)"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110"><g transform="scale(.1)"><g aria-hidden="true" fill="#010101"><text x="245" y="150" fill-opacity=".8" filter="url(#blur)" textLength="370">license</text><text x="245" y="150" fill-opacity=".3" textLength="370">license</text></g><text x="245" y="140" textLength="370">license</text></g><g transform="scale(.1)"><g aria-hidden="true" fill="#010101"><text x="615" y="150" fill-opacity=".8" filter="url(#blur)" textLength="210">MIT</text><text x="615" y="150" fill-opacity=".3" textLength="210">MIT</text></g><text x="615" y="140" textLength="210">MIT</text></g></g></svg>
<img width="78" height="20" alt="License" src="https://github.com/user-attachments/assets/38289d3e-5d89-49e8-8a16-d9196e427e47" />


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
