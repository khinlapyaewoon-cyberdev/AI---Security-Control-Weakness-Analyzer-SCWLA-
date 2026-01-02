# 🛡️ SCWLA v3: AI Security Control Weakness Analyzer (Chunked Batch LLaMA)
🗓️ Tool Completion Date: December 2025

Defensive Security Control Weakness Analysis Streamlit App

SCWLA v3 is a **strictly defensive cybersecurity tool** designed to analyze reconnaissance TXT files and detect **weaknesses in security controls**, provide **dynamic risk scoring**, **MITRE ATT&CK & OWASP mapping**, and generate **defensive recommendations** via **chunked LLaMA analysis** — **without generating exploits or offensive instructions**.

⚠️ WARNING: Use only on systems you own or are explicitly authorized to analyze.

--------------------------------------------------

✨ FEATURES

🔐 Security Control Weakness Detection
- Detects gaps in WAF, CSP, TLS/HTTPS, Authentication, Authorization, Rate Limiting, CORS, Security Headers, API Gateway, Reverse Proxy, Firewall, IDS/IPS, DDoS Protection, Cloud Security, Container Security, Secrets Management, Patch Management, Logging & Monitoring, Security Awareness, and Incident Response Controls
- Indicator-based detection via reconnaissance TXT files

📊 Dynamic Risk Scoring
- Automatic risk calculation per control (0–10 scale)
- Defensive scoring logic
- Highlights high-risk areas

🧭 MITRE ATT&CK & OWASP Mapping
- Dynamic mapping based on risk level
- High-risk flags are annotated with "-High"
- Supports defensive threat modeling and remediation prioritization

🤖 Chunked LLaMA 3.1 Defensive Analysis
- Chunked requests to prevent timeout
- Provides structured defensive report per control
- Sections include:
  1. Purpose of security control
  2. Common weaknesses or blind spots
  3. Possible information leakage or risk (high-level)
  4. Why these weaknesses exist
  5. Secure configuration & hardening steps
  6. Monitoring & validation recommendations
- ❌ No exploits, bypasses, or offensive steps

📈 Streamlit Dashboard
- Visual metrics for risk scores
- MITRE ATT&CK & OWASP Top-10 mappings
- Consolidated defensive analysis display
- LLaMA temperature adjustment for creativity/analysis depth

📄 Structured TXT Report
- Human-readable, SOC-ready
- Includes all risk scores, mappings, and LLaMA analysis
- Exportable and shareable for academic or professional review

--------------------------------------------------

⚙️ INSTALLATION

pip install streamlit huggingface_hub

--------------------------------------------------

▶️ USAGE

streamlit run app.py

1. Upload a reconnaissance TXT file 📂  
2. Adjust LLaMA temperature 🌡️ (analysis depth)  
3. Review detected security controls and dynamic risk scores 📊  
4. Explore MITRE ATT&CK & OWASP mapping 🧭  
5. Read consolidated defensive LLaMA analysis 📝  
6. Download the structured TXT report 💾  

--------------------------------------------------

🔍 DETECTION CATEGORIES

- 🛡️ Web Application Firewall (WAF)  
- 📜 Content Security Policy (CSP)  
- 🔒 TLS / HTTPS Configuration  
- 🔑 Authentication System  
- 🛂 Authorization / Access Control  
- 🤖 Rate Limiting / Bot Protection  
- 🌐 CORS Policy  
- 🏷️ Security Headers  
- ⚙️ API Gateway  
- 🌉 Reverse Proxy / Load Balancer  
- 🔥 Firewall  
- 🕵️ IDS / IPS  
- 🚨 DDoS Protection  
- ☁️ Cloud Security Controls  
- 🐳 Container Security  
- 🔑 Secrets Management  
- 🛠️ Patch Management  
- 📊 Logging & Monitoring  
- 👥 Security Awareness Training  
- ⚡ Incident Response Controls

--------------------------------------------------

🧩 HOW IT WORKS

Recon TXT File 📄  
↓  
Security Control Indicator Detection 🔎  
↓  
Dynamic Risk Scoring 📊  
↓  
MITRE ATT&CK & OWASP Mapping 🧭  
↓  
Chunked LLaMA Defensive Analysis 🤖  
↓  
Streamlit Dashboard & TXT Report Export 📈📄  

--------------------------------------------------

👤 AUTHOR

Khin La Pyae Woon  
AI-Enhanced Ethical Hacking | Cyber Defense | Digital Forensics | Analyze | Developing 

Portfolio: https://khinlapyaewoon-cyberdev.vercel.app  
LinkedIn: www.linkedin.com/in/khin-la-pyae-woon-ba59183a2  
WhatsApp: https://wa.me/qr/MJYX74CQ5VA4D1

--------------------------------------------------

📜 LICENSE & ETHICS

This tool is strictly for **educational, defensive, and research purposes**.

❌ PROHIBITED USES
- Exploit development  
- Offensive security testing  
- Bypass or attack simulations  
- Unauthorized analysis  

SCWLA v3 is designed to **raise awareness, improve defense, and support secure system hardening — never to attack**.

