#!/usr/bin/env python3
"""
SCWLA v3: AI Security Control Weakness Analyzer (Chunked Batch LLaMA)
- Complete defensive output for all controls
- Chunked LLaMA requests to avoid timeouts
- Dynamic risk scoring per control
- Dynamic MITRE & OWASP mapping
- Streamlit dashboard
- Temperature control for LLaMA outputs
"""

import os
import streamlit as st
from huggingface_hub import InferenceClient
from requests.exceptions import ReadTimeout

# ==================================================
# 🔐 CLEAR PROXIES
# ==================================================
for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
    os.environ[k] = ""

# ==================================================
# 🔐 HF CONFIG
# ==================================================
HF_TOKEN_EMBEDDED = "HF_TOKEN"
LLaMA_MODEL = "meta-llama/Llama-3.1-8B-Instruct"

client = InferenceClient(token=HF_TOKEN_EMBEDDED, timeout=300)

# ==================================================
# 🔐 EXPANDED SECURITY CONTROLS
# ==================================================
SECURITY_CONTROLS = {
    "Web Application Firewall (WAF)": ["cloudflare", "akamai", "imperva", "aws waf", "403 forbidden"],
    "Content Security Policy (CSP)": ["content-security-policy"],
    "TLS / HTTPS": ["https", "tls", "ssl certificate"],
    "Authentication System": ["login", "authentication", "signin", "jwt", "session"],
    "Authorization / Access Control": ["role", "permission", "access denied"],
    "Rate Limiting / Bot Protection": ["429 too many requests", "rate limit", "captcha"],
    "CORS Policy": ["access-control-allow-origin"],
    "Security Headers": ["x-frame-options", "x-content-type-options", "strict-transport-security", "referrer-policy"],
    "API Gateway": ["/api/", "api gateway", "graphql"],
    "Reverse Proxy / Load Balancer": ["nginx", "haproxy", "x-forwarded-for"],
    "Firewall": ["iptables", "firewall", "pf", "pfSense", "allow all", "open port"],
    "IDS / IPS": ["snort", "suricata", "ids", "ips", "alert log"],
    "DDoS Protection": ["ddos", "rate limiting", "traffic spike", "cloudflare ddos"],
    "Cloud Security Controls": ["aws", "azure", "gcp", "s3", "iam", "bucket public", "security group"],
    "Container Security": ["docker", "k8s", "kubernetes", "pod security", "container escape"],
    "Secrets Management": ["vault", "secret manager", "env secret", "k8s secret"],
    "Patch Management": ["patch", "update", "vulnerability", "cve", "security bulletin"],
    "Logging & Monitoring": ["audit log", "siem", "log retention", "event log", "elk", "splunk"],
    "Security Awareness Training": ["phishing", "training", "user awareness"],
    "Incident Response Controls": ["playbook", "incident response", "ir drill"]
}

# ==================================================
# MITRE & OWASP DATABASE (simplified)
# ==================================================
CONTROL_MAPPING = {
    "Web Application Firewall (WAF)": {"mitre":["TA0005"], "owasp":["A05"]},
    "Content Security Policy (CSP)": {"mitre":["TA0001"], "owasp":["A03"]},
    "TLS / HTTPS": {"mitre":["TA0006"], "owasp":["A02"]},
    "Authentication System": {"mitre":["TA0006"], "owasp":["A07"]},
    "Authorization / Access Control": {"mitre":["TA0004"], "owasp":["A01"]},
    "Rate Limiting / Bot Protection": {"mitre":["TA0043"], "owasp":["A04"]},
    "CORS Policy": {"mitre":["TA0006"], "owasp":["A05"]},
    "Security Headers": {"mitre":["TA0001"], "owasp":["A05"]},
    "API Gateway": {"mitre":["TA0005"], "owasp":["A05"]},
    "Reverse Proxy / Load Balancer": {"mitre":["TA0005"], "owasp":["A05"]},
    "Firewall": {"mitre":["TA0001"], "owasp":["A05"]},
    "IDS / IPS": {"mitre":["TA0005"], "owasp":["A05"]},
    "DDoS Protection": {"mitre":["TA0043"], "owasp":["A04"]},
    "Cloud Security Controls": {"mitre":["TA0006"], "owasp":["A06"]},
    "Container Security": {"mitre":["TA0006"], "owasp":["A05"]},
    "Secrets Management": {"mitre":["TA0006"], "owasp":["A02"]},
    "Patch Management": {"mitre":["TA0006"], "owasp":["A05"]},
    "Logging & Monitoring": {"mitre":["TA0009"], "owasp":["A09"]},
    "Security Awareness Training": {"mitre":["TA0003"], "owasp":["A08"]},
    "Incident Response Controls": {"mitre":["TA0009"], "owasp":["A09"]}
}

# ==================================================
# DETECT CONTROLS
# ==================================================
def detect_controls(text):
    text_lower = text.lower()
    detected = {}
    for ctrl, indicators in SECURITY_CONTROLS.items():
        count = sum(ind.lower() in text_lower for ind in indicators)
        if count > 0:
            detected[ctrl] = count
    return detected

# ==================================================
# DYNAMIC RISK SCORING
# ==================================================
def compute_dynamic_risk(indicator_count, base_risk=5):
    risk = base_risk + indicator_count
    return min(risk, 10)

# ==================================================
# DYNAMIC MITRE & OWASP BASED ON RISK
# ==================================================
def dynamic_mapping(control, risk_score):
    mapping = CONTROL_MAPPING.get(control, {"mitre":["TA0000"], "owasp":["A00"]})
    dynamic_mitre = [f"{m}-High" if risk_score >=8 else m for m in mapping["mitre"]]
    dynamic_owasp = [f"{o}-High" if risk_score >=8 else o for o in mapping["owasp"]]
    return dynamic_mitre, dynamic_owasp

# ==================================================
# SPLIT CONTROLS INTO CHUNKS
# ==================================================
def chunk_controls(control_list, chunk_size=5):
    for i in range(0, len(control_list), chunk_size):
        yield control_list[i:i+chunk_size]

# ==================================================
# LLaMA DEFENSIVE ANALYSIS (CHUNKED)
# ==================================================
def llama_analysis_batch(controls, temperature=0.3):
    control_list = "\n".join(f"- {c}" for c in controls)
    prompt = f"""
You are a senior defensive security auditor.

The following security controls were detected:
{control_list}

For each control, provide a fully structured defensive security assessment with these sections:

1. Purpose of this security control
2. Common weaknesses or blind spots (defensive awareness only)
3. Possible information leakage or risk (high-level)
4. Why these weaknesses exist
5. Secure configuration & hardening steps
6. Monitoring & validation recommendations

Format clearly per control with headings.
Do NOT include bypass or exploit steps.
Ensure complete output; do not truncate.
"""
    try:
        response = client.chat.completions.create(
            model=LLaMA_MODEL,
            messages=[
                {"role": "system", "content": "You are a senior defensive cybersecurity analyst."},
                {"role": "user", "content": prompt}
            ],
            temperature=temperature,
            max_tokens=4000
        )
        if "choices" in response and len(response["choices"]) > 0:
            return response["choices"][0]["message"]["content"].strip()
        return "⚠️ No response from LLaMA"
    except ReadTimeout:
        return "⚠️ LLaMA request timed out"

# ==================================================
# TXT REPORT GENERATOR
# ==================================================
def generate_txt_report(filename, results, batch_analysis):
    out = f"SCWLA_Report_{filename}.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write("="*70 + "\n")
        f.write("SECURITY CONTROL WEAKNESS & DYNAMIC RISK REPORT\n")
        f.write("="*70 + "\n\n")
        f.write("=== CONSOLIDATED DEFENSIVE ANALYSIS ===\n\n")
        f.write(batch_analysis + "\n\n")
        f.write("="*70 + "\n\n")
        f.write("=== DYNAMIC RISK & MAPPING SUMMARY ===\n\n")
        for ctrl, data in results.items():
            f.write(f"CONTROL: {ctrl}\n")
            f.write("-"*60 + "\n")
            f.write(f"Indicators detected : {data['indicator_count']}\n")
            f.write(f"Dynamic Risk Score  : {data['risk']}/10\n")
            f.write(f"MITRE ATT&CK        : {', '.join(data['mitre'])}\n")
            f.write(f"OWASP Top-10        : {', '.join(data['owasp'])}\n\n")
        f.write("="*70 + "\n")
    return out

# ==================================================
# STREAMLIT UI
# ==================================================
st.set_page_config(page_title="SCWLA v3", layout="wide")
st.title("🛡️ SCWLA v3: AI Security Control Weakness Analyzer")

temperature = st.slider("LLaMA Temperature (Creativity)", 0.0, 1.0, 0.3, 0.05)

uploaded_file = st.file_uploader("Upload Recon TXT File", type=["txt"])
if uploaded_file:
    recon_text = uploaded_file.read().decode(errors="ignore")
    detected_controls = detect_controls(recon_text)

    if not detected_controls:
        st.warning("No security controls detected.")
        st.stop()

    st.subheader("🔍 Detected Security Controls & Dynamic Risk")
    results = {}
    detected_controls_list = list(detected_controls.keys())

    # Compute dynamic risk and mapping
    for ctrl, count in detected_controls.items():
        risk_score = compute_dynamic_risk(count)
        mitre_dyn, owasp_dyn = dynamic_mapping(ctrl, risk_score)
        results[ctrl] = {
            "indicator_count": count,
            "risk": risk_score,
            "mitre": mitre_dyn,
            "owasp": owasp_dyn
        }

    # Generate LLaMA analysis in chunks to prevent truncation
    full_analysis = ""
    for chunk in chunk_controls(detected_controls_list, 5):
        with st.spinner(f"Analyzing controls: {', '.join(chunk)}"):
            full_analysis += llama_analysis_batch(chunk, temperature) + "\n\n"

    # Display consolidated analysis
    st.subheader("📝 Consolidated Defensive Analysis")
    st.text_area("All Controls Analysis", full_analysis, height=600)

    # Display summary metrics
    st.subheader("📊 Dynamic Risk & Mapping Summary")
    for ctrl, data in results.items():
        col1, col2 = st.columns([1,3])
        with col1:
            st.metric("Dynamic Risk Score", data["risk"])
            st.progress(data["risk"]/10)
        with col2:
            st.markdown(f"**MITRE ATT&CK:** {', '.join(data['mitre'])}")
            st.markdown(f"**OWASP Top-10:** {', '.join(data['owasp'])}")

    # Generate downloadable TXT report
    report_file = generate_txt_report(uploaded_file.name, results, full_analysis)
    with open(report_file, "rb") as f:
        st.download_button("📄 Download Structured TXT Report", f, file_name=report_file)
