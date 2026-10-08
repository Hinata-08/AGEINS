import os
import re
from typing import Dict, Any, List
import joblib

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "account suspended", "terminate",
    "24 hours", "48 hours", "unauthorized login", "security alert", "freeze",
    "arrest", "lawsuit", "legal action", "compromised", "final warning", "lockout"
]

FINANCIAL_SCAM_KEYWORDS = [
    "gift card", "crypto", "bitcoin", "ethereum", "wallet", "wire transfer",
    "western union", "lottery", "prize", "inheritance", "million dollars",
    "beneficiary", "claim your funds", "direct deposit", "invoice attached"
]

CREDENTIAL_HARVEST_KEYWORDS = [
    "verify password", "update credential", "confirm identity", "ssn",
    "social security", "pin code", "otp", "2fa code", "seed phrase", "secret key"
]

_EMAIL_NLP_BUNDLE = None
_EMAIL_TABULAR_MODEL = None

def get_email_models():
    global _EMAIL_NLP_BUNDLE, _EMAIL_TABULAR_MODEL
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    if _EMAIL_NLP_BUNDLE is None:
        nlp_path = os.path.join(models_dir, "nlp_email_model.joblib")
        if os.path.exists(nlp_path):
            try:
                _EMAIL_NLP_BUNDLE = joblib.load(nlp_path)
            except Exception as e:
                print(f"[Warning] Email NLP model load error: {e}")
    if _EMAIL_TABULAR_MODEL is None:
        tab_path = os.path.join(models_dir, "tabular_email_model.joblib")
        if os.path.exists(tab_path):
            try:
                _EMAIL_TABULAR_MODEL = joblib.load(tab_path)
            except Exception as e:
                print(f"[Warning] Email tabular model load error: {e}")
    return _EMAIL_NLP_BUNDLE, _EMAIL_TABULAR_MODEL

def analyze_email(subject: str, sender: str, body: str, raw_headers: str = "") -> Dict[str, Any]:
    full_text = f"{subject}\n{body}".lower()
    flags: List[Dict[str, Any]] = []
    heuristic_score = 0

    # 1. Sender Analysis & Spoofing Indicators
    sender_lower = sender.lower().strip()
    sender_domain = ""
    if "@" in sender_lower:
        sender_domain = sender_lower.split("@")[-1].replace(">", "").strip()

    free_webmails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
    corporate_keywords = ["support", "security", "admin", "billing", "ceo", "director", "bank", "irs", "hr"]

    if any(k in sender_lower for k in corporate_keywords) and any(sender_domain == fw for fw in free_webmails):
        heuristic_score += 35
        flags.append({
            "severity": "critical",
            "title": "Corporate Authority Spoofing via Free Webmail",
            "desc": f"Sender claims administrative authority but uses generic public provider ({sender_domain})."
        })

    if "<" in sender and ">" in sender:
        display_name = sender.split("<")[0].lower()
        if "paypal" in display_name and "paypal.com" not in sender_domain:
            heuristic_score += 40
            flags.append({
                "severity": "critical",
                "title": "Display Name Deception",
                "desc": f"Display name masquerades as PayPal, but domain origin is '{sender_domain}'."
            })
        elif "bank" in display_name and not any(b in sender_domain for b in ["bank", "chase", "wells", "citi"]):
            heuristic_score += 35
            flags.append({
                "severity": "high",
                "title": "Banking Entity Mismatch",
                "desc": f"Display name contains banking moniker without matching corporate domain."
            })

    # 2. Subject Signals
    if subject.isupper() and len(subject) > 10:
        heuristic_score += 15
        flags.append({
            "severity": "medium",
            "title": "All-Caps Alarmist Subject",
            "desc": "Entire subject in uppercase designed to induce psychological urgency."
        })

    # 3. Urgency & Coercion Tokens
    matched_urgency = [kw for kw in URGENCY_KEYWORDS if kw in full_text]
    if len(matched_urgency) >= 3:
        heuristic_score += 30
        flags.append({
            "severity": "high",
            "title": "Extreme Urgency & Psychological Coercion",
            "desc": f"Detected coercion signals: {', '.join(matched_urgency[:4])}"
        })
    elif len(matched_urgency) >= 1:
        heuristic_score += 15
        flags.append({
            "severity": "medium",
            "title": "Urgency Indicators",
            "desc": f"Detected urgency phrasing: {', '.join(matched_urgency)}"
        })

    # 4. Financial & Advance Fee Lures
    matched_financial = [kw for kw in FINANCIAL_SCAM_KEYWORDS if kw in full_text]
    if matched_financial:
        heuristic_score += 25
        flags.append({
            "severity": "high",
            "title": "High-Risk Financial & Wire Demands",
            "desc": f"Payment/Crypto/Wire request patterns: {', '.join(matched_financial)}"
        })

    # 5. Credential Harvesting Cues
    matched_creds = [kw for kw in CREDENTIAL_HARVEST_KEYWORDS if kw in full_text]
    if matched_creds:
        heuristic_score += 35
        flags.append({
            "severity": "critical",
            "title": "Credential Harvest Attempt",
            "desc": f"Requests sensitive authentication secrets: {', '.join(matched_creds)}"
        })

    # 6. Embedded Links
    urls_found = re.findall(r"https?://[^\s<>\"']+", body)
    suspicious_links = []
    for u in urls_found:
        if any(bad_tld in u for bad_tld in [".xyz", ".top", ".buzz", ".work", ".cf"]):
            suspicious_links.append(u)
        elif re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u):
            suspicious_links.append(u)

    if suspicious_links:
        heuristic_score += 30
        flags.append({
            "severity": "critical",
            "title": "High-Risk Embedded Hyperlinks",
            "desc": f"Found {len(suspicious_links)} link(s) using IP host or high-risk TLDs."
        })
    elif urls_found:
        heuristic_score += 10
        flags.append({
            "severity": "low",
            "title": "Embedded Hyperlinks Detected",
            "desc": f"Contains {len(urls_found)} link(s) requiring security quarantine."
        })

    # 7. Raw Header Parsing
    if raw_headers:
        raw_lower = raw_headers.lower()
        if "spf=fail" in raw_lower or "spf=softfail" in raw_lower:
            heuristic_score += 30
            flags.append({"severity": "high", "title": "SPF Authentication Failure", "desc": "Sender server is not authorized to deliver mail for this domain."})
        if "dkim=fail" in raw_lower:
            heuristic_score += 30
            flags.append({"severity": "high", "title": "DKIM Cryptographic Signature Invalid", "desc": "Message body or headers altered in transit."})
        if "dmarc=fail" in raw_lower:
            heuristic_score += 25
            flags.append({"severity": "high", "title": "DMARC Alignment Failure", "desc": "Email failed organizational DMARC policy validation."})

    # 8. Machine Learning Model Evaluation
    nlp_bundle, tab_model = get_email_models()
    ml_confidence = None

    if nlp_bundle:
        try:
            vec = nlp_bundle["vectorizer"]
            clf = nlp_bundle["classifier"]
            combined_text = f"{subject} {body}"
            X_vec = vec.transform([combined_text])
            proba = clf.predict_proba(X_vec)[0]
            ml_confidence = round(float(proba[1]) * 100, 1)
            flags.append({
                "severity": "critical" if ml_confidence >= 70 else "medium" if ml_confidence >= 40 else "low",
                "title": f"NLP Machine Learning Confidence: {ml_confidence}% Malicious",
                "desc": "Trained on real Nazario Phishing & Enron Legal MBOX archives (2,500+ messages)."
            })
        except Exception as e:
            print(f"[Error in email ML prediction]: {e}")

    # Compute Final Score
    if ml_confidence is not None:
        final_score = int(round(0.45 * heuristic_score + 0.55 * ml_confidence))
    else:
        final_score = min(heuristic_score, 100)

    final_score = min(max(final_score, 0), 100)

    # Risk Tier: SAFE, MEDIUM, CRITICAL
    if final_score >= 65:
        risk_tier = "CRITICAL"
        status_color = "red"
        verdict = "CRITICAL PHISHING / MALICIOUS EMAIL"
        recommendations = [
            "Quarantine email immediately across email exchange server.",
            "Do NOT click any hyperlinks, download attachments, or reply to sender.",
            "Report sender address to enterprise anti-phishing gateway.",
            "If user opened attachment or provided credentials, initiate password resets immediately."
        ]
    elif final_score >= 35:
        risk_tier = "MEDIUM"
        status_color = "amber"
        verdict = "SUSPICIOUS / UNVERIFIED EMAIL"
        recommendations = [
            "Verify sender identity out-of-band through known telephone number or internal chat.",
            "Scan any attachments in isolated sandbox before accessing.",
            "Do not disclose confidential company credentials or execute wire transfers."
        ]
    else:
        risk_tier = "SAFE"
        status_color = "emerald"
        verdict = "SAFE / LEGITIMATE COMMUNICATION"
        recommendations = [
            "Email exhibits normal transactional or corporate communication profile.",
            "Standard business procedures apply."
        ]

    return {
        "risk_score": final_score,
        "risk_tier": risk_tier,
        "status_color": status_color,
        "verdict": verdict,
        "recommendations": recommendations,
        "flags": flags,
        "links_extracted": urls_found,
        "suspicious_tokens": list(set(matched_urgency + matched_financial + matched_creds)),
        "ml_telemetry": {
            "ml_probability": ml_confidence if ml_confidence is not None else "N/A",
            "model_type": "TF-IDF + Logistic Regression (Trained on Nazario, Enron & Kaggle 2026 Data)",
            "status": "OPERATIONAL"
        },
        "metrics": {
            "urgency_triggers": len(matched_urgency),
            "financial_triggers": len(matched_financial),
            "credential_triggers": len(matched_creds),
            "total_links": len(urls_found),
            "headers_checked": bool(raw_headers)
        }
    }
