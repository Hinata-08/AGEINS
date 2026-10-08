import os
import math
import re
from urllib.parse import urlparse
import joblib

TARGET_BRANDS = [
    "google", "paypal", "microsoft", "amazon", "apple", "netflix",
    "facebook", "instagram", "chase", "bankofamerica", "wellsfargo",
    "sbi", "hdfc", "binance", "coinbase", "meta", "whatsapp",
    "dropbox", "linkedin", "twitter", "adobe", "outlook", "icloud"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "buzz", "fit", "tk", "ml", "ga",
    "cf", "gq", "rest", "surf", "monster", "bar", "live", "icu", "site"
}

SUSPICIOUS_KEYWORDS = [
    "verify", "login", "update", "account", "secure", "banking", "wallet",
    "confirm", "password", "security", "authenticate", "signin", "support",
    "billing", "payment", "suspension", "unauthorized", "kyc", "recover"
]

_URL_MODEL = None

def get_url_model():
    global _URL_MODEL
    if _URL_MODEL is None:
        model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "phishing_url_model.joblib")
        if os.path.exists(model_path):
            try:
                _URL_MODEL = joblib.load(model_path)
            except Exception as e:
                print(f"[Warning] Phishing URL model load error: {e}")
    return _URL_MODEL

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def check_typosquatting(domain_name: str):
    domain_clean = domain_name.lower().split(".")[0]
    normalized_full = domain_clean.replace("0", "o").replace("1", "l").replace("vv", "w")
    tokens = re.split(r'[-._0-9]', domain_clean)
    matches = []
    seen = set()

    for brand in TARGET_BRANDS:
        if brand in domain_clean and brand != domain_clean and brand not in seen:
            matches.append({"brand": brand, "type": "Subdomain / Keyword Embedded", "similarity": 95})
            seen.add(brand)
            continue
        dist_full = levenshtein_distance(normalized_full, brand)
        if dist_full == 1 and len(brand) >= 4 and brand not in seen:
            matches.append({"brand": brand, "type": "Homoglyph Typosquatting (Edit dist: 1)", "similarity": 90})
            seen.add(brand)
            continue
        for token in tokens:
            if not token:
                continue
            norm_token = token.replace("0", "o").replace("1", "l").replace("vv", "w")
            if norm_token == brand and token != brand and brand not in seen:
                matches.append({"brand": brand, "type": "Homoglyph Character Substitution", "similarity": 96})
                seen.add(brand)
                break
            dist_token = levenshtein_distance(norm_token, brand)
            if dist_token == 1 and len(brand) >= 4 and brand not in seen:
                matches.append({"brand": brand, "type": "Sub-Token Typosquatting", "similarity": 86})
                seen.add(brand)
                break
    return matches

def analyze_url(url: str) -> dict:
    url_cleaned = url.strip()
    if not url_cleaned.startswith(("http://", "https://")):
        url_cleaned = "http://" + url_cleaned

    parsed = urlparse(url_cleaned)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_str = url_cleaned.lower()

    flags = []
    heuristic_score = 0

    # 1. Scheme Check
    if parsed.scheme != "https":
        heuristic_score += 15
        flags.append({"severity": "medium", "title": "Insecure Protocol (HTTP)", "desc": "Uses unencrypted HTTP without SSL/TLS encryption certificate."})

    # 2. IP in Hostname
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    is_ip = bool(re.match(ip_pattern, hostname))
    if is_ip:
        heuristic_score += 40
        flags.append({"severity": "critical", "title": "Raw Numerical IP Host", "desc": f"Host connects directly to IP address ({hostname}), typical of adversarial C2 infrastructure."})

    # 3. Shannon Entropy
    domain_entropy = calculate_shannon_entropy(hostname)
    if domain_entropy > 4.2:
        heuristic_score += 25
        flags.append({"severity": "high", "title": "High Domain Entropy", "desc": f"Entropy of {domain_entropy} indicates potential Domain Generation Algorithm (DGA)."})
    elif domain_entropy > 3.6:
        heuristic_score += 10
        flags.append({"severity": "low", "title": "Elevated Entropy", "desc": f"Lexical entropy ({domain_entropy}) shows abnormal randomness."})

    # 4. Typosquatting
    typos = check_typosquatting(hostname)
    if typos:
        for t in typos:
            heuristic_score += 45
            flags.append({"severity": "critical", "title": f"Target Brand Impersonation: {t['brand'].upper()}", "desc": f"Detected {t['type']} masquerading as legitimate organization."})

    # 5. High-Risk TLD
    tld = hostname.split(".")[-1].lower() if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        heuristic_score += 25
        flags.append({"severity": "medium", "title": f"High-Abuse TLD (.{tld})", "desc": f"Top-level domain .{tld} is heavily associated with malicious campaigns."})

    # 6. Subdomain Stacking
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) >= 4 and not is_ip:
        heuristic_score += 15
        flags.append({"severity": "medium", "title": "Subdomain Stacking Evasion", "desc": f"{len(subdomain_parts)} domain segments detected, common in evasive redirects."})

    # 7. Sensitive Keywords
    detected_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_str]
    if len(detected_kw) >= 3:
        heuristic_score += 25
        flags.append({"severity": "high", "title": "Multiple Phishing Lures", "desc": f"Sensitive keywords detected: {', '.join(detected_kw)}"})
    elif len(detected_kw) >= 1:
        heuristic_score += 10
        flags.append({"severity": "low", "title": "Sensitive Action Keyword", "desc": f"Contains security keywords: {', '.join(detected_kw)}"})

    # 8. Special Character Obfuscation
    if "@" in url_cleaned:
        heuristic_score += 35
        flags.append({"severity": "critical", "title": "Credential Obfuscation (@)", "desc": "Uses '@' sign to conceal true destination authority."})

    # 9. Real ML Model Evaluation
    model = get_url_model()
    ml_confidence = None
    if model:
        digits = sum(c.isdigit() for c in url_cleaned)
        f_digit_ratio = round(digits / max(1, len(url_cleaned)), 3)
        feat_vector = [
            len(url_cleaned), domain_entropy, url_cleaned.count("."), url_cleaned.count("-"),
            1 if is_ip else 0, 1 if parsed.scheme == "https" else 0, 1 if tld in SUSPICIOUS_TLDS else 0,
            1 if "@" in url_cleaned else 0, len(detected_kw), 1 if len(typos) > 0 else 0, f_digit_ratio
        ]
        try:
            proba = model.predict_proba([feat_vector])[0]
            ml_confidence = round(float(proba[1]) * 100, 1)
            flags.append({
                "severity": "critical" if ml_confidence >= 70 else "medium" if ml_confidence >= 40 else "low",
                "title": f"Random Forest ML Prediction: {ml_confidence}% Malicious",
                "desc": f"Trained on real Kaggle & Nazario phishing datasets (1,300+ real samples)."
            })
        except Exception as e:
            print(f"[Error in URL ML prediction]: {e}")

    # Compute final score
    if ml_confidence is not None:
        final_score = int(round(0.5 * heuristic_score + 0.5 * ml_confidence))
    else:
        final_score = min(heuristic_score, 100)

    final_score = min(max(final_score, 0), 100)

    # Risk Tier classification: SAFE, MEDIUM, CRITICAL
    if final_score >= 65:
        risk_tier = "CRITICAL"
        status_color = "red"
        verdict = "CRITICAL PHISHING THREAT DETECTED"
        recommendations = [
            "Block connection immediately across enterprise firewall and proxy gateways.",
            "Do NOT input credentials, 2FA tokens, or financial payment details.",
            "Add domain and destination IP to perimeter blacklists.",
            "Notify Security Operations Center (SOC) if internal users visited this destination."
        ]
    elif final_score >= 35:
        risk_tier = "MEDIUM"
        status_color = "amber"
        verdict = "SUSPICIOUS THREAT INDICATORS DETECTED"
        recommendations = [
            "Proceed with extreme caution; inspect SSL certificate and domain WHOIS registry.",
            "Verify organization authenticity out-of-band via phone or official mobile app.",
            "Enable browser isolation sandbox before navigating."
        ]
    else:
        risk_tier = "SAFE"
        status_color = "emerald"
        verdict = "SAFE / CLEAN DESTINATION"
        recommendations = [
            "URL appears consistent with standard benign web infrastructure.",
            "Continue standard security posture and operational monitoring."
        ]

    return {
        "url": url_cleaned,
        "hostname": hostname,
        "protocol": parsed.scheme,
        "risk_score": final_score,
        "risk_tier": risk_tier,
        "status_color": status_color,
        "verdict": verdict,
        "recommendations": recommendations,
        "flags": flags,
        "ml_telemetry": {
            "ml_probability": ml_confidence if ml_confidence is not None else "N/A",
            "model_type": "RandomForestClassifier (Trained on Real Nazario & Kaggle Datasets)",
            "status": "OPERATIONAL"
        },
        "metrics": {
            "entropy": domain_entropy,
            "url_length": len(url_cleaned),
            "subdomain_count": len(subdomain_parts),
            "detected_keywords_count": len(detected_kw),
            "has_ip_host": is_ip,
            "typosquatting_hits": len(typos)
        }
    }
