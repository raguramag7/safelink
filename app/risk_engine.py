# app/risk_engine.py
import re
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".ml", ".cf", ".ga", ".bid", ".pw"}
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "bank", "secure", "update", "signin", "password",
    "confirm", "ssn", "social", "credential", "change-password", "otp", "one-time"
]

def is_ip_host(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

def tld_is_suspicious(hostname: Optional[str]) -> bool:
    if not hostname or "." not in hostname:
        return False
    lower = hostname.lower()
    for tld in SUSPICIOUS_TLDS:
        if lower.endswith(tld):
            return True
    return False

def external_script_ratio(scripts: List[str], domain: str) -> float:
    if not scripts:
        return 0.0
    external = 0
    for s in scripts:
        if s and not s.startswith("/") and domain not in (s or ""):
            external += 1
    return external / len(scripts)

def external_links_ratio(links: List[str], domain: str) -> float:
    if not links:
        return 0.0
    external = 0
    for l in links:
        try:
            parsed = urlparse(l)
            host = parsed.hostname or ""
            if host and domain not in host:
                external += 1
        except Exception:
            continue
    return external / len(links)

def count_forms(forms: List[Dict[str, Any]]) -> int:
    return len(forms or [])

def count_iframes(iframes: List[str]) -> int:
    return len(iframes or [])

def suspicious_keyword_matches(text: str) -> int:
    if not text:
        return 0
    low = text.lower()
    count = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in low:
            count += 1
    return count

def combine_vt_gsb_score(vt: Optional[Dict[str, Any]], gsb: Optional[Dict[str, Any]]) -> float:
    """
    Normalize external API signals into a 0..100 penalty score.
    vt: expects {'malicious_count': int, 'suspicious_count': int, ...} or None
    gsb: expects {} with 'matches' key if threat found (structure may vary)
    """
    score = 0.0
    if vt:
        malicious = vt.get("malicious_count", 0) or vt.get("malicious", 0) or 0
        suspicious = vt.get("suspicious_count", 0) or vt.get("suspicious", 0) or 0
        score += min(50, malicious * 20)   # each engine flagged is heavy
        score += min(20, suspicious * 5)
    if gsb:
        # Google Safe Browsing returns matches object when threat found
        if isinstance(gsb, dict) and gsb.get("matches"):
            score += 60
        elif isinstance(gsb, dict) and gsb.get("threats"):
            score += 60
    return min(100.0, score)

def compute_heuristic_score(fetch: Dict[str, Any], extracted: Dict[str, Any], normalized_url: str,
                            vt: Optional[Dict[str, Any]] = None, gsb: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Returns a dict:
      {
        'score': 0-100 (higher => more risky),
        'components': {...weights...},
        'verdict': 'SAFE'|'SUSPICIOUS'|'DANGEROUS',
        'explanations': [str, ...]
      }
    """
    explanations = []
    score = 0.0
    # Base domain and host
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    domain = hostname

    # 1) External API signals (very important)
    api_penalty = combine_vt_gsb_score(vt, gsb)
    if api_penalty > 0:
        explanations.append(f"External threat services flagged: penalty {api_penalty:.0f}")
    score += api_penalty  # up to 100

    # 2) Redirects
    head_dict = fetch.get("head") or {}
    get_dict = fetch.get("get") or {}
    redirect_count = max(
        len(head_dict.get("redirects", []) or []),
        len(get_dict.get("redirects", []) or [])
    )
    if redirect_count >= 3:
        score += 12
        explanations.append(f"Redirect chain length {redirect_count} (suspicious)")
    elif redirect_count == 2:
        score += 6

    # 3) Host checks
    if is_ip_host(hostname):
        score += 15
        explanations.append("URL uses numeric IP address (suspicious)")
    if tld_is_suspicious(hostname):
        score += 8
        explanations.append(f"Suspicious TLD ({hostname.split('.')[-1]})")

    # 4) Forms / credential harvesting risk
    forms_count = count_forms(extracted.get("forms", []))
    if forms_count > 0:
        score += min(20, forms_count * 6)
        explanations.append(f"Found {forms_count} form(s) (could request credentials)")

    # 5) External scripts & iframes
    scripts = extracted.get("scripts", [])
    iframes = extracted.get("iframes", [])
    ext_script_ratio = external_script_ratio(scripts, domain)
    if ext_script_ratio > 0.6:
        score += 10
        explanations.append(f"High external script ratio: {ext_script_ratio:.2f}")
    iframe_count = count_iframes(iframes)
    if iframe_count > 0:
        score += min(12, iframe_count * 6)
        explanations.append(f"Found {iframe_count} iframe(s)")

    # 6) External links ratio
    links = extracted.get("links", [])
    ext_link_ratio = external_links_ratio(links, domain)
    if ext_link_ratio > 0.6:
        score += 8
        explanations.append(f"High external links ratio: {ext_link_ratio:.2f}")

    # 7) Suspicious keywords in page text
    text = extracted.get("clean_text", "") or ""
    kw_matches = suspicious_keyword_matches(text)
    if kw_matches > 0:
        score += min(15, kw_matches * 3)
        explanations.append(f"Suspicious keywords found: {kw_matches}")

    # 8) HTTP vs HTTPS
    if parsed.scheme == "http":
        score += 4
        explanations.append("Using HTTP (not HTTPS)")

    # 9) File size weirdness (very small pages pretending to be login)
    filesize = (fetch.get("get") or {}).get("filesize") or 0
    if filesize < 200 and forms_count > 0:
        score += 8
        explanations.append("Very small page with forms (phishing-like)")

    # Cap the score 0..100
    raw_score = min(100.0, score)

    # Convert to verdict
    if raw_score >= 65:
        verdict = "DANGEROUS"
    elif raw_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "score": round(raw_score, 1),
        "verdict": verdict,
        "components": {
            "api_penalty": round(api_penalty, 1),
            "redirect_count": redirect_count,
            "forms_count": forms_count,
            "ext_script_ratio": round(ext_script_ratio, 2),
            "iframe_count": iframe_count,
            "ext_link_ratio": round(ext_link_ratio, 2),
            "kw_matches": kw_matches,
            "filesize": filesize,
            "scheme": parsed.scheme
        },
        "explanations": explanations
    }
