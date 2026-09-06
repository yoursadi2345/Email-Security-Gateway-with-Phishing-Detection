"""
detector.py
------------
Core detection engine for the Email Security Gateway.

Yeh module ek raw email (.eml text ya paste kiya hua email) ko parse karta hai
aur multiple heuristic checks chalakar ek "phishing risk score" nikalta hai.

Checks included:
  1. Sender domain mismatch     -> From / Reply-To / Return-Path alag domains
  2. Suspicious URLs            -> IP-based links, URL shorteners, @ trick, raw IP
  3. Lookalike / typosquat domain -> known brand se milta-julta fake domain
  4. Link text vs actual href mismatch -> "paypal.com" likha but href kuch aur
  5. Urgency / pressure language -> "verify now", "account suspended" jaise phrases
  6. Generic greeting           -> "Dear Customer" jaise generic greetings
  7. Suspicious attachments     -> .exe, .scr, .js, double extensions etc.
  8. Sensitive info request     -> password/OTP/card number maangna
  9. Header authentication sim  -> SPF/DKIM/DMARC result agar headers me mile
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse
import difflib

# ----------------------------------------------------------------------
# Reference data used by the heuristics
# ----------------------------------------------------------------------

KNOWN_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "netflix.com", "bankofamerica.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "axisbank.com", "irctc.co.in",
    "linkedin.com", "whatsapp.com", "outlook.com",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly",
]

URGENCY_PHRASES = [
    "verify your account", "account suspended", "act now", "urgent action required",
    "your account will be closed", "click here immediately", "confirm your identity",
    "unusual activity detected", "limited time", "final notice", "immediate action",
    "account has been locked", "security alert", "update your payment",
    "will be terminated", "expire within", "last warning",
]

SENSITIVE_INFO_PHRASES = [
    "enter your password", "your otp", "card number", "cvv", "social security",
    "aadhaar number", "pan card", "net banking password", "atm pin", "login credentials",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear account holder", "dear valued customer",
    "dear sir/madam", "dear member",
]

SUSPICIOUS_ATTACHMENT_EXT = [
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".msi", ".ps1",
]

IP_URL_PATTERN = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
HREF_PATTERN = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
ANCHOR_TEXT_PATTERN = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')


def get_domain(url_or_email: str) -> str:
    """Extract a clean domain from a URL or an email address."""
    if "@" in url_or_email and "://" not in url_or_email:
        return url_or_email.split("@")[-1].strip().lower().strip(">").strip()
    parsed = urlparse(url_or_email)
    netloc = parsed.netloc or parsed.path
    return netloc.lower().split("@")[-1].split(":")[0]


# Common look-alike character substitutions used in typosquatting
HOMOGLYPH_MAP = str.maketrans({
    "1": "l", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t",
    "$": "s", "@": "a",
})


def is_lookalike_domain(domain: str, threshold: float = 0.82):
    """
    Check karta hai ki given domain kisi known brand se 'suspiciously similar'
    hai ya nahi (typosquatting jaise paypa1.com, micros0ft-support.com).
    Exact match ko lookalike nahi mana jayega.
    """
    domain = domain.lower()
    normalized = domain[4:] if domain.startswith("www.") else domain
    deobfuscated = normalized.translate(HOMOGLYPH_MAP)

    for brand in KNOWN_BRANDS:
        if normalized == brand:
            continue
        ratio = difflib.SequenceMatcher(None, normalized, brand).ratio()
        deob_ratio = difflib.SequenceMatcher(None, deobfuscated, brand).ratio()
        best_ratio = max(ratio, deob_ratio)
        if best_ratio >= threshold:
            return True, brand, round(best_ratio, 2)
        # brand name embedded with extra hyphens/words (e.g. paypal-secure-login.com)
        brand_root = brand.split(".")[0]
        if (brand_root in normalized or brand_root in deobfuscated) and normalized != brand:
            return True, brand, round(best_ratio, 2)
    return False, None, 0.0


class EmailAnalysisResult:
    def __init__(self):
        self.score = 0
        self.max_score = 0
        self.findings = []  # list of dicts: {check, severity, detail, points}
        self.headers = {}
        self.urls_found = []
        self.attachments = []

    def add(self, check, severity, detail, points):
        self.findings.append({
            "check": check,
            "severity": severity,
            "detail": detail,
            "points": points,
        })
        self.score += points

    @property
    def verdict(self):
        pct = (self.score / self.max_score * 100) if self.max_score else 0
        if pct >= 55:
            return "PHISHING", pct
        elif pct >= 25:
            return "SUSPICIOUS", pct
        else:
            return "SAFE", pct

    def to_dict(self):
        verdict, pct = self.verdict
        return {
            "verdict": verdict,
            "risk_percent": round(pct, 1),
            "score": self.score,
            "max_score": self.max_score,
            "findings": self.findings,
            "headers": self.headers,
            "urls_found": self.urls_found,
            "attachments": self.attachments,
        }


def analyze_email(raw_text: str) -> dict:
    """
    Main entry point. raw_text ek poora .eml file ka content ho sakta hai
    (headers + body), ya sirf plain pasted email text.
    """
    result = EmailAnalysisResult()

    # Try to parse as a proper RFC822 email first (with headers).
    try:
        msg = Parser(policy=policy.default).parsestr(raw_text)
        has_real_headers = bool(msg.get("From") or msg.get("Subject"))
    except Exception:
        msg = None
        has_real_headers = False

    from_addr = ""
    reply_to = ""
    return_path = ""
    subject = ""
    body = raw_text

    if has_real_headers:
        from_addr = msg.get("From", "") or ""
        reply_to = msg.get("Reply-To", "") or ""
        return_path = msg.get("Return-Path", "") or ""
        subject = msg.get("Subject", "") or ""
        result.headers = {
            "From": from_addr, "Reply-To": reply_to,
            "Return-Path": return_path, "Subject": subject,
            "Received-SPF": msg.get("Received-SPF", ""),
            "Authentication-Results": msg.get("Authentication-Results", ""),
        }
        # get body (prefer plain text, fallback to html)
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        body += part.get_content()
                    except Exception:
                        pass
        else:
            try:
                body = msg.get_content()
            except Exception:
                body = raw_text

        # attachments
        for part in msg.iter_attachments():
            fname = part.get_filename() or "unnamed"
            result.attachments.append(fname)

    text_lower = (subject + "\n" + body).lower()

    # ---------------- CHECK 1: Sender domain mismatch ----------------
    result.max_score += 15
    domains = set()
    for addr in (from_addr, reply_to, return_path):
        if addr:
            d = get_domain(addr)
            if d:
                domains.add(d)
    if len(domains) >= 2:
        result.add(
            "Sender domain mismatch", "high",
            f"From/Reply-To/Return-Path point to different domains: {', '.join(domains)}",
            15,
        )
    elif from_addr:
        result.add("Sender domain mismatch", "info", "Sender domains are consistent", 0)

    result.max_score += 10
    if from_addr:
        sender_domain = get_domain(from_addr)
        lookalike, brand, ratio = is_lookalike_domain(sender_domain)
        if lookalike:
            result.add(
                "Lookalike sender domain", "high",
                f"Sender domain '{sender_domain}' closely resembles '{brand}' (similarity {ratio})",
                10,
            )

    # ---------------- CHECK 2 & 3: URLs -> shorteners, IP links, lookalike ----------------
    result.max_score += 25
    urls = set(URL_PATTERN.findall(body))
    for url in urls:
        result.urls_found.append(url)
        domain = get_domain(url)

        if IP_URL_PATTERN.match(url):
            result.add("Raw IP address link", "high", f"URL uses a raw IP instead of a domain: {url}", 10)

        if any(domain.endswith(s) for s in URL_SHORTENERS):
            result.add("URL shortener", "medium", f"Shortened URL hides real destination: {url}", 6)

        if "@" in url.split("//")[-1]:
            result.add("'@' trick in URL", "high", f"URL contains '@' which can hide the real domain: {url}", 8)

        lookalike, brand, ratio = is_lookalike_domain(domain)
        if lookalike:
            result.add(
                "Lookalike / typosquat domain", "high",
                f"Domain '{domain}' closely resembles '{brand}' (similarity {ratio})",
                10,
            )

    # ---------------- CHECK 4: anchor text vs actual href mismatch ----------------
    result.max_score += 10
    for href, text in ANCHOR_TEXT_PATTERN.findall(body):
        visible_text = re.sub("<[^>]+>", "", text).strip()
        if visible_text.startswith("http") or "." in visible_text:
            shown_domain = get_domain(visible_text)
            real_domain = get_domain(href)
            if shown_domain and real_domain and shown_domain != real_domain:
                result.add(
                    "Link text / destination mismatch", "high",
                    f"Displayed link '{visible_text}' actually points to '{real_domain}'",
                    10,
                )
                break  # one strong finding is enough to flag this check

    # ---------------- CHECK 5: urgency / pressure language ----------------
    result.max_score += 15
    hits = [p for p in URGENCY_PHRASES if p in text_lower]
    if hits:
        result.add(
            "Urgency / pressure language", "medium",
            f"Phrases found: {', '.join(hits[:4])}" + (" ..." if len(hits) > 4 else ""),
            min(15, 5 * len(hits)),
        )

    # ---------------- CHECK 6: generic greeting ----------------
    result.max_score += 5
    if any(g in text_lower for g in GENERIC_GREETINGS):
        result.add("Generic greeting", "low", "Email uses a generic greeting instead of your name", 5)

    # ---------------- CHECK 7: suspicious attachments ----------------
    result.max_score += 15
    for fname in result.attachments:
        fname_lower = fname.lower()
        if any(fname_lower.endswith(ext) for ext in SUSPICIOUS_ATTACHMENT_EXT):
            result.add("Dangerous attachment type", "high", f"Attachment '{fname}' has an executable/script extension", 15)
        elif fname_lower.count(".") >= 2:
            result.add("Double extension attachment", "medium", f"Attachment '{fname}' has a suspicious double extension", 8)

    # ---------------- CHECK 8: sensitive info request ----------------
    result.max_score += 15
    hits2 = [p for p in SENSITIVE_INFO_PHRASES if p in text_lower]
    if hits2:
        result.add(
            "Requests sensitive information", "high",
            f"Email asks for: {', '.join(hits2)}",
            15,
        )

    # ---------------- CHECK 9: SPF/DKIM/DMARC simulation from headers ----------------
    result.max_score += 10
    auth_results = (result.headers.get("Authentication-Results") or "").lower()
    spf_header = (result.headers.get("Received-SPF") or "").lower()
    if "fail" in auth_results or "fail" in spf_header:
        result.add("Authentication failure", "high", "SPF/DKIM/DMARC check failed as per email headers", 10)
    elif auth_results or spf_header:
        result.add("Authentication check", "info", "SPF/DKIM/DMARC passed as per email headers", 0)
    else:
        result.add("No authentication headers", "low", "Email has no SPF/DKIM/DMARC headers to verify (common in pasted text)", 3)

    if result.max_score == 0:
        result.max_score = 1  # avoid divide by zero

    return result.to_dict()
