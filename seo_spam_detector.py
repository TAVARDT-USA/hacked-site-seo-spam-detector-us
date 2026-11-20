#!/usr/bin/env python3
import sys
import re
import json
import ssl
import argparse
import urllib.request
import urllib.error

LEGITIMATE_IFRAME_SUBSTRINGS = [
    "cloudflare", "challenges.cloudflare.com", "googletagmanager.com",
    "google.com/recaptcha", "hcaptcha.com"
]

SPAM_KEYWORDS = [
    "viagra", "cialis", "casino", "payday loan", "replica watch",
    "poker", "roulette", "baccarat", "vape", "ketamine"
]

def scan_site_integrity(target_url, timeout=8):
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url
    target_url = target_url.rstrip("/")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    results = {
        "target": target_url,
        "score": 100,
        "status": "PASS",
        "findings": [],
        "checks": {},
        "recommendations": []
    }

    user_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    bot_headers = {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}

    try:
        user_req = urllib.request.Request(target_url, headers=user_headers)
        with urllib.request.urlopen(user_req, context=ctx, timeout=timeout) as r:
            user_body = r.read().decode("utf-8", errors="ignore")
            user_len = len(user_body)

        bot_req = urllib.request.Request(target_url, headers=bot_headers)
        with urllib.request.urlopen(bot_req, context=ctx, timeout=timeout) as r:
            bot_body = r.read().decode("utf-8", errors="ignore")
            bot_len = len(bot_body)

        # 1. Differential Cloaking Analysis
        ratio = abs(user_len - bot_len) / max(1, max(user_len, bot_len))
        if ratio > 0.40 and abs(user_len - bot_len) > 1000:
            results["findings"].append({
                "type": "cloaking_detected",
                "detail": f"Divergence of {user_len} bytes (User) vs {bot_len} bytes (Googlebot)",
                "penalty": 30
            })
            results["score"] -= 30
            results["checks"]["cloaking"] = {"status": "suspicious", "divergence_ratio": round(ratio, 2)}
            results["recommendations"].append("Inspect web server rules serving altered markup specifically to search indexers.")
        else:
            results["checks"]["cloaking"] = {"status": "consistent", "divergence_ratio": round(ratio, 2)}

        # 2. Hidden non-whitelisted iframes
        raw_iframes = re.findall(r'<iframe[^>]+(?:width=["']0["']|height=["']0["']|style=["'][^"']*display:\s*none)[^>]*>', user_body, re.I)
        suspicious_iframes = []
        for ifr in raw_iframes:
            is_legit = any(legit in ifr.lower() for legit in LEGITIMATE_IFRAME_SUBSTRINGS)
            if not is_legit:
                suspicious_iframes.append(ifr)

        if suspicious_iframes:
            results["findings"].append({
                "type": "suspicious_hidden_iframe",
                "detail": f"Detected {len(suspicious_iframes)} hidden iframe element(s)",
                "penalty": 20
            })
            results["score"] -= 20
            results["checks"]["hidden_iframes"] = {"status": "detected", "count": len(suspicious_iframes)}
            results["recommendations"].append("Remove concealed unauthorized iframes from templates.")
        else:
            results["checks"]["hidden_iframes"] = {"status": "clean"}

        # 3. Spam keyword injection in hidden CSS containers
        hidden_divs = re.findall(r'style=["'][^"']*(?:display:\s*none|visibility:\s*hidden|opacity:\s*0|left:\s*-\d{3,}px)[^"']*["'][^>]*>(.*?)</div>', user_body, re.I | re.DOTALL)
        spam_div_matches = []
        for hdiv in hidden_divs:
            for kw in SPAM_KEYWORDS:
                if kw in hdiv.lower():
                    spam_div_matches.append(kw)

        if spam_div_matches:
            found_kw = list(set(spam_div_matches))
            results["findings"].append({
                "type": "spam_keywords_in_hidden_block",
                "detail": f"Spam keywords ({', '.join(found_kw)}) discovered inside hidden containers",
                "penalty": 35
            })
            results["score"] -= 35
            results["checks"]["spam_keywords"] = {"status": "compromised", "keywords": found_kw}
            results["recommendations"].append("Eradicate malicious injected keyword blocks and audit file integrity.")
        else:
            results["checks"]["spam_keywords"] = {"status": "clean"}

        # 4. Obfuscated script execution patterns
        obf = re.findall(r'(?:eval\s*\(|unescape\s*\(|base64_decode)', user_body, re.I)
        if len(obf) > 2:
            results["findings"].append({
                "type": "obfuscated_code_patterns",
                "detail": f"Detected {len(obf)} occurrences of eval/unescape code patterns",
                "penalty": 15
            })
            results["score"] -= 15
            results["checks"]["obfuscated_code"] = {"status": "warning", "count": len(obf)}
            results["recommendations"].append("Inspect source code for obfuscated JavaScript or PHP evaluation payloads.")
        else:
            results["checks"]["obfuscated_code"] = {"status": "clean"}

    except Exception as e:
        results["findings"].append({
            "type": "connection_error",
            "detail": str(e),
            "penalty": 20
        })
        results["score"] -= 20

    results["score"] = max(0, min(100, results["score"]))
    if results["score"] >= 85:
        results["status"] = "CLEAN"
    elif results["score"] >= 60:
        results["status"] = "SUSPICIOUS"
    else:
        results["status"] = "COMPROMISED"

    return results

def main():
    parser = argparse.ArgumentParser(description="TAVARDT USA - Hacked Site and SEO Spam Detector")
    parser.add_argument("target", help="Target domain or URL to inspect")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")

    args = parser.parse_args()
    report = scan_site_integrity(args.target, timeout=args.timeout)

    if args.json:
        print(json.dumps(report, indent=2))
        return

    print("=" * 60)
    print(" " + "TAVARDT USA - Hacked Site and SEO Spam Detector")
    print("=" * 60)
    print(f"Target: {report['target']}")
    print(f"Site Cleanliness and Integrity Score: {report['score']}/100")
    print(f"Security Status: {report['status']}")
    print("-" * 60)

    print(f"\n[Compromise Indicators Detected]:")
    if not report["findings"]:
        print(f"  - No SEO spam, cloaking, or compromise indicators detected.")
    else:
        for f in report["findings"]:
            print(f"  * [Penalty -{f['penalty']} pts] {f['type']}: {f['detail']}")

    print(f"\n[Integrity Inspection Breakdown]:")
    for chk, details in report["checks"].items():
        st = details.get("status", "unknown")
        print(f"  * {chk}: {st}")

    if report["recommendations"]:
        print(f"\n[Remediation and Hardening Advice]:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")

    print("-" * 60)
    print(f"Full audit and malware cleanup: https://tools.tavardt.com/seo-spam-detector/")
    print("=" * 60)

if __name__ == "__main__":
    main()
