"""
Passive, non-intrusive security checks for the Light Up Tech "Security Health Check" tool.

IMPORTANT SCOPE NOTE:
Every check here only does what a normal web browser or DNS resolver already does when
visiting a public website: it connects to the site's public port 443/80 like a browser
would, and it reads public DNS records. Nothing here attempts to log in, exploit, brute
force, or access anything not already exposed to the public internet. That is what makes
it safe to run against a domain a visitor merely *claims* to be authorized for, and it is
the reason this MVP does not attempt active vulnerability scanning (port sweeps, exploit
attempts, credential testing, etc.) -- that category of tool needs verified domain
ownership, legal terms, and dedicated scanning infrastructure, which is a separate,
bigger project.
"""

import socket
import ssl
import datetime
from urllib.parse import urlparse

import requests

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

REQUEST_TIMEOUT = 8


def normalize_domain(raw: str) -> str:
    """Turn 'https://Example.com/path' or 'example.com' into 'example.com'."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = parsed.netloc or parsed.path
    host = host.split("/")[0].split(":")[0].lower()
    return host


def check_ssl(domain: str) -> dict:
    """Check certificate validity, expiry, and negotiated TLS version."""
    result = {"name": "SSL/TLS Certificate", "status": "unknown", "details": [], "severity": "info"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days
        issuer = dict(x[0] for x in cert.get("issuer", []))

        result["details"].append(f"TLS protocol negotiated: {tls_version}")
        result["details"].append(f"Certificate issuer: {issuer.get('organizationName', issuer.get('commonName', 'unknown'))}")
        result["details"].append(f"Certificate expires in {days_left} day(s) ({cert['notAfter']})")

        if days_left < 0:
            result["status"] = "fail"
            result["severity"] = "high"
            result["details"].append("Certificate has EXPIRED.")
        elif days_left < 21:
            result["status"] = "warn"
            result["severity"] = "medium"
        else:
            result["status"] = "pass"
            result["severity"] = "low"

        if tls_version in ("TLSv1", "TLSv1.1"):
            result["status"] = "fail"
            result["severity"] = "high"
            result["details"].append(f"{tls_version} is outdated and considered insecure.")

    except ssl.SSLCertVerificationError as e:
        result["status"] = "fail"
        result["severity"] = "high"
        result["details"].append(f"Certificate verification failed: {e.verify_message if hasattr(e, 'verify_message') else e}")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["status"] = "error"
        result["severity"] = "info"
        result["details"].append(f"Could not connect on port 443: {e}")
    except Exception as e:  # noqa: BLE001
        result["status"] = "error"
        result["details"].append(f"Unexpected error checking SSL: {e}")

    return result


def check_security_headers(domain: str) -> dict:
    """Check for the presence of common HTTP security headers, and HTTP->HTTPS redirect."""
    result = {"name": "HTTP Security Headers", "status": "unknown", "details": [], "severity": "info"}
    important_headers = {
        "Strict-Transport-Security": "Forces browsers to use HTTPS for future visits.",
        "Content-Security-Policy": "Restricts what scripts/resources a page may load, mitigating XSS.",
        "X-Content-Type-Options": "Stops browsers from guessing (\"sniffing\") a file's type.",
        "X-Frame-Options": "Prevents the site from being embedded in a hidden iframe (clickjacking).",
        "Referrer-Policy": "Controls how much URL information leaks to other sites via the Referer header.",
        "Permissions-Policy": "Restricts which browser features (camera, mic, geolocation...) a page may use.",
    }

    try:
        resp = requests.get(f"https://{domain}", timeout=REQUEST_TIMEOUT, allow_redirects=True)
        headers = resp.headers

        missing = []
        present = []
        for header, why in important_headers.items():
            if header in headers:
                present.append(header)
            else:
                missing.append((header, why))

        result["details"].append(f"Headers present: {', '.join(present) if present else 'none'}")
        for header, why in missing:
            result["details"].append(f"Missing {header} -- {why}")

        try:
            http_resp = requests.get(f"http://{domain}", timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if http_resp.status_code in (301, 302, 307, 308) and http_resp.headers.get("Location", "").startswith("https://"):
                result["details"].append("HTTP correctly redirects to HTTPS.")
            else:
                result["details"].append("Plain HTTP does not redirect to HTTPS -- visitors can load an unencrypted version of the site.")
                missing.append(("HTTPS redirect", "Ensures no visitor ever loads the site unencrypted."))
        except requests.RequestException:
            result["details"].append("Could not test plain-HTTP behavior (site may only serve HTTPS, which is fine).")

        if len(missing) >= 4:
            result["status"] = "fail"
            result["severity"] = "high"
        elif len(missing) >= 1:
            result["status"] = "warn"
            result["severity"] = "medium"
        else:
            result["status"] = "pass"
            result["severity"] = "low"

    except requests.RequestException as e:
        result["status"] = "error"
        result["details"].append(f"Could not fetch site over HTTPS: {e}")

    return result


def check_email_authentication(domain: str) -> dict:
    """Check for SPF and DMARC DNS TXT records (email spoofing protection)."""
    result = {"name": "Email Authentication (SPF / DMARC)", "status": "unknown", "details": [], "severity": "info"}

    if not DNS_AVAILABLE:
        result["status"] = "error"
        result["details"].append("dnspython is not installed on the server; cannot check DNS records.")
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = REQUEST_TIMEOUT
    resolver.lifetime = REQUEST_TIMEOUT

    spf_found = False
    dmarc_found = False

    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=spf1"):
                spf_found = True
                result["details"].append(f"SPF record found: {txt}")
    except Exception:
        pass

    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=DMARC1"):
                dmarc_found = True
                result["details"].append(f"DMARC record found: {txt}")
    except Exception:
        pass

    if not spf_found:
        result["details"].append("No SPF record found -- attackers can more easily spoof emails 'from' this domain.")
    if not dmarc_found:
        result["details"].append("No DMARC record found -- spoofed emails that fail SPF/DKIM are not reported or rejected.")
    result["details"].append("Note: DKIM is selector-specific and not checked by this tool; verify it with your email provider's setup docs.")

    if spf_found and dmarc_found:
        result["status"] = "pass"
        result["severity"] = "low"
    elif spf_found or dmarc_found:
        result["status"] = "warn"
        result["severity"] = "medium"
    else:
        result["status"] = "fail"
        result["severity"] = "high"

    return result


def run_all_checks(domain: str) -> list:
    domain = normalize_domain(domain)
    return [
        check_ssl(domain),
        check_security_headers(domain),
        check_email_authentication(domain),
    ]
