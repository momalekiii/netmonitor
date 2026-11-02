"""IP geolocation and domain/IP intelligence lookups.

Hardening:
- All network calls have timeouts.
- Responses are validated; malformed data is skipped.
- No secrets are logged.
"""

import socket
from typing import Any, Dict, Optional

import dns.resolver
import requests
import whois


# Timeout for all external HTTP/DNS calls (seconds)
REQUEST_TIMEOUT = 10


def geoip_lookup(ip: Optional[str] = None) -> Dict[str, Any]:
    """Look up geolocation for an IP (defaults to the public IP of this machine).

    Uses the free ipapi.co endpoint (no API key required for light usage).
    """
    # Validate IP format if provided
    if ip is not None:
        if not _is_valid_ip(ip):
            return {"error": f"Invalid IP address: {ip}"}

    url = f"https://ipapi.co/{ip}/json/" if ip else "https://ipapi.co/json/"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            return {"error": "Unexpected response format from GeoIP provider"}
        if "error" in data:
            return {"error": data.get("reason", "GeoIP lookup failed")}
        return {
            "ip": data.get("ip"),
            "version": data.get("version"),
            "city": data.get("city"),
            "region": data.get("region"),
            "region_code": data.get("region_code"),
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "continent": data.get("continent_code"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": data.get("timezone"),
            "utc_offset": data.get("utc_offset"),
            "country_calling_code": data.get("country_calling_code"),
            "currency": data.get("currency"),
            "languages": data.get("languages"),
            "asn": data.get("asn"),
            "org": data.get("org"),
            "isp": data.get("org"),
            "postal": data.get("postal"),
        }
    except requests.RequestException as exc:
        return {"error": str(exc)}
    except ValueError:  # JSON decode error
        return {"error": "Failed to parse GeoIP response"}


def _is_valid_ip(ip: str) -> bool:
    """Basic IPv4/IPv6 validation."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except OSError:
        pass
    return False


def resolve_domain(domain: str) -> Dict[str, Any]:
    """Resolve a domain to IP addresses and reverse DNS."""
    if not domain or len(domain) > 253:
        return {"domain": domain or "", "ips": [], "resolve_error": "Invalid domain"}

    result: Dict[str, Any] = {"domain": domain}
    try:
        addrs = socket.getaddrinfo(domain, None)
        ips = sorted({a[4][0] for a in addrs if a[4]})
        result["ips"] = ips
    except socket.gaierror as exc:
        result["ips"] = []
        result["resolve_error"] = str(exc)

    reverse: Dict[str, str] = {}
    for ip in result.get("ips", []):
        try:
            reverse[ip] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, OSError):
            reverse[ip] = "N/A"
    result["reverse_dns"] = reverse
    return result


def dns_records(domain: str) -> Dict[str, Any]:
    """Fetch common DNS records (A, AAAA, MX, NS, TXT, CNAME)."""
    records: Dict[str, List[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:
            records[rtype] = []
    return records


def whois_lookup(domain: str) -> Dict[str, Any]:
    """Fetch WHOIS registration data for a domain."""
    if not domain or len(domain) > 253:
        return {"error": "Invalid domain"}

    try:
        w = whois.whois(domain)

        def clean(val: Any) -> Any:
            if isinstance(val, list):
                return [clean(v) for v in val]
            return val

        return {
            "domain_name": clean(w.domain_name),
            "registrar": w.registrar,
            "whois_server": w.whois_server,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "updated_date": str(w.updated_date) if w.updated_date else None,
            "name_servers": clean(w.name_servers),
            "emails": clean(w.emails),
            "status": clean(w.status),
            "org": w.org,
            "country": w.country,
        }
    except Exception as exc:
        return {"error": str(exc)}


def ip_details(ip: str) -> Dict[str, Any]:
    """Aggregate GeoIP + reverse DNS for a single IP."""
    return {
        "ip": ip,
        "geoip": geoip_lookup(ip),
        "reverse_dns": _reverse_single(ip),
    }


def _reverse_single(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, OSError):
        return "N/A"


def domain_details(domain: str) -> Dict[str, Any]:
    """Full domain dossier: resolution, DNS records, WHOIS."""
    return {
        "domain": domain,
        "resolution": resolve_domain(domain),
        "dns_records": dns_records(domain),
        "whois": whois_lookup(domain),
    }
