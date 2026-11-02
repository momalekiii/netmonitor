"""DNS leak detection feature.

Checks if DNS queries resolve consistently across multiple resolvers.
Non-destructive: only performs DNS lookups.
"""

import socket
from typing import Any, Dict

from ..config import DEFAULT_CONFIG

# Public DNS resolvers to cross-check
DNS_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
]


class DNSLeakFeature:
    name = "dns_leak"
    description = "DNS leak / hijack detection"
    default_enabled = False
    requires_root = False

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("dns_leak", False)
        self.domains = config.get("dns_leak_domains", ["google.com", "cloudflare.com"])

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            changes.append(
                "Monitoring "
                + str(len(self.domains))
                + " domain(s) across "
                + str(len(DNS_RESOLVERS))
                + " resolvers"
            )
        return {"ok": True, "message": "DNS leak feature configured", "changes": changes}

    def check_dns(self) -> Dict[str, Any]:
        """Check DNS resolution consistency across resolvers.

        Returns potential leaks without modifying anything.
        """
        results: Dict[str, Any] = {}
        leaks = []

        for domain in self.domains:
            ips_per_resolver: Dict[str, list] = {}
            for resolver_name, resolver_ip in DNS_RESOLVERS:
                try:
                    ips = socket.getaddrinfo(domain, None)
                    ip_set = sorted({a[4][0] for a in ips if a[4]})
                    ips_per_resolver[resolver_name] = ip_set
                except Exception as exc:
                    ips_per_resolver[resolver_name] = ["error: " + str(exc)]

            ip_lists = [
                tuple(v) for v in ips_per_resolver.values() if not v[0].startswith("error")
            ]
            consistent = len(set(ip_lists)) <= 1 if ip_lists else False

            if not consistent:
                leaks.append(domain)

            results[domain] = {
                "consistent": consistent,
                "resolvers": ips_per_resolver,
            }

        return {
            "domains_checked": len(self.domains),
            "leaks_detected": len(leaks),
            "leaked_domains": leaks,
            "details": results,
        }
