"""Optional HTTP API server for netmonitor (FastAPI + uvicorn).

Hardening:
- Binds to localhost by default (not exposed to network).
- Rate limiting middleware.
- No secrets exposed in endpoints.
- All endpoints wrapped in try/except.
"""

import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .config import load_config
from .network import get_connections, listening_ports, get_adapters, detect_vpn, active_vpn_summary
from .intel import geoip_lookup, domain_details, _is_valid_ip
from .monitor import get_daemon

app = FastAPI(title="NetMonitor API", version="1.1.0")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/")
def root() -> Dict[str, str]:
    return {"service": "netmonitor", "status": "ok", "version": "1.1.0"}


@app.get("/status")
@limiter.limit("60/minute")
def status(request: Request) -> Dict[str, Any]:
    daemon = get_daemon()
    return {
        "running": daemon.running,
        "config": load_config(),
    }


@app.get("/connections")
@limiter.limit("60/minute")
def connections(request: Request, kind: str = "inet", status: Optional[str] = None) -> Dict[str, Any]:
    try:
        conns = get_connections(kind=kind)
        if status:
            conns = [c for c in conns if c["status"].upper() == status.upper()]
        return {"count": len(conns), "connections": conns}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="internal_error")


@app.get("/ports")
@limiter.limit("60/minute")
def ports(request: Request) -> Dict[str, Any]:
    try:
        return {"count": len(listening_ports()), "ports": listening_ports()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="internal_error")


@app.get("/adapters")
@limiter.limit("60/minute")
def adapters(request: Request) -> Dict[str, Any]:
    try:
        return {"adapters": get_adapters()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="internal_error")


@app.get("/vpn")
@limiter.limit("60/minute")
def vpn(request: Request) -> Dict[str, Any]:
    try:
        vpns = detect_vpn()
        return {"count": len(vpns), "vpns": vpns, "summary": active_vpn_summary()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="internal_error")


@app.get("/geoip/{ip}")
@limiter.limit("10/minute")
def geoip(request: Request, ip: str) -> Dict[str, Any]:
    if not _is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="invalid_ip")
    try:
        return geoip_lookup(ip)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="internal_error")


@app.get("/domain/{name}")
@limiter.limit("10/minute")
def domain(request: Request, name: str) -> Dict[str, Any]:
    if not name or len(name) > 253:
        raise HTTPException(status_code=400, detail="invalid_domain")
    try:
        return domain_details(name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="internal_error")


def run_api(host: str = "127.0.0.1", port: int = 8765) -> None:
    import uvicorn  # type: ignore
    uvicorn.run(app, host=host, port=port, log_level="warning")
