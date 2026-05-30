from __future__ import annotations

from pathlib import Path
import re
import socket
import subprocess
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.llm import OLLAMA_BASE_URL, OLLAMA_MODEL, USE_LLM, explain_with_local_llm
from app.risk_engine import calculate_risk


ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "static"

app = FastAPI(title="Explainable Cloud Risk Scoring")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class AnalyzeRequest(BaseModel):
    ip: str = ""
    country: str = "UNKNOWN"
    asn: str = ""
    timezone: str = ""
    accept_language: str = ""
    user_agent: str | None = None
    screen: str | None = None
    device_seen_before: bool = False
    previous_countries: list[str] = Field(default_factory=list)
    failed_logins_last_5_min: int = 0
    downloaded_docs_last_10_min: int = 0
    protected_requests_last_2_min: int = 0
    webrtc_leak: bool = False
    ipv6_enabled: bool = False
    public_ip_source: str | None = None
    browser_fingerprint_hash: str | None = None
    device_profile: dict[str, Any] = Field(default_factory=dict)
    network_profile: dict[str, Any] = Field(default_factory=dict)
    previous_snapshot: dict[str, Any] | None = None


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/config")
async def config() -> dict[str, str]:
    return {
        "analysis_mode": "ollama" if USE_LLM else "deterministic-formula",
        "ollama_base_url": OLLAMA_BASE_URL,
        "ollama_model": OLLAMA_MODEL,
    }


def _local_ipv4_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        output = subprocess.check_output(
            ["ip", "-4", "addr", "show", "scope", "global"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=1,
        )
        addresses.update(re.findall(r"inet ([0-9.]+)/", output))
    except (OSError, subprocess.SubprocessError):
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            addresses.add(sock.getsockname()[0])
    except OSError:
        pass

    hostname = socket.gethostname()
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            address = info[4][0]
            if not address.startswith("127."):
                addresses.add(address)
    except OSError:
        pass
    docker_prefixes = ("172.17.", "172.18.", "172.19.", "172.20.")
    return sorted(ip for ip in addresses if not ip.startswith(docker_prefixes))


@app.get("/api/client-info")
async def client_info(request: Request) -> dict[str, Any]:
    client_host = request.client.host if request.client else "unknown"
    host_header = request.headers.get("host", "").split(":")[0]
    addresses = set(_local_ipv4_addresses())
    if host_header and host_header not in {"localhost", "127.0.0.1", "0.0.0.0"}:
        addresses.add(host_header)
    if client_host not in {"unknown", "127.0.0.1"}:
        addresses.add(client_host)
    return {
        "observed_ip": client_host,
        "user_agent": request.headers.get("user-agent", ""),
        "server_lan_urls": [f"http://{ip}:8000" for ip in sorted(addresses)],
    }


@app.get("/api/time")
async def server_time() -> dict[str, Any]:
    return {
        "server_epoch_ms": int(time.time() * 1000),
        "server_timezone": time.tzname[0] if time.tzname else "unknown",
    }


@app.post("/api/analyze")
async def analyze(payload: AnalyzeRequest, request: Request) -> dict[str, Any]:
    data = payload.model_dump()
    if not data.get("ip"):
        data["ip"] = request.client.host if request.client else "unknown"

    report = calculate_risk(data)
    explanation = await explain_with_local_llm(report)
    return {"report": report, "explanation": explanation}
