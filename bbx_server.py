#!/usr/bin/env python3
"""
BBX Security Workbench - local server (static files + REST API)
================================================================
Serves bbx.html and the pages/ directory, plus a JSON API for
threat-intel lookups (NVD), LLM report synthesis (OpenAI), test-payload
generation, infrastructure status, a master-sweep ("override") endpoint,
a learning log, page management, self-update, and an authenticated
command shell for local tooling.

Endpoints
---------
GET    /api/status                 module health + version
GET    /api/pages                  list saved pages
GET    /api/learn                  read LEARNED.md
POST   /api/learn                  append to LEARNED.md
POST   /api/save_page              create/overwrite a page
DELETE /api/page?name=...          delete a page
POST   /api/update_app             hot-replace bbx.html (+ optional version)
POST   /api/cmd                    run a local shell command (auth required)
GET    /api/cve/<CVE-ID>           NVD 2.0 vulnerability lookup
POST   /api/analyze                LLM threat-intel synthesis (OpenAI JSON mode)
POST   /api/payload                generate PoC payloads (xss|sqli|ssti)
POST   /api/override               master sweep: CVE intel + payloads + infra + LLM

Configuration (environment variables)
-------------------------------------
BBX_OPENAI_API_KEY   required for /api/analyze and /api/override (LLM step)
BBX_LLM_MODEL        default: gpt-4o
BBX_NVD_API_KEY      optional NVD 2.0 key (raises limit from 5 to 50 req/30s)
BBX_API_TOKEN        bearer token required for /api/cmd (strongly advised with --lan)
BBX_PROXIES          optional comma-separated proxy list (scheme://user:pass@host:port)
BBX_SMTP_HOST        optional SMTP relay host (identity/infra reporting)
BBX_SMTP_PORT        default 587
BBX_SMTP_USER        optional SMTP user
BBX_SMTP_FROM        optional sender address
BBX_HOST / BBX_PORT  default 127.0.0.1:8080

Usage
-----
python3 bbx_server.py            # localhost only
python3 bbx_server.py --lan      # 0.0.0.0 -- set BBX_API_TOKEN first
"""

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import requests

try:
    from openai import OpenAI
except ImportError:  # server still runs; /api/analyze reports LLM_NOT_CONFIGURED
    OpenAI = None

# ---------------------------------------------------------------- config --
ROOT = os.path.dirname(os.path.abspath(__file__))
ALLOW_LAN = "--lan" in sys.argv

OPENAI_API_KEY = os.environ.get("BBX_OPENAI_API_KEY", "").strip()
LLM_MODEL = os.environ.get("BBX_LLM_MODEL", "gpt-4o").strip()
NVD_API_KEY = os.environ.get("BBX_NVD_API_KEY", "").strip()
API_TOKEN = os.environ.get("BBX_API_TOKEN", "").strip()
PROXIES_RAW = os.environ.get("BBX_PROXIES", "").strip()
SMTP_HOST = os.environ.get("BBX_SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("BBX_SMTP_PORT", "587") or "587")
SMTP_USER = os.environ.get("BBX_SMTP_USER", "").strip()
SMTP_FROM = os.environ.get("BBX_SMTP_FROM", "").strip()

HOST = os.environ.get("BBX_HOST", "0.0.0.0" if ALLOW_LAN else "127.0.0.1")
PORT = int(os.environ.get("BBX_PORT", "8080"))

MAX_BODY_BYTES = 1024 * 1024      # 1 MiB request body cap
CMD_TIMEOUT_SECONDS = 180
RATE_LIMIT = 6                    # /api/cmd calls per window per client
RATE_WINDOW_SECONDS = 60.0
OVERRIDE_RATE_LIMIT = 3           # /api/override calls per window per client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("bbx")


# -------------------------------------------------------------- helpers ---
class RateLimiter:
    """Minimal fixed-window rate limiter keyed by client address."""

    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window = window_seconds
        self._hits: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(recent) >= self.limit:
                self._hits[key] = recent
                return False
            recent.append(now)
            self._hits[key] = recent
            return True


def mask_proxy(proxy: str) -> str:
    """Redact credentials from a proxy URL before logging/reporting."""
    try:
        parsed = urlparse(proxy)
        if parsed.username:
            return f"{parsed.scheme}://***:***@{parsed.hostname}:{parsed.port or ''}"
    except Exception:
        pass
    return proxy


# ------------------------------------------------------------ CVE module --
class CVEModule:
    """Client for the NVD 2.0 REST API (https://services.nvd.nist.gov)."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    LATEST_DAYS = 30               # window for the "latest" sweep query
    LATEST_CACHE_TTL = 600.0       # seconds; avoids burning the NVD rate limit

    def __init__(self, api_key: str = ""):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BBX-Security-Workbench/1.0"})
        if api_key:
            self.session.headers["apiKey"] = api_key
        self._latest_cache: Dict[str, Any] = {"ts": 0.0, "data": None}

    def query(self, cve_id: str) -> Dict[str, Any]:
        """Look up a single CVE. Also accepts the alias
        'latest_common_vulnerability' -> returns the most recent CVEs."""
        cve_id = (cve_id or "").strip().upper()
        if cve_id == "LATEST_COMMON_VULNERABILITY":
            return self.latest()
        if not self.CVE_ID_RE.match(cve_id):
            return {"error": "INVALID_CVE_ID",
                    "details": "Expected CVE-YYYY-NNNN (e.g. CVE-2021-44228)"}
        try:
            resp = self.session.get(self.BASE_URL,
                                    params={"cveId": cve_id}, timeout=20)
        except requests.RequestException as exc:
            return {"error": "API_FAILURE", "details": str(exc)}

        if resp.status_code == 403:
            return {"error": "NVD_RATE_LIMITED",
                    "details": "NVD returned 403. Set BBX_NVD_API_KEY or slow down "
                               "(5 req/30s anonymous, 50 req/30s with key)."}
        if resp.status_code == 404:
            return {"error": "NOT_FOUND", "details": f"{cve_id} is not indexed by NVD"}
        if resp.status_code != 200:
            return {"error": "HTTP_%d" % resp.status_code,
                    "details": resp.text[:500]}

        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return {"error": "NOT_FOUND", "details": f"No record for {cve_id}"}
        return self._summarize(vulns[0]["cve"])

    def latest(self, limit: int = 5) -> Dict[str, Any]:
        """Most recently published CVEs (cached for 10 minutes)."""
        now = time.time()
        if self._latest_cache["data"] is not None and \
                now - self._latest_cache["ts"] < self.LATEST_CACHE_TTL:
            return self._latest_cache["data"]

        end = datetime.utcnow()
        start = end - timedelta(days=self.LATEST_DAYS)
        params = {
            "resultsPerPage": max(1, min(limit, 20)),
            # NVD 2.0 requires millisecond precision; omitted offset = UTC
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        try:
            resp = self.session.get(self.BASE_URL, params=params, timeout=20)
        except requests.RequestException as exc:
            return {"error": "API_FAILURE", "details": str(exc)}
        if resp.status_code != 200:
            return {"error": "HTTP_%d" % resp.status_code,
                    "details": resp.text[:500]}

        vulns = resp.json().get("vulnerabilities", [])
        result = {"count": len(vulns),
                  "window_days": self.LATEST_DAYS,
                  "items": [self._summarize(v["cve"]) for v in vulns]}
        self._latest_cache = {"ts": now, "data": result}
        return result

    @staticmethod
    def _summarize(cve: Dict[str, Any]) -> Dict[str, Any]:
        description = next(
            (d["value"] for d in cve.get("descriptions", [])
             if d.get("lang") == "en"), "")
        cvss = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if cve.get("metrics", {}).get(metric_key):
                cvss = cve["metrics"][metric_key][0].get("cvssData")
                break
        weaknesses = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value"):
                    weaknesses.append(d["value"])
        references = [r.get("url") for r in cve.get("references", [])
                      if r.get("url")][:10]
        return {
            "id": cve.get("id"),
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
            "description": description[:2000],
            "cvss": cvss,
            "weaknesses": weaknesses,
            "references": references,
        }


# ------------------------------------------------------------- LLM module --
class LLMModule:
    """Threat-intel synthesis via OpenAI Chat Completions (JSON mode)."""

    SYSTEM_PROMPT = (
        "You are an elite threat-intelligence analyst. Given CVE data, a target "
        "URL, and manual notes, produce a JSON object with exactly these keys: "
        "summary (string), risk_level (string), attack_surface (list of strings), "
        "recommended_actions (list of strings), open_questions (list of strings)."
    )

    def __init__(self, api_key: str, model: str):
        self.model = model
        self.client = OpenAI(api_key=api_key) if (api_key and OpenAI) else None

    def ready(self) -> bool:
        return self.client is not None

    def analyze(self, target_url: str, cve_findings: List[Dict[str, Any]],
                notes: str) -> Dict[str, Any]:
        if not self.ready():
            return {"error": "LLM_NOT_CONFIGURED",
                    "details": "Set BBX_OPENAI_API_KEY and install openai>=1.0"}
        user_content = json.dumps({
            "target_url": target_url,
            "cve_findings": cve_findings,
            "manual_notes": notes,
        }, indent=2)
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                timeout=90,
            )
            raw = response.choices[0].message.content or "{}"
            return json.loads(raw)
        except Exception as exc:  # network, auth, malformed JSON, etc.
            return {"error": "LLM_API_FAILURE", "details": str(exc)}


# -------------------------------------------------------- payload module ---
class PayloadModule:
    """Generates proof-of-concept payloads for authorized testing.

    Execution never happens here; the caller runs the payloads against
    in-scope targets only.
    """

    PAYLOADS: Dict[str, List[str]] = {
        "xss": [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
        ],
        "sqli": [
            "' OR '1'='1",
            "' UNION SELECT NULL,username,password FROM users--",
            "1; DROP TABLE users--",
            "' AND SLEEP(5)--",
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        ],
    }

    def generate(self, vuln_type: str, context: Optional[str] = None) -> Dict[str, Any]:
        vuln_type = (vuln_type or "").lower().strip()
        if vuln_type not in self.PAYLOADS:
            return {"error": "UNKNOWN_TYPE",
                    "details": "Choose one of: " + ", ".join(self.PAYLOADS)}
        payloads = list(self.PAYLOADS[vuln_type])
        if context:
            payloads = [p.replace("{context}", context) for p in payloads]
        return {"type": vuln_type, "count": len(payloads), "payloads": payloads}


# ------------------------------------------------------- proxy module ------
class ProxyManager:
    """Round-robin proxy pool parsed from BBX_PROXIES.

    Credentials are never echoed back in reports; use .status() which
    masks them. The pool is informational/config-level: downstream tooling
    (curl in the terminal, recon scripts) can read proxies from the env.
    """

    def __init__(self, raw: str = ""):
        self.pool = [p.strip() for p in raw.split(",") if p.strip()]
        self._idx = 0
        self._lock = threading.Lock()

    def configured(self) -> bool:
        return bool(self.pool)

    def next(self) -> Optional[str]:
        """Return the next proxy (consuming rotation), or None if unset."""
        if not self.pool:
            return None
        with self._lock:
            proxy = self.pool[self._idx % len(self.pool)]
            self._idx += 1
            return proxy

    def current(self) -> Optional[str]:
        with self._lock:
            return self.pool[self._idx % len(self.pool)] if self.pool else None

    def status(self) -> Dict[str, Any]:
        return {
            "configured": self.configured(),
            "count": len(self.pool),
            "current": mask_proxy(self.current()) if self.current() else None,
        }


# ---------------------------------------------------- identity module -----
class IdentityManager:
    """Reports optional SMTP relay / sender identity config (BBX_SMTP_*).

    Pure configuration reporting — this module never sends mail.
    An smtplib sender can be added later without changing the contract.
    """

    def __init__(self, host: str, port: int, user: str, from_addr: str):
        self.host = host
        self.port = port
        self.user = user
        self.from_addr = from_addr

    def smtp_configured(self) -> bool:
        return bool(self.host and self.from_addr)

    def license_details(self, tier: str = "full") -> Dict[str, Any]:
        configured = self.smtp_configured()
        return {
            "tier": tier,
            "SMTPs": 1 if configured else 0,          # legacy key kept for compat
            "smtp": {
                "configured": configured,
                "host": self.host or None,
                "port": self.port,
                "user": self.user or None,
                "from": self.from_addr or None,
            },
        }


# ---------------------------------------------------- module singletons ---
CVE_DB = CVEModule(NVD_API_KEY)
LLM = LLMModule(OPENAI_API_KEY, LLM_MODEL)
PAYLOADS = PayloadModule()
PROXY_MANAGER = ProxyManager(PROXIES_RAW)
IDENTITY = IdentityManager(SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_FROM)
CMD_LIMITER = RateLimiter(RATE_LIMIT, RATE_WINDOW_SECONDS)
OVERRIDE_LIMITER = RateLimiter(OVERRIDE_RATE_LIMIT, RATE_WINDOW_SECONDS)


# --------------------------------------------------------------- server ---
class Handler(SimpleHTTPRequestHandler):
    server_version = "BBX-Security-Workbench/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, fmt: str, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    # ---- helpers ----------------------------------------------------------
    def _json(self, obj: Any, code: int = 200):
        data = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            raise ValueError("request body exceeds 1 MiB limit")
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            return json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            raise ValueError("invalid JSON body")

    def _authorized(self) -> bool:
        if not API_TOKEN:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {API_TOKEN}"

    @staticmethod
    def _version() -> str:
        try:
            with open(os.path.join(ROOT, "version.json"), encoding="utf-8") as f:
                return json.load(f).get("version", "?")
        except Exception:
            return "?"

    # ---- master sweep (the merged force_override_all_systems) ------------
    def _run_override(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate all subsystems: CVE intel -> payloads -> infra -> LLM."""
        started = time.monotonic()

        # 1. Immediate data injection (latest CVE intel, NVD-backed, cached)
        cve_result = CVE_DB.query("latest_common_vulnerability")

        # 2. Payload generation (action layer)
        payload_result = PAYLOADS.generate(
            (body.get("payload_type") or "xss").lower().strip(),
            body.get("payload_context"))

        # 3. Infrastructure check (proxy pool + identity/SMTP config)
        infra_result = {
            "proxy": PROXY_MANAGER.status(),
            "identity": IDENTITY.license_details("full"),
        }

        # 4. Master synthesis (optional — requires a target URL + LLM key)
        target = (body.get("target_url") or "").strip()
        llm_result = None
        if target:
            cve_findings = [cve_result] if "error" not in cve_result else []
            llm_result = LLM.analyze(
                target, cve_findings, (body.get("manual_notes") or "").strip())

        elapsed = round(time.monotonic() - started, 2)
        return {
            "OVERRIDE_STATUS": "all subsystems operational",
            "DETAIL": "CVE intel, payload engine, proxy pool and identity "
                      "config queried; optional LLM synthesis ran when a "
                      "target_url was supplied.",
            "steps": {
                "cve_intel": cve_result,
                "payloads": payload_result,
                "infra": infra_result,
                "llm_synthesis": llm_result,
            },
            "elapsed_seconds": elapsed,
        }

    # ---- CORS -------------------------------------------------------------
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.send_header("Access-Control-Max-Age", "3600")
        self.end_headers()

    # ---- GET --------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if self._handle_api_get(path):
                return
        except Exception as exc:  # noqa: BLE001 - surface as JSON 500
            log.exception("GET %s failed", path)
            self._json({"error": "INTERNAL", "details": str(exc)}, 500)
            return
        super().do_GET()  # static files (bbx.html, pages/, assets...)

    def _handle_api_get(self, path: str) -> bool:
        if path == "/api/status":
            self._json({
                "ok": True,
                "version": self._version(),
                "root": ROOT,
                "lan": ALLOW_LAN,
                "modules": {
                    "cve": "ok",
                    "llm": "ready" if LLM.ready() else "not_configured",
                    "payloads": "ok",
                    "proxy": "ready" if PROXY_MANAGER.configured() else "not_configured",
                    "smtp": "ready" if IDENTITY.smtp_configured() else "not_configured",
                },
                "security": {
                    "cmd_auth_required": bool(API_TOKEN),
                    "cmd_rate_limit": f"{RATE_LIMIT}/{int(RATE_WINDOW_SECONDS)}s",
                    "override_rate_limit": f"{OVERRIDE_RATE_LIMIT}/{int(RATE_WINDOW_SECONDS)}s",
                },
            })
            return True
        if path == "/api/pages":
            pages_dir = os.path.join(ROOT, "pages")
            os.makedirs(pages_dir, exist_ok=True)
            files = sorted(f for f in os.listdir(pages_dir)
                           if not f.startswith("."))
            self._json({"pages": files})
            return True
        if path == "/api/learn":
            try:
                with open(os.path.join(ROOT, "LEARNED.md"), encoding="utf-8") as f:
                    text = f.read()
                self._json({"text": text[-20000:]})
            except OSError:
                self._json({"text": ""})
            return True
        if path.startswith("/api/cve/"):
            cve_id = path.rsplit("/", 1)[-1]
            self._json(CVE_DB.query(cve_id))
            return True
        return False

    # ---- POST -------------------------------------------------------------
    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json({"error": "BAD_REQUEST", "details": str(exc)}, 400)
            return
        try:
            self._handle_api_post(path, body)
        except Exception as exc:  # noqa: BLE001
            log.exception("POST %s failed", path)
            self._json({"error": "INTERNAL", "details": str(exc)}, 500)

    def _handle_api_post(self, path: str, body: Dict[str, Any]) -> None:
        if path == "/api/cmd":
            if not self._authorized():
                self._json({"error": "UNAUTHORIZED"}, 401)
                return
            if not CMD_LIMITER.allow(self.client_address[0]):
                self._json({"error": "RATE_LIMITED",
                            "details": "too many /api/cmd calls"}, 429)
                return
            command = (body.get("cmd") or "").strip()
            if not command:
                self._json({"error": "EMPTY_COMMAND"}, 400)
                return
            try:
                result = subprocess.run(
                    command, shell=True, cwd=ROOT,
                    capture_output=True, text=True,
                    timeout=CMD_TIMEOUT_SECONDS,
                )
                self._json({
                    "rc": result.returncode,
                    "out": result.stdout[-50000:],
                    "err": result.stderr[-20000:],
                })
            except subprocess.TimeoutExpired:
                self._json({"error": "TIMEOUT",
                            "details": f"command exceeded {CMD_TIMEOUT_SECONDS}s"},
                           408)
            except OSError as exc:
                self._json({"error": str(exc)}, 500)
            return

        if path == "/api/override":
            if not OVERRIDE_LIMITER.allow(self.client_address[0]):
                self._json({"error": "RATE_LIMITED",
                            "details": f"too many /api/override calls "
                                       f"({OVERRIDE_RATE_LIMIT}/{int(RATE_WINDOW_SECONDS)}s)"},
                           429)
                return
            self._json(self._run_override(body))
            return

        if path == "/api/save_page":
            name = (body.get("name") or "").strip()
            name = os.path.basename(name)  # strips any path traversal
            if not name or name.startswith("."):
                self._json({"error": "INVALID_NAME"}, 400)
                return
            content = body.get("content") or ""
            pages_dir = os.path.join(ROOT, "pages")
            os.makedirs(pages_dir, exist_ok=True)
            with open(os.path.join(pages_dir, name), "w", encoding="utf-8") as f:
                f.write(content)
            self._json({"ok": True, "name": name})
            return

        if path == "/api/learn":
            text = (body.get("text") or "").strip()
            if not text:
                self._json({"error": "EMPTY_TEXT"}, 400)
                return
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
            with open(os.path.join(ROOT, "LEARNED.md"), "a", encoding="utf-8") as f:
                f.write(f"\n\n## {stamp}\n{text}\n")
            self._json({"ok": True})
            return

        if path == "/api/update_app":
            html = body.get("html")
            if not html:
                self._json({"error": "NO_HTML"}, 400)
                return
            with open(os.path.join(ROOT, "bbx.html"), "w", encoding="utf-8") as f:
                f.write(html)
            version = (body.get("version") or "").strip()
            if version:
                with open(os.path.join(ROOT, "version.json"), "w",
                          encoding="utf-8") as f:
                    json.dump({"version": version,
                               "note": "applied in-panel",
                               "applied_at": datetime.now().isoformat()},
                              f, indent=2)
            self._json({"ok": True, "version": version})
            return

        if path == "/api/analyze":
            target = (body.get("target_url") or "").strip()
            notes = (body.get("manual_notes") or "").strip()
            cve_ids = body.get("cve_ids") or []
            findings = [CVE_DB.query(str(cve_id)) for cve_id in cve_ids[:10]]
            self._json(LLM.analyze(target, findings, notes))
            return

        if path == "/api/payload":
            self._json(PAYLOADS.generate(body.get("type"), body.get("context")))
            return

        self._json({"error": "NOT_FOUND", "path": path}, 404)

    # ---- DELETE -----------------------------------------------------------
    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/page":
            self._json({"error": "NOT_FOUND"}, 404)
            return
        name = (parse_qs(parsed.query).get("name") or [""])[0]
        name = os.path.basename(name)
        if not name or name.startswith("."):
            self._json({"error": "INVALID_NAME"}, 400)
            return
        try:
            os.remove(os.path.join(ROOT, "pages", name))
            self._json({"ok": True, "name": name})
        except FileNotFoundError:
            self._json({"error": "NOT_FOUND", "details": name}, 404)
        except OSError as exc:
            self._json({"error": str(exc)}, 500)


# ------------------------------------------------------------------ main --
def main() -> int:
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as exc:
        log.error("Cannot bind %s:%d: %s", HOST, PORT, exc)
        return 1

    log.info("BBX Security Workbench -> http://%s:%d/bbx.html", HOST, PORT)
    log.info("LAN mode: %s | /api/cmd auth: %s",
             ALLOW_LAN, "required" if API_TOKEN else "disabled")
    log.info("Modules: CVE=%s LLM=%s Payloads=ready Proxy=%s SMTP=%s",
             "ready" if NVD_API_KEY else "ok (no key)",
             "ready" if LLM.ready() else "not configured",
             "ready (%d proxies)" % len(PROXY_MANAGER.pool) if PROXY_MANAGER.configured() else "not configured",
             "ready" if IDENTITY.smtp_configured() else "not configured")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down (Ctrl+C).")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
