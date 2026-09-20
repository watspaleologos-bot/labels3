from __future__ import annotations

import hmac
import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
PORT = int(os.environ.get("PORT", "8080"))
SYNC_TOKEN = os.environ.get("LABEL3_SYNC_TOKEN", "").strip()
VIEW_PIN = os.environ.get("LABEL3_VIEW_PIN", "").strip()
STATE_FILE = Path(os.environ.get("LABEL3_STATE_FILE", "/tmp/label3_readonly_state.json"))
MAX_BODY = 12 * 1024 * 1024
SCHEMA_VERSION = 4
SUPPORTED_SCHEMA_VERSIONS = {2, 3, 4}

_lock = threading.RLock()
_state: dict | None = None
_received_at: str | None = None
_last_contact_at: str | None = None


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_equal(a, b):
    return bool(a) and bool(b) and hmac.compare_digest(str(a), str(b))


def _load_state():
    global _state, _received_at, _last_contact_at
    try:
        if STATE_FILE.exists():
            payload = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("state"), dict):
                _state = payload["state"]
                _received_at = str(payload.get("received_at") or "") or None
                _last_contact_at = str(payload.get("last_contact_at") or _received_at or "") or None
    except Exception:
        _state = None
        _received_at = None
        _last_contact_at = None


def _persist_state(state, received_at, last_contact_at=None):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        temp = STATE_FILE.with_suffix(STATE_FILE.suffix + ".tmp")
        temp.write_text(
            json.dumps({"state": state, "received_at": received_at, "last_contact_at": last_contact_at or received_at}, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        temp.replace(STATE_FILE)
    except Exception:
        # Persistence is optional: the local Label 3 sync repopulates after restart.
        pass


def _touch_contact():
    global _last_contact_at
    stamp = _utc_now()
    with _lock:
        _last_contact_at = stamp
    return stamp


def get_state_envelope():
    with _lock:
        return {
            "ok": True,
            "state": _state,
            "received_at": _received_at,
            "last_contact_at": _last_contact_at,
            "snapshot_hash": (_state or {}).get("snapshot_hash"),
        }


def apply_snapshot(snapshot):
    global _state, _received_at, _last_contact_at
    if not isinstance(snapshot, dict):
        raise ValueError("Invalid snapshot")
    if int(snapshot.get("schema_version") or 0) not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError("Unsupported snapshot schema")
    required = ("source_version", "generated_at", "board", "flow", "snapshot_hash")
    if any(key not in snapshot for key in required):
        raise ValueError("Incomplete snapshot")
    received_at = _utc_now()
    with _lock:
        _state = snapshot
        _received_at = received_at
        _last_contact_at = received_at
        _persist_state(snapshot, received_at, received_at)
    return {
        "ok": True,
        "snapshot_hash": snapshot.get("snapshot_hash"),
        "received_at": received_at,
        "last_contact_at": received_at,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "PaleologosLabels3Readonly/1.1"

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def _send(self, status, body=b"", content_type="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, payload, status=200):
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            raise ValueError("Invalid body")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Invalid JSON")
        return data

    def _sync_authorized(self):
        auth = str(self.headers.get("Authorization") or "")
        return auth.startswith("Bearer ") and _safe_equal(SYNC_TOKEN, auth[7:].strip())

    def _view_authorized(self):
        return _safe_equal(VIEW_PIN, str(self.headers.get("X-View-PIN") or "").strip())

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._json({"ok": True, "service": "label3-readonly", "has_state": _state is not None})
            return
        if path == "/api/label3/sync-status":
            if not self._sync_authorized():
                self._json({"error": "Unauthorized"}, 401)
                return
            # This authenticated lightweight poll is also the heartbeat.  It updates
            # online freshness even when the canonical snapshot hash did not change.
            contact = _touch_contact()
            env = get_state_envelope()
            self._json({
                "ok": True,
                "snapshot_hash": env["snapshot_hash"],
                "received_at": env["received_at"],
                "last_contact_at": contact,
            })
            return
        if path == "/api/state-status":
            if not self._view_authorized():
                self._json({"error": "Unauthorized"}, 401)
                return
            env = get_state_envelope()
            self._json({
                "ok": True,
                "received_at": env["received_at"],
                "last_contact_at": env["last_contact_at"],
                "snapshot_hash": env["snapshot_hash"],
            })
            return
        if path == "/api/state":
            if not self._view_authorized():
                self._json({"error": "Unauthorized"}, 401)
                return
            self._json(get_state_envelope())
            return
        if path in {"/", "/index.html"}:
            body = (STATIC_DIR / "index.html").read_bytes()
            self._send(200, body, "text/html; charset=utf-8")
            return
        if path == "/header_logo.png":
            body = (STATIC_DIR / "header_logo.png").read_bytes()
            self._send(200, body, "image/png")
            return
        if path in {"/app-icon.png", "/app-icon-192.png", "/app-icon-512.png"}:
            filename = path.lstrip("/")
            body = (STATIC_DIR / filename).read_bytes()
            self._send(200, body, "image/png")
            return
        if path == "/manifest.webmanifest":
            body = (STATIC_DIR / "manifest.webmanifest").read_bytes()
            self._send(200, body, "application/manifest+json; charset=utf-8")
            return
        if path == "/sw.js":
            body = (STATIC_DIR / "sw.js").read_bytes()
            self._send(200, body, "application/javascript; charset=utf-8")
            return
        self._json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/login":
            try:
                payload = self._read_json()
                ok = _safe_equal(VIEW_PIN, str(payload.get("pin") or "").strip())
            except Exception:
                ok = False
            self._json({"ok": ok}, 200 if ok else 401)
            return
        if path == "/api/label3/sync":
            if not self._sync_authorized():
                self._json({"error": "Unauthorized"}, 401)
                return
            try:
                result = apply_snapshot(self._read_json())
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
                return
            except Exception:
                self._json({"error": "Snapshot rejected"}, 500)
                return
            self._json(result)
            return
        self._json({"error": "Not found"}, 404)


_load_state()

if __name__ == "__main__":
    if not SYNC_TOKEN or not VIEW_PIN:
        raise SystemExit("LABEL3_SYNC_TOKEN and LABEL3_VIEW_PIN are required")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Label 3 read-only Railway service listening on 0.0.0.0:{PORT}")
    server.serve_forever()
