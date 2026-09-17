import base64
import hashlib
import hmac
import json
import os
import queue
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, redirect, request
from flask_sock import Sock
from werkzeug.exceptions import NotFound


def load_env_file():
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env_file()

DATABASE_PATH = os.environ.get("DATABASE_PATH", "wispbyte_gateway.sqlite3")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
MAX_BODY_MB = int(os.environ.get("MAX_BODY_MB", "512"))

app = Flask(__name__)
sock = Sock(app)
devices = {}
pending_http = {}
tcp_clients = {}
update_clients = {}
screenshot_clients = {}
scan_tokens = {}
lock = threading.RLock()


@contextmanager
def db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    with db() as connection:
        connection.execute(
            """
            create table if not exists devices (
                slug text primary key,
                name text not null,
                ftp_port integer not null default 2121,
                web_port integer not null default 8088,
                ftp_server_running integer not null default 1,
                remote_web_enabled integer not null default 1,
                remote_ftp_enabled integer not null default 0,
                remote_update_enabled integer not null default 0,
                app_version text,
                project_clipboard text,
                last_seen_at text
            )
            """
        )
        connection.execute(
            """
            create table if not exists audit_logs (
                id integer primary key autoincrement,
                occurred_at text not null,
                slug text,
                event text not null,
                detail text
            )
            """
        )
        connection.execute(
            """
            create table if not exists portal_settings (
                key text primary key,
                value text
            )
            """
        )
    drop_legacy_token_column()
    ensure_project_clipboard_column()
    ensure_app_version_column()
    ensure_remote_update_column()
    ensure_ftp_server_running_column()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def audit(slug, event, detail=""):
    with db() as connection:
        connection.execute(
            "insert into audit_logs(occurred_at, slug, event, detail) values (?, ?, ?, ?)",
            (now_iso(), slug, event, detail),
        )


def get_setting(key):
    with db() as connection:
        row = connection.execute("select value from portal_settings where key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(key, value):
    with db() as connection:
        connection.execute(
            "insert into portal_settings(key, value) values (?, ?) on conflict(key) do update set value=excluded.value",
            (key, value),
        )


def delete_setting(key):
    with db() as connection:
        connection.execute("delete from portal_settings where key = ?", (key,))


def clean_pattern(pattern):
    parts = str(pattern or "").split("-")
    values = []
    for part in parts:
        if not part.isdigit():
            return ""
        value = int(part)
        if value < 0 or value > 8 or value in values:
            return ""
        values.append(value)
    return "-".join(str(value) for value in values) if len(values) >= 4 else ""


def hash_pattern(pattern, salt):
    return hashlib.pbkdf2_hmac("sha256", pattern.encode("utf-8"), salt, 120000).hex()


def pattern_config():
    value = get_setting("pattern_lock")
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def issue_scan_token():
    token = secrets.token_urlsafe(32)
    with lock:
        scan_tokens[token] = time.time() + 300
    return token


def validate_scan_token(token):
    if not pattern_config():
        return True
    with lock:
        expires = scan_tokens.get(token or "")
        if not expires or expires < time.time():
            scan_tokens.pop(token or "", None)
            return False
        return True


def get_device(slug):
    with db() as connection:
        return connection.execute("select * from devices where slug = ?", (slug,)).fetchone()


def get_columns(table):
    with db() as connection:
        rows = connection.execute(f"pragma table_info({table})").fetchall()
    return [row["name"] for row in rows]


def drop_legacy_token_column():
    if "token_hash" not in get_columns("devices"):
        return
    try:
        with db() as connection:
            connection.execute("alter table devices drop column token_hash")
    except sqlite3.OperationalError:
        with db() as connection:
            connection.execute(
                """
                create table devices_new (
                    slug text primary key,
                    name text not null,
                    ftp_port integer not null default 2121,
                    web_port integer not null default 8088,
                    remote_web_enabled integer not null default 1,
                    remote_ftp_enabled integer not null default 0,
                    remote_update_enabled integer not null default 0,
                    app_version text,
                    project_clipboard text,
                    last_seen_at text
                )
                """
            )
            connection.execute(
                """
                insert into devices_new(slug, name, ftp_port, web_port, remote_web_enabled, remote_ftp_enabled, remote_update_enabled, last_seen_at)
                select slug, name, ftp_port, web_port, remote_web_enabled, remote_ftp_enabled, 0, last_seen_at from devices
                """
            )
            connection.execute("drop table devices")
            connection.execute("alter table devices_new rename to devices")


def ensure_project_clipboard_column():
    if "project_clipboard" in get_columns("devices"):
        return
    with db() as connection:
        connection.execute("alter table devices add column project_clipboard text")


def ensure_app_version_column():
    if "app_version" in get_columns("devices"):
        return
    with db() as connection:
        connection.execute("alter table devices add column app_version text")


def ensure_remote_update_column():
    if "remote_update_enabled" in get_columns("devices"):
        return
    with db() as connection:
        connection.execute("alter table devices add column remote_update_enabled integer not null default 0")


def ensure_ftp_server_running_column():
    if "ftp_server_running" in get_columns("devices"):
        return
    with db() as connection:
        connection.execute("alter table devices add column ftp_server_running integer not null default 1")


def ensure_device(slug, name=None):
    clean_slug = (slug or "").strip().lower()
    if not clean_slug:
        return None
    clean_name = (name or clean_slug).strip() or clean_slug
    with db() as connection:
        connection.execute(
            """
            insert into devices(slug, name, last_seen_at)
            values (?, ?, ?)
            on conflict(slug) do update set last_seen_at=excluded.last_seen_at
            """,
            (clean_slug, clean_name, now_iso()),
        )
    return get_device(clean_slug)


def device_summary(row, online_slugs):
    return {
        "slug": row["slug"],
        "name": row["name"],
        "ftpPort": row["ftp_port"],
        "webPort": row["web_port"],
        "ftpServerRunning": bool(row["ftp_server_running"]),
        "remoteWebEnabled": bool(row["remote_web_enabled"]),
        "remoteFtpEnabled": bool(row["remote_ftp_enabled"]),
        "remoteUpdateEnabled": bool(row["remote_update_enabled"]),
        "online": row["slug"] in online_slugs,
        "lastSeenAt": row["last_seen_at"] or now_iso(),
        "projectClipboard": json.loads(row["project_clipboard"]) if row["project_clipboard"] else None,
        "appVersion": row["app_version"] or "",
    }


def send_json(ws, payload):
    ws.send(json.dumps(payload, separators=(",", ":")))


def recv_json(ws):
    message = ws.receive()
    if message is None:
        return None
    if isinstance(message, bytes):
        message = message.decode("utf-8")
    return json.loads(message)


@app.get("/")
def index():
    return redirect("/api/devices")


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "naart-wispbyte-gateway"})


@app.get("/api/pattern/status")
def pattern_status():
    return jsonify({"isConfigured": pattern_config() is not None})


@app.post("/api/pattern/setup")
def pattern_setup():
    if pattern_config() is not None:
        return Response("Pattern lock is already configured", status=409)
    pattern = clean_pattern((request.get_json(silent=True) or {}).get("pattern"))
    if not pattern:
        return Response("Invalid pattern", status=400)
    salt = secrets.token_bytes(16)
    set_setting(
        "pattern_lock",
        json.dumps({"salt": base64.b64encode(salt).decode("ascii"), "hash": hash_pattern(pattern, salt)}, separators=(",", ":")),
    )
    audit(None, "pattern-lock-setup")
    return jsonify({"ok": True, "scanToken": issue_scan_token()})


@app.post("/api/pattern/verify")
def pattern_verify():
    config = pattern_config()
    if config is None:
        return jsonify({"ok": True, "scanToken": issue_scan_token()})
    pattern = clean_pattern((request.get_json(silent=True) or {}).get("pattern"))
    if not pattern:
        return Response("Invalid pattern", status=403)
    salt = base64.b64decode(config.get("salt") or "")
    expected = config.get("hash") or ""
    if not hmac.compare_digest(hash_pattern(pattern, salt), expected):
        audit(None, "pattern-lock-denied")
        return Response("Invalid pattern", status=403)
    audit(None, "pattern-lock-verified")
    return jsonify({"ok": True, "scanToken": issue_scan_token()})


@app.post("/api/pattern/clear")
def pattern_clear():
    config = pattern_config()
    if config is not None:
        pattern = clean_pattern((request.get_json(silent=True) or {}).get("pattern"))
        salt = base64.b64decode(config.get("salt") or "")
        expected = config.get("hash") or ""
        if not pattern or not hmac.compare_digest(hash_pattern(pattern, salt), expected):
            return Response("Invalid pattern", status=403)
    delete_setting("pattern_lock")
    with lock:
        scan_tokens.clear()
    audit(None, "pattern-lock-cleared")
    return jsonify({"ok": True})


@app.get("/api/devices")
def list_devices():
    if not validate_scan_token(request.headers.get("X-NAART-Scan-Token")):
        return Response("Pattern lock required", status=423)
    with db() as connection:
        rows = connection.execute("select * from devices order by name").fetchall()
    with lock:
        online_slugs = set(devices.keys())
    return jsonify([device_summary(row, online_slugs) for row in rows])


@app.get("/api/devices/<slug>")
def get_device_status(slug):
    clean_slug = (slug or "").strip().lower()
    if not clean_slug:
        raise NotFound()
    row = get_device(clean_slug)
    if row is None:
        raise NotFound()
    with lock:
        online_slugs = set(devices.keys())
    return jsonify(device_summary(row, online_slugs))


@app.post("/api/devices/<slug>/project-clipboard/clear")
def clear_project_clipboard(slug):
    clean_slug = (slug or "").strip().lower()
    if not clean_slug:
        raise NotFound()

    with db() as connection:
        row = connection.execute("select slug from devices where slug = ?", (clean_slug,)).fetchone()
        if row is None:
            raise NotFound()
        connection.execute(
            "update devices set project_clipboard = null, last_seen_at = ? where slug = ?",
            (now_iso(), clean_slug),
        )

    delivered = False
    with lock:
        device = devices.get(clean_slug)
    if device is not None:
        try:
            device.send(json.dumps({"type": "projectClipboard.clear"}))
            delivered = True
        except Exception as ex:
            audit(clean_slug, "project-clipboard-clear-delivery-failed", str(ex))

    audit(clean_slug, "project-clipboard-cleared", "delivered" if delivered else "offline")
    return jsonify({"ok": True, "slug": clean_slug, "delivered": delivered, "projectClipboard": None})


@sock.route("/ws/device")
def device_socket(ws):
    slug = request.args.get("slug", "").strip().lower()
    if not ensure_device(slug):
        ws.close()
        return

    with lock:
        devices[slug] = ws
    audit(slug, "device-online")
    try:
        while True:
            frame = recv_json(ws)
            if frame is None:
                break
            handle_device_frame(slug, frame)
    finally:
        with lock:
            if devices.get(slug) is ws:
                del devices[slug]
        with db() as connection:
            connection.execute("update devices set last_seen_at=? where slug=?", (now_iso(), slug))
        audit(slug, "device-offline")


def handle_device_frame(slug, frame):
    frame_type = frame.get("type")
    if frame_type == "device.hello":
        data = json.loads(frame.get("data") or "{}")
        with db() as connection:
            connection.execute(
                """
                update devices
                set name=?, ftp_port=?, web_port=?, ftp_server_running=?, remote_web_enabled=?, remote_ftp_enabled=?, remote_update_enabled=?, app_version=?, project_clipboard=?, last_seen_at=?
                where slug=?
                """,
                (
                    data.get("name") or slug,
                    int(data.get("ftpPort") or 2121),
                    int(data.get("webPort") or 8088),
                    1 if data.get("ftpServerRunning", True) else 0,
                    1 if data.get("remoteWebEnabled") else 0,
                    1 if data.get("remoteFtpEnabled") else 0,
                    1 if data.get("remoteUpdateEnabled") else 0,
                    data.get("appVersion") or "",
                    json.dumps(data.get("projectClipboard"), separators=(",", ":")) if data.get("projectClipboard") else None,
                    now_iso(),
                    slug,
                ),
            )
        return

    stream_id = frame.get("streamId")
    if frame_type == "http.response" and stream_id in pending_http:
        pending_http[stream_id].put(frame)
    elif frame_type == "tcp.data" and stream_id in tcp_clients:
        tcp_clients[stream_id].send(base64.b64decode(frame.get("data") or ""))
    elif frame_type in ("tcp.close", "error") and stream_id in tcp_clients:
        try:
            tcp_clients[stream_id].close()
        finally:
            tcp_clients.pop(stream_id, None)
    elif frame_type == "error" and stream_id in update_clients:
        try:
            send_json(update_clients[stream_id], {"type": "update.status", "streamId": stream_id, "data": json.dumps({"status": "error", "message": frame.get("error") or "Remote update failed."}, separators=(",", ":"))})
        except Exception:
            update_clients.pop(stream_id, None)
    elif frame_type.startswith("update.") and stream_id in update_clients:
        try:
            send_json(update_clients[stream_id], frame)
        except Exception:
            update_clients.pop(stream_id, None)
    elif frame_type in ("screenshot.response", "error") and stream_id in screenshot_clients:
        try:
            send_json(screenshot_clients[stream_id], frame)
        except Exception:
            screenshot_clients.pop(stream_id, None)


@app.route("/r/<slug>/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/r/<slug>/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def remote_web(slug, path):
    row = get_device(slug)
    if row is None or not row["remote_web_enabled"]:
        raise NotFound("Remote web is not available")
    with lock:
        device = devices.get(slug)
    if device is None:
        raise NotFound("Device is offline")

    body = request.get_data()
    if len(body) > MAX_BODY_MB * 1024 * 1024:
        return Response("Request is too large", status=413)

    request_id = secrets.token_hex(16)
    response_queue = queue.Queue(maxsize=1)
    pending_http[request_id] = response_queue
    query = ("?" + request.query_string.decode("utf-8")) if request.query_string else ""
    headers = build_remote_request_headers()
    payload = {
        "method": request.method,
        "path": "/" + path + query,
        "headers": headers,
        "bodyBase64": base64.b64encode(body).decode("ascii"),
    }
    send_json(device, {"type": "http.request", "streamId": request_id, "data": json.dumps(payload, separators=(",", ":"))})
    try:
        frame = response_queue.get(timeout=120)
    except queue.Empty:
        return Response("Remote device timeout", status=504)
    finally:
        pending_http.pop(request_id, None)

    data = json.loads(frame.get("data") or "{}")
    body = base64.b64decode(data.get("bodyBase64") or "")
    content_type = data.get("contentType") or "application/octet-stream"
    if content_type.lower().startswith("text/html"):
        body = rewrite_remote_html(body, slug)

    response = Response(
        body,
        status=int(data.get("statusCode") or 502),
        content_type=content_type,
    )
    for name, values in (data.get("headers") or {}).items():
        if name.lower() in {"connection", "content-length", "transfer-encoding", "upgrade"}:
            continue
        if isinstance(values, str):
            values = [values]
        for value in rewrite_remote_header_values(name, values, slug):
            response.headers.add(name, value)
    return response


def build_remote_request_headers():
    headers = dict(request.headers)
    headers["X-NAART-Remote-Access"] = "1"
    return headers


def rewrite_remote_html(body, slug):
    prefix = f"/r/{slug}"
    text = body.decode("utf-8", errors="replace")
    replacements = {
        'href="/': f'href="{prefix}/',
        "href='/": f"href='{prefix}/",
        'src="/': f'src="{prefix}/',
        "src='/": f"src='{prefix}/",
        'data-preview-url="/': f'data-preview-url="{prefix}/',
        "data-preview-url='/": f"data-preview-url='{prefix}/",
        'action="/': f'action="{prefix}/',
        "action='/": f"action='{prefix}/",
        'url("/': f'url("{prefix}/',
        "url('/": f"url('{prefix}/",
        "url(/": f"url({prefix}/",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text.encode("utf-8")


def rewrite_remote_header_values(name, values, slug):
    if name.lower() != "location":
        return values
    prefix = f"/r/{slug}"
    rewritten = []
    for value in values:
        if value.startswith("/") and not value.startswith(prefix + "/"):
            rewritten.append(prefix + value)
        else:
            rewritten.append(value)
    return rewritten


@sock.route("/ws/client/tcp")
def client_tcp(ws):
    slug = request.args.get("slug", "").strip().lower()
    target_port = int(request.args.get("targetPort", "0"))
    row = get_device(slug)
    if row is None or not row["remote_ftp_enabled"]:
        ws.close()
        return
    with lock:
        device = devices.get(slug)
    if device is None:
        ws.close()
        return

    stream_id = secrets.token_hex(16)
    tcp_clients[stream_id] = ws
    try:
        first = recv_json(ws)
        if first is None or first.get("type") != "tcp.open":
            ws.close()
            return
        send_json(device, {"type": "tcp.open", "streamId": stream_id, "targetPort": target_port, "data": first.get("data") or "{}"})
        while True:
            data = ws.receive()
            if data is None:
                break
            if isinstance(data, str):
                try:
                    frame = json.loads(data)
                    if frame.get("type") == "tcp.open":
                        continue
                except json.JSONDecodeError:
                    pass
            if isinstance(data, str):
                data = data.encode("utf-8")
            send_json(device, {"type": "tcp.data", "streamId": stream_id, "data": base64.b64encode(data).decode("ascii")})
    finally:
        tcp_clients.pop(stream_id, None)
        try:
            send_json(device, {"type": "tcp.close", "streamId": stream_id})
        except Exception:
            pass


@sock.route("/ws/client/update")
def client_update(ws):
    slug = request.args.get("slug", "").strip().lower()
    row = get_device(slug)
    if row is None or not row["remote_update_enabled"]:
        ws.close()
        return
    with lock:
        device = devices.get(slug)
    if device is None:
        ws.close()
        return

    stream_id = secrets.token_hex(16)
    update_clients[stream_id] = ws
    audit(slug, "update-client-open")
    try:
        while True:
            frame = recv_json(ws)
            if frame is None:
                break
            frame["streamId"] = stream_id
            send_json(device, frame)
    finally:
        update_clients.pop(stream_id, None)
        try:
            send_json(device, {"type": "update.cancel", "streamId": stream_id})
        except Exception:
            pass
        audit(slug, "update-client-close")


@sock.route("/ws/client/screenshot")
def client_screenshot(ws):
    slug = request.args.get("slug", "").strip().lower()
    row = get_device(slug)
    if row is None:
        ws.close()
        return
    with lock:
        device = devices.get(slug)
    if device is None:
        ws.close()
        return

    stream_id = secrets.token_hex(16)
    screenshot_clients[stream_id] = ws
    audit(slug, "screenshot-client-open")
    try:
        first = recv_json(ws)
        if first is None or first.get("type") != "screenshot.request":
            ws.close()
            return
        send_json(device, {"type": "screenshot.request", "streamId": stream_id, "data": first.get("data") or "{}"})
        while True:
            message = ws.receive()
            if message is None:
                break
    finally:
        screenshot_clients.pop(stream_id, None)
        audit(slug, "screenshot-client-close")


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
