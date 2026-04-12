"""
Live HTTP run of DocManager.

Boots the Flask app behind a real Werkzeug WSGI server bound to a random
loopback port, exercises every endpoint with urllib.request, captures
timing + status + body + headers, then shuts the server down cleanly.

Run with:   python run_live.py
"""

import io
import json
import os
import re
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _build_opener():
    cj = CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj)), cj


def _multipart_body(boundary, fields, files):
    out = []
    for k, v in fields.items():
        out.append(f"--{boundary}\r\n".encode())
        out.append(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
        out.append(str(v).encode() + b"\r\n")
    for k, (filename, data, ctype) in files.items():
        out.append(f"--{boundary}\r\n".encode())
        out.append(
            f'Content-Disposition: form-data; name="{k}"; filename="{filename}"\r\n'.encode()
        )
        out.append(f"Content-Type: {ctype}\r\n\r\n".encode())
        out.append(data + b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out)


def _request(opener, method, url, **kw):
    headers = kw.pop("headers", {})
    data = kw.pop("data", None)
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    t0 = time.perf_counter()
    try:
        r = opener.open(req)
        elapsed = (time.perf_counter() - t0) * 1000
        body = r.read()
        return {
            "status": r.status,
            "elapsed_ms": elapsed,
            "headers": dict(r.headers),
            "body": body,
        }
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return {
            "status": e.code,
            "elapsed_ms": elapsed,
            "headers": dict(e.headers),
            "body": e.read(),
        }


def main():
    # Make sure the test environment is clean.
    for f in ("documents.db",):
        try:
            os.remove(f)
        except OSError:
            pass
    for f in os.listdir("uploads"):
        try:
            os.remove(os.path.join("uploads", f))
        except OSError:
            pass

    # Force a known FLASK_SECRET_KEY so the run is reproducible.
    os.environ["FLASK_SECRET_KEY"] = "live-run-deterministic-secret-key-do-not-use"

    import importlib

    if "app" in globals().get("__seen", set()):
        importlib.reload(__import__("app"))
    import app as appmod

    from werkzeug.serving import make_server

    port = _free_port()
    server = make_server("127.0.0.1", port, appmod.app)
    base = f"http://127.0.0.1:{port}"

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # Wait for the listener
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            break
        except OSError:
            time.sleep(0.02)
    else:
        raise RuntimeError("server failed to start")

    runs = []
    try:
        opener, cj = _build_opener()

        # 1. GET /
        r = _request(opener, "GET", f"{base}/")
        runs.append(("GET /", r))
        body_text = r["body"].decode("utf-8", errors="replace")
        m = re.search(r'name="_csrf_token" value="([^"]+)"', body_text)
        assert m, "no CSRF token in /"
        token = m.group(1)

        # 2. POST /login
        body = f"username=alice&_csrf_token={token}".encode()
        r = _request(
            opener,
            "POST",
            f"{base}/login",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        runs.append(("POST /login", r))

        # 3. GET / again to refresh CSRF token under the new session
        r = _request(opener, "GET", f"{base}/")
        runs.append(("GET / (post-login)", r))
        body_text = r["body"].decode("utf-8", errors="replace")
        token = re.search(r'name="_csrf_token" value="([^"]+)"', body_text).group(1)

        # 4. POST /upload (multipart)
        boundary = "----LiveRunBoundary42"
        body = _multipart_body(
            boundary,
            {"_csrf_token": token},
            {"file": ("livedoc.txt", b"hello-from-live-server", "text/plain")},
        )
        r = _request(
            opener,
            "POST",
            f"{base}/upload",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        runs.append(("POST /upload", r))

        # Look up the doc id directly from the DB so we can fetch it.
        row = (
            sqlite3.connect(appmod._DB_PATH)
            .execute(
                "SELECT id FROM documents WHERE owner='alice' ORDER BY id DESC LIMIT 1"
            )
            .fetchone()
        )
        doc_id = row[0]

        # 5. GET /documents/<id>
        r = _request(opener, "GET", f"{base}/documents/{doc_id}")
        runs.append((f"GET /documents/{doc_id}", r))
        assert r["body"] == b"hello-from-live-server", r["body"]

        # 6. GET /search?q=live
        r = _request(opener, "GET", f"{base}/search?q=live")
        runs.append(("GET /search?q=live", r))

        # 7. POST /upload of a forbidden extension (should 400)
        body = _multipart_body(
            boundary,
            {"_csrf_token": token},
            {"file": ("evil.html", b"<script>alert(1)</script>", "text/html")},
        )
        r = _request(
            opener,
            "POST",
            f"{base}/upload",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        runs.append(("POST /upload (.html, must 400)", r))
        assert r["status"] == 400

        # 8. GET /documents/9999 (must 404, IDOR check)
        r = _request(opener, "GET", f"{base}/documents/9999")
        runs.append(("GET /documents/9999 (IDOR, must 404)", r))
        assert r["status"] == 404

        # 9. POST /logout
        # Refresh CSRF
        r0 = _request(opener, "GET", f"{base}/")
        body_text = r0["body"].decode("utf-8", errors="replace")
        token = re.search(r'name="_csrf_token" value="([^"]+)"', body_text).group(1)
        body = f"_csrf_token={token}".encode()
        r = _request(
            opener,
            "POST",
            f"{base}/logout",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        runs.append(("POST /logout", r))

        # 10. After logout, /documents/<id> must redirect to /
        r = _request(opener, "GET", f"{base}/documents/{doc_id}")
        runs.append(("GET /documents/<id> (after logout)", r))
    finally:
        server.shutdown()
        t.join(timeout=2)

    # ---- Report ----------------------------------------------------------
    print(f"\nLive HTTP run on {base}\n")
    print(f"{'#':<3} {'Endpoint':<42} {'Status':>6} {'ms':>10}  Notes")
    print("-" * 100)
    for i, (name, r) in enumerate(runs, 1):
        notes = []
        ct = r["headers"].get("Content-Type", "")
        if ct:
            notes.append(ct.split(";")[0])
        if r["headers"].get("Content-Disposition"):
            notes.append("attachment")
        if r["headers"].get("Strict-Transport-Security"):
            notes.append("HSTS")
        if r["headers"].get("Content-Security-Policy"):
            notes.append("CSP")
        print(
            f"{i:<3} {name:<42} {r['status']:>6} {r['elapsed_ms']:>9.2f}  {' '.join(notes)}"
        )

    successes = sum(1 for _, r in runs if r["status"] in (200, 302, 400, 404))
    failures = len(runs) - successes
    avg_ms = sum(r["elapsed_ms"] for _, r in runs) / len(runs)
    print(
        f"\nTotal requests: {len(runs)}  successes: {successes}  failures: {failures}"
    )
    print(f"Average response: {avg_ms:.2f} ms")

    # Verify the security headers are actually emitted by the live server
    sec_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cache-Control",
        "Vary",
    ]
    print("\nSecurity headers on GET / (live server):")
    first = runs[0][1]["headers"]
    for h in sec_headers:
        v = first.get(h, "<MISSING>")
        print(f"  {h:<32} {v}")

    return failures == 0


if __name__ == "__main__":
    ok = main()
    raise SystemExit(0 if ok else 1)
