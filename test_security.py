"""
Security regression tests for the DocManager hardening pass.

Run with:   python test_security.py
Exits 0 on success, non-zero on the first failure. Uses Flask's test client
in an isolated tmp working directory; no network sockets are opened.

Note for SAST tools: this file uses `assert` because that is the standard
test assertion form in Python. Add `# nosec B101,B105` if running bandit
against this file directly.
"""

import io
import os
import re
import sys
import shutil
import sqlite3
import tempfile
import importlib


# ---- Helpers --------------------------------------------------------------


def _bootstrap():
    """Import app.py inside an isolated cwd so the test never touches
    the real uploads/ or documents.db files."""
    tmp = tempfile.mkdtemp(prefix="docmanager_test_")
    shutil.copytree(
        os.path.dirname(os.path.abspath(__file__)),
        os.path.join(tmp, "src"),
        ignore=shutil.ignore_patterns("__pycache__", "test_*.py", "documents.db"),
    )
    os.chdir(os.path.join(tmp, "src"))
    sys.path.insert(0, os.getcwd())
    if "app" in sys.modules:
        del sys.modules["app"]
    return importlib.import_module("app")


def _csrf_from(html: str) -> str:
    m = re.search(r'name="_csrf_token" value="([^"]+)"', html)
    assert m, "no CSRF token in rendered template"
    return m.group(1)


def _login(client, username):
    r = client.get("/")
    token = _csrf_from(r.get_data(as_text=True))
    r = client.post(
        "/login",
        data={"username": username, "_csrf_token": token},
        follow_redirects=False,
    )
    assert r.status_code == 302, f"login failed: {r.status_code}"


def _fresh_token(client):
    return _csrf_from(client.get("/").get_data(as_text=True))


# ---- Test cases -----------------------------------------------------------


def test_login_csrf_required(app):
    with app.test_client() as c:
        # No prior GET / → no CSRF token in session → must be rejected.
        r = c.post("/login", data={"username": "alice"})
        assert r.status_code == 403, f"expected 403 got {r.status_code}"


def test_login_rejects_bad_username(app):
    with app.test_client() as c:
        token = _fresh_token(c)
        r = c.post("/login", data={"username": "", "_csrf_token": token})
        assert r.status_code == 400
        token = _fresh_token(c)
        r = c.post("/login", data={"username": "../etc", "_csrf_token": token})
        assert r.status_code == 400
        token = _fresh_token(c)
        r = c.post("/login", data={"username": "x" * 200, "_csrf_token": token})
        assert r.status_code == 400


def test_session_rotation_on_login(app):
    with app.test_client() as c:
        t1 = _fresh_token(c)
        _login(c, "alice")
        # New CSRF token after login
        t2 = _fresh_token(c)
        assert t1 != t2, "session/CSRF token did not rotate on login"


def test_upload_path_traversal_blocked(app):
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        # Use a non-blocked extension so the only thing standing between the
        # payload and a sandbox escape is the path-traversal sanitizer.
        data = {
            "_csrf_token": token,
            "file": (io.BytesIO(b"pwned"), "../../etc/pwn.txt"),
        }
        r = c.post("/upload", data=data, content_type="multipart/form-data")
        assert r.status_code == 302, f"upload should succeed sanitized: {r.status_code}"
        # Nothing must have been written outside uploads/
        assert not os.path.exists("../etc/pwn.txt")
        assert (
            not os.path.exists("/etc/pwn.txt")
            or open("/etc/pwn.txt", "rb").read() != b"pwned"
        )
        # The sanitized name must live INSIDE uploads/, with no path components.
        files = os.listdir(app.config["UPLOAD_FOLDER"])
        assert any(f.endswith("pwn.txt") for f in files), files
        for f in files:
            assert ".." not in f and "/" not in f


def test_upload_dangerous_extension_blocked(app):
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        data = {
            "_csrf_token": token,
            "file": (io.BytesIO(b"<script>alert(1)</script>"), "xss.html"),
        }
        r = c.post("/upload", data=data, content_type="multipart/form-data")
        assert r.status_code == 400, f"html upload should be 400, got {r.status_code}"


def test_idor_blocked_on_view_document(app):
    # alice uploads a doc, bob attempts to read it
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b"alice-data"), "a.txt")},
            content_type="multipart/form-data",
        )
    # find the row id alice owns
    conn = sqlite3.connect("documents.db")
    row = conn.execute(
        "SELECT id FROM documents WHERE owner='alice' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert row, "alice's row not inserted"
    doc_id = row[0]

    with app.test_client() as c:
        _login(c, "bob")
        r = c.get(f"/documents/{doc_id}")
        assert r.status_code == 404, f"IDOR not blocked: status {r.status_code}"

    with app.test_client() as c:
        _login(c, "alice")
        r = c.get(f"/documents/{doc_id}")
        assert r.status_code == 200, f"owner cannot read own doc: {r.status_code}"
        assert r.headers.get("Content-Disposition", "").startswith("attachment"), (
            "served document must be forced as attachment"
        )
        assert r.headers.get("Content-Type", "").startswith("application/octet-stream")


def test_view_document_requires_auth(app):
    with app.test_client() as c:
        # Unauthenticated → redirect to /
        r = c.get("/documents/1", follow_redirects=False)
        assert r.status_code in (302, 401, 403), (
            f"expected redirect, got {r.status_code}"
        )


def test_search_requires_auth(app):
    with app.test_client() as c:
        r = c.get("/search?q=test", follow_redirects=False)
        assert r.status_code in (302, 401, 403)


def test_search_no_sql_injection(app):
    # Plant a row owned by 'alice' and one owned by 'mallory'
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b"x"), "alice.txt")},
            content_type="multipart/form-data",
        )
    with app.test_client() as c:
        _login(c, "mallory")
        token = _fresh_token(c)
        c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b"x"), "secret.txt")},
            content_type="multipart/form-data",
        )

    # mallory's classic SQLi payload must NOT return alice's row, and must
    # not blow up the query.
    with app.test_client() as c:
        _login(c, "mallory")
        payload = "%' OR '1'='1"
        r = c.get(f"/search?q={payload}")
        body = r.get_data(as_text=True)
        assert r.status_code == 200, body
        assert "alice.txt" not in body, "SQLi leaked another user's row"


def test_search_results_scoped_to_owner(app):
    with app.test_client() as c:
        _login(c, "alice")
        r = c.get("/search?q=secret")
        body = r.get_data(as_text=True)
        # alice's search must not see mallory's secret.txt
        assert "secret.txt" not in body


def test_search_like_wildcards_escaped(app):
    # Searching for literal "_" should not match unrelated rows.
    with app.test_client() as c:
        _login(c, "carol")
        token = _fresh_token(c)
        c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b"x"), "abc.txt")},
            content_type="multipart/form-data",
        )
        token = _fresh_token(c)
        c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b"x"), "a_c.txt")},
            content_type="multipart/form-data",
        )
        r = c.get("/search?q=_")
        body = r.get_data(as_text=True)
        assert "a_c.txt" in body
        assert "abc.txt" not in body, "LIKE wildcard not escaped"


def test_security_headers(app):
    with app.test_client() as c:
        r = c.get("/")
        for h in (
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
        ):
            assert h in r.headers, f"missing header {h}"


def test_double_extension_blocked(app):
    """N2: shell.php.jpg must be rejected even though .jpg is allowed."""
    with app.test_client() as c:
        _login(c, "alice")
        for evil in ("shell.php.jpg", "x.html.png", "boom.svg.txt", "evil.JS.gif"):
            token = _fresh_token(c)
            r = c.post(
                "/upload",
                data={"_csrf_token": token, "file": (io.BytesIO(b"x"), evil)},
                content_type="multipart/form-data",
            )
            assert r.status_code == 400, (
                f"{evil} should be blocked, got {r.status_code}"
            )


def test_concurrent_upload_collision_no_clobber(app):
    """N1: two parallel uploads of the same name must produce two files,
    two DB rows, and zero data loss."""
    import threading

    barrier = threading.Barrier(2)
    results = []
    lock = threading.Lock()

    def worker(payload, marker):
        with app.test_client() as c:
            _login(c, "alice")
            token = _fresh_token(c)
            barrier.wait()  # release both threads simultaneously
            r = c.post(
                "/upload",
                data={"_csrf_token": token, "file": (io.BytesIO(payload), "race.bin")},
                content_type="multipart/form-data",
            )
            with lock:
                results.append((marker, r.status_code))

    t1 = threading.Thread(target=worker, args=(b"AAAA" * 32, "A"))
    t2 = threading.Thread(target=worker, args=(b"BBBB" * 32, "B"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert all(s == 302 for _, s in results), f"both uploads should succeed: {results}"

    files = sorted(os.listdir(app.config["UPLOAD_FOLDER"]))
    assert len(files) == 2, f"expected 2 files, got {files}"

    # Read both files; their byte contents must be the two distinct payloads.
    bodies = set()
    for f in files:
        with open(os.path.join(app.config["UPLOAD_FOLDER"], f), "rb") as fh:
            bodies.add(fh.read())
    assert bodies == {b"AAAA" * 32, b"BBBB" * 32}, "data loss in concurrent upload"

    # And the DB must have two rows whose filenames match the two on-disk files.
    rows = (
        sqlite3.connect("documents.db")
        .execute("SELECT filename FROM documents WHERE owner='alice'")
        .fetchall()
    )
    db_names = sorted(r[0] for r in rows)
    assert db_names == files, f"DB/disk mismatch: {db_names} vs {files}"


def test_upload_failure_rolls_back_db_row(app):
    """If the file write fails, no orphan DB row must remain."""
    # We simulate failure by uploading something whose secure_filename collapses
    # to nothing AFTER the dot-segment check. This is a sanity check that the
    # except block does NOT leak rows when abort() fires inside the try.
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        # Force a 400 via empty post-sanitize name; no row should be inserted.
        r = c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b"x"), "...")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 400
        rows = (
            sqlite3.connect("documents.db")
            .execute("SELECT COUNT(*) FROM documents")
            .fetchone()
        )
        assert rows[0] == 0, "DB row leaked after rejected upload"


def test_secret_key_not_hardcoded(app):
    assert app.secret_key != "super-secret-key-12345"  # nosec B105
    assert len(app.secret_key) >= 32


def test_debug_off_by_default(app):
    # Even though we don't actually call .run(), make sure the debugger
    # is not somehow enabled by config.
    assert app.debug is False


def test_search_response_is_text_plain(app):
    """P3.1: /search must serve text/plain so a future XSS regression in
    upstream input sanitization cannot be interpreted as HTML."""
    with app.test_client() as c:
        _login(c, "alice")
        r = c.get("/search?q=anything")
        ct = r.headers.get("Content-Type", "")
        assert ct.startswith("text/plain"), f"expected text/plain, got {ct!r}"


def test_session_lifetime_bounded(app):
    """P3.2: PERMANENT_SESSION_LIFETIME must be set to a tight bound."""
    from datetime import timedelta

    lt = app.config.get("PERMANENT_SESSION_LIFETIME")
    assert lt is not None, "PERMANENT_SESSION_LIFETIME unset"
    assert lt <= timedelta(hours=24), f"lifetime too long: {lt}"


def test_vary_cookie_header_present(app):
    """P3.3: Vary: Cookie must appear so cache layers key on the session."""
    with app.test_client() as c:
        r = c.get("/")
        vary = r.headers.get("Vary", "")
        assert "Cookie" in vary, f"Vary header missing Cookie: {vary!r}"


def _capture_audit():
    """Attach an in-memory handler to the audit logger and return it."""
    import logging
    import importlib

    mod = importlib.import_module("app")
    log = mod.audit_log
    records = []

    class Cap(logging.Handler):
        def emit(self, r):
            records.append(self.format(r))

    h = Cap()
    h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h)
    return records, lambda: log.removeHandler(h)


def test_audit_logs_login(app):
    """P4.1: successful login must emit an audit record."""
    records, undo = _capture_audit()
    try:
        with app.test_client() as c:
            _login(c, "alice")
        joined = " | ".join(records)
        assert "event=login_ok" in joined and "username=alice" in joined, joined
    finally:
        undo()


def test_audit_logs_csrf_denied(app):
    """P4.3: CSRF rejections must leave an audit trail."""
    records, undo = _capture_audit()
    try:
        with app.test_client() as c:
            r = c.post("/login", data={"username": "x"})  # no token
            assert r.status_code == 403
        joined = " | ".join(records)
        assert "event=csrf_denied" in joined, joined
    finally:
        undo()


def test_audit_logs_idor_attempt(app):
    """P4.1: blocked IDOR access must leave an audit trail."""
    records, undo = _capture_audit()
    try:
        with app.test_client() as c:
            _login(c, "alice")
            token = _fresh_token(c)
            c.post(
                "/upload",
                data={"_csrf_token": token, "file": (io.BytesIO(b"x"), "a.txt")},
                content_type="multipart/form-data",
            )
        with app.test_client() as c:
            _login(c, "bob")
            r = c.get("/documents/1")
            assert r.status_code == 404
        joined = " | ".join(records)
        assert "event=view_denied" in joined and "user=bob" in joined, joined
    finally:
        undo()


def test_audit_logs_upload_ok(app):
    """P4.1: successful upload must emit an audit record with filename."""
    records, undo = _capture_audit()
    try:
        with app.test_client() as c:
            _login(c, "alice")
            token = _fresh_token(c)
            c.post(
                "/upload",
                data={"_csrf_token": token, "file": (io.BytesIO(b"x"), "doc.txt")},
                content_type="multipart/form-data",
            )
        joined = " | ".join(records)
        assert "event=upload_ok" in joined and "filename=doc.txt" in joined, joined
    finally:
        undo()


def test_zero_byte_upload_rejected(app):
    """P5.1: empty files must be rejected (no inode-exhaustion DoS)."""
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        r = c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b""), "empty.txt")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 400, f"empty file should be 400, got {r.status_code}"
        files = os.listdir(app.config["UPLOAD_FOLDER"])
        assert files == [], f"no file should be on disk: {files}"
        rows = (
            sqlite3.connect("documents.db")
            .execute("SELECT COUNT(*) FROM documents")
            .fetchone()
        )
        assert rows[0] == 0, "no DB row should exist"


def test_oversized_upload_returns_413(app):
    """P5.2: an upload exceeding MAX_CONTENT_LENGTH must be 413 not 500."""
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        # 17 MiB payload > 16 MiB cap
        big = b"A" * (17 * 1024 * 1024)
        r = c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(big), "big.bin")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 413, f"expected 413, got {r.status_code}"


def test_search_strips_nul_bytes(app):
    """P5.3: NUL bytes in q must not crash the query and must not appear
    in any row's matching pattern."""
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b"x"), "abc.txt")},
            content_type="multipart/form-data",
        )
        r = c.get("/search?q=ab%00c")
        assert r.status_code == 200
        # The NUL must have been stripped, leaving "abc" which DOES match.
        assert "abc.txt" in r.get_data(as_text=True)


def test_upload_unauth_redirects(app):
    """P5.5: /upload without a session must not 500; it should redirect.
    (CSRF check happens first if no session, returning 403 — also acceptable.)"""
    with app.test_client() as c:
        # No prior /login
        r = c.post("/upload", follow_redirects=False)
        assert r.status_code in (302, 403), f"unexpected: {r.status_code}"


def test_filename_with_nul_byte_sanitized(app):
    """P5.4: secure_filename must strip NUL bytes from uploaded filenames."""
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        # NUL embedded in filename
        r = c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b"data"), "ev\x00il.txt")},
            content_type="multipart/form-data",
        )
        # Either accepted with sanitized name OR rejected; never crash.
        assert r.status_code in (302, 400), r.status_code
        files = os.listdir(app.config["UPLOAD_FOLDER"])
        for f in files:
            assert "\x00" not in f, f


def test_login_rate_limited(app):
    """P6.1: more than 10 login attempts per IP per minute must 429."""
    # Reset the limiter so this test is order-independent.
    import importlib

    mod = importlib.import_module("app")
    mod._login_limiter._buckets.clear()
    statuses = []
    with app.test_client() as c:
        for _ in range(15):
            tok = _fresh_token(c)
            r = c.post("/login", data={"username": "alice", "_csrf_token": tok})
            statuses.append(r.status_code)
    assert 429 in statuses, f"expected at least one 429, got {statuses}"
    # First 10 should succeed (302) and the rest should be 429.
    n429 = sum(1 for s in statuses if s == 429)
    assert n429 >= 5, f"expected >=5 429s, got {n429}: {statuses}"


def test_upload_rate_limited(app):
    """P6.1: more than 60 uploads per IP per minute must 429."""
    import importlib

    mod = importlib.import_module("app")
    mod._upload_limiter._buckets.clear()
    mod._login_limiter._buckets.clear()
    with app.test_client() as c:
        _login(c, "alice")
        seen = set()
        for i in range(70):
            tok = _fresh_token(c)
            r = c.post(
                "/upload",
                data={"_csrf_token": tok, "file": (io.BytesIO(b"x"), f"f{i}.txt")},
                content_type="multipart/form-data",
            )
            seen.add(r.status_code)
            if r.status_code == 429:
                break
        assert 429 in seen, f"never hit 429: {seen}"


def test_vary_merge_does_not_duplicate(app):
    """P6.3: repeated requests must not append duplicate Cookie tokens."""
    with app.test_client() as c:
        r = c.get("/")
        v = r.headers.get("Vary", "")
        assert v.count("Cookie") == 1, f"duplicate Cookie in Vary: {v!r}"


def test_leading_dot_filename_sanitized(app):
    """P6.4: leading-dot filenames (.bashrc, .htaccess) must be normalized
    so they don't land as dotfiles in the upload directory."""
    import importlib

    mod = importlib.import_module("app")
    mod._upload_limiter._buckets.clear()
    mod._login_limiter._buckets.clear()
    with app.test_client() as c:
        _login(c, "alice")
        token = _fresh_token(c)
        r = c.post(
            "/upload",
            data={"_csrf_token": token, "file": (io.BytesIO(b"x"), ".bashrc")},
            content_type="multipart/form-data",
        )
        # Either rejected (400) or accepted with stripped leading dot.
        assert r.status_code in (302, 400)
        files = os.listdir(app.config["UPLOAD_FOLDER"])
        for f in files:
            assert not f.startswith("."), f"dotfile in uploads: {f}"


def test_audit_log_includes_user_agent(app):
    """P8.2: audit lines must carry the (sanitized) User-Agent."""
    records, undo = _capture_audit()
    try:
        with app.test_client() as c:
            tok = _fresh_token(c)
            c.post(
                "/login",
                data={"username": "alice", "_csrf_token": tok},
                headers={"User-Agent": "MyTestAgent/1.0"},
            )
        joined = " | ".join(records)
        assert 'ua="MyTestAgent/1.0"' in joined, joined
    finally:
        undo()


def test_rate_limit_env_configurable(app):
    """P9.1: LOGIN_RATE_LIMIT_PER_MIN env var must override the default."""
    import importlib, os as _os

    _os.environ["LOGIN_RATE_LIMIT_PER_MIN"] = "3"
    try:
        if "app" in sys.modules:
            del sys.modules["app"]
        mod = importlib.import_module("app")
        assert mod._login_limiter.limit == 3, mod._login_limiter.limit
    finally:
        _os.environ.pop("LOGIN_RATE_LIMIT_PER_MIN", None)
        # Restore the canonical app module for subsequent tests.
        if "app" in sys.modules:
            del sys.modules["app"]
        importlib.import_module("app")


def test_rate_limit_env_clamped(app):
    """P9.1: an absurd LOGIN_RATE_LIMIT_PER_MIN value must be clamped, not
    crash startup."""
    import importlib, os as _os

    _os.environ["LOGIN_RATE_LIMIT_PER_MIN"] = "999999999"
    try:
        if "app" in sys.modules:
            del sys.modules["app"]
        mod = importlib.import_module("app")
        assert mod._login_limiter.limit <= 10000, mod._login_limiter.limit
    finally:
        _os.environ.pop("LOGIN_RATE_LIMIT_PER_MIN", None)
        if "app" in sys.modules:
            del sys.modules["app"]
        importlib.import_module("app")


def test_rate_limit_env_garbage_falls_back(app):
    """P9.1: a non-numeric LOGIN_RATE_LIMIT_PER_MIN must fall back, not crash."""
    import importlib, os as _os

    _os.environ["LOGIN_RATE_LIMIT_PER_MIN"] = "abc"
    try:
        if "app" in sys.modules:
            del sys.modules["app"]
        mod = importlib.import_module("app")
        assert mod._login_limiter.limit == 10, mod._login_limiter.limit
    finally:
        _os.environ.pop("LOGIN_RATE_LIMIT_PER_MIN", None)
        if "app" in sys.modules:
            del sys.modules["app"]
        importlib.import_module("app")


def test_logout_clears_session(app):
    """P10.1: POST /logout with a valid CSRF token must drop the session."""
    with app.test_client() as c:
        _login(c, "alice")
        # Confirm logged in by accessing a protected route
        token = _fresh_token(c)
        # Now logout
        r = c.post(
            "/logout",
            data={"_csrf_token": token},
            follow_redirects=False,
        )
        assert r.status_code == 302
        # Subsequent /upload must redirect (not authorized) or 403 CSRF.
        r = c.post("/upload", follow_redirects=False)
        assert r.status_code in (302, 403)


def test_logout_requires_csrf(app):
    """P10.1: /logout must be CSRF-protected like every other POST."""
    with app.test_client() as c:
        _login(c, "alice")
        r = c.post("/logout")  # no token
        assert r.status_code == 403


def test_logout_audit_event(app):
    """P10.1: /logout must emit an audit record naming the user."""
    records, undo = _capture_audit()
    try:
        with app.test_client() as c:
            _login(c, "alice")
            tok = _fresh_token(c)
            c.post("/logout", data={"_csrf_token": tok})
        joined = " | ".join(records)
        assert "event=logout" in joined and "username=alice" in joined, joined
    finally:
        undo()


def test_session_cookie_name_renamed(app):
    """P10.2: cookie name must not fingerprint Flask as 'session'."""
    assert app.config.get("SESSION_COOKIE_NAME") == "docmgr_session"
    with app.test_client() as c:
        r = c.get("/")
        sc = r.headers.get("Set-Cookie", "")
        assert sc.startswith("docmgr_session="), f"unexpected Set-Cookie: {sc!r}"


def test_template_includes_logout_button(app):
    """P10.3: rendered index must contain a Logout form so browsers can use it."""
    with app.test_client() as c:
        r = c.get("/")
        body = r.get_data(as_text=True)
        assert "/logout" in body, body
        assert "Logout" in body, body


def test_audit_kwargs_strip_control_bytes(app):
    """P11.1: every kwarg value in an audit record must be scrubbed of
    control bytes, not just \\n / \\r."""
    records, undo = _capture_audit()
    try:
        # Call _audit directly with a hostile value, inside a request context
        # so the request/session proxies are valid.
        import importlib

        mod = importlib.import_module("app")
        with app.test_request_context("/"):
            mod._audit("test_event", path="evil\nFAKE\x00BAD\x7fX\x01Y")
        joined = " | ".join(records)
        # No control bytes anywhere in the rendered line.
        for ch in "\n\r\x00\x01\x02\x07\x1b\x7f":
            assert ch not in joined, f"control byte {ord(ch):#04x} leaked"
        # The visible characters around the stripped bytes must remain.
        assert "evilFAKEBADXY" in joined or "path=evilFAKEBADXY" in joined, joined
    finally:
        undo()


def test_audit_path_log_injection_blocked(app):
    """P11.2: a request path containing %0A must not split the audit line."""
    records, undo = _capture_audit()
    try:
        with app.test_client() as c:
            # POST to a URL whose path contains an encoded newline. The CSRF
            # check fires before routing, so this exercises the same audit
            # path used by csrf_denied.
            c.post("/foo%0AFAKE_EVENT=1")
        # No record line may begin with FAKE_EVENT (would mean we split a row).
        for line in records:
            assert not line.lstrip().startswith("FAKE_EVENT"), line
    finally:
        undo()


def test_db_path_is_absolute(app):
    """P12.1: the resolved database path must be absolute so a later
    os.chdir() cannot split application state."""
    import importlib

    mod = importlib.import_module("app")
    assert os.path.isabs(mod._DB_PATH), mod._DB_PATH
    # The constant must end in 'documents.db' regardless of cwd.
    assert mod._DB_PATH.endswith("documents.db"), mod._DB_PATH


def test_db_writes_survive_chdir(app):
    """P12.1 functional check: a chdir between requests must not split DB
    state. Upload one file, chdir, then verify the row is still visible."""
    import importlib

    mod = importlib.import_module("app")
    mod._login_limiter._buckets.clear()
    mod._upload_limiter._buckets.clear()
    original_cwd = os.getcwd()
    try:
        with app.test_client() as c:
            _login(c, "alice")
            tok = _fresh_token(c)
            c.post(
                "/upload",
                data={"_csrf_token": tok, "file": (io.BytesIO(b"x"), "preserved.txt")},
                content_type="multipart/form-data",
            )
        # Move cwd somewhere unrelated.
        os.chdir(tempfile.gettempdir())
        with app.test_client() as c:
            _login(c, "alice")
            r = c.get("/search?q=preserved")
            body = r.get_data(as_text=True)
            assert "preserved.txt" in body, body
    finally:
        os.chdir(original_cwd)


def test_logout_emits_cookie_deletion(app):
    """P13.1: /logout must emit a Set-Cookie that actually deletes the
    browser-side cookie, not just mutate server state. A stolen cookie that
    survives a logout would defeat the entire point of the endpoint."""
    with app.test_client() as c:
        _login(c, "alice")
        tok = _fresh_token(c)
        r = c.post("/logout", data={"_csrf_token": tok}, follow_redirects=False)
        sc_headers = r.headers.getlist("Set-Cookie")
        # Find the docmgr_session cookie in the response.
        cookie_lines = [s for s in sc_headers if s.startswith("docmgr_session=")]
        assert cookie_lines, f"no Set-Cookie for docmgr_session: {sc_headers}"
        cookie = cookie_lines[0].lower()
        # Either an explicit Expires in the past or Max-Age=0.
        assert "expires=" in cookie or "max-age=0" in cookie, cookie


def test_search_response_bounded(app):
    """P13.3: search response must stay bounded even if the user has many
    matching rows (LIMIT 100 + bounded filename length).

    Optimized in pass 16: previously did 250 multipart POSTs through the
    upload pipeline (~0.5s). Now plants rows directly in the DB and only
    exercises /search end-to-end. ~50x faster while still validating the
    SQL LIMIT clause."""
    import importlib

    mod = importlib.import_module("app")
    # Plant 250 matching rows directly so the test focuses on the LIMIT clause.
    conn = sqlite3.connect(mod._DB_PATH)
    try:
        c = conn.cursor()
        c.executemany(
            "INSERT INTO documents (filename, owner, content) VALUES (?, ?, ?)",
            [(f"f{i:04d}.txt", "alice", "placeholder") for i in range(250)],
        )
        conn.commit()
    finally:
        conn.close()
    with app.test_client() as c:
        _login(c, "alice")
        r = c.get("/search?q=f")
        body = r.get_data(as_text=True)
        assert len(body) < 50 * 1024, f"search body too large: {len(body)}"
        # And no more than 100 row tuples should be present.
        assert body.count("'alice'") <= 100, body.count("'alice'")


def test_no_relative_db_paths_in_source(app):
    """P13.2: structural check that no sqlite3.connect() in app.py uses a
    relative literal path. Catches future regressions."""
    import re

    with open("app.py") as f:
        src = f.read()
    # Find every sqlite3.connect(...) call argument.
    for m in re.finditer(r"sqlite3\.connect\(([^)]+)\)", src):
        arg = m.group(1).strip()
        assert arg == "_DB_PATH", f"sqlite3.connect uses non-_DB_PATH arg: {arg!r}"


def test_audit_user_agent_strips_control_bytes(app):
    """P8.2 / log injection defense: control bytes in the User-Agent must be
    stripped so an attacker cannot smuggle non-printable bytes into the
    audit log. Werkzeug already blocks LF/CR before headers reach the app;
    this test verifies the in-app sanitizer covers the bytes that DO get
    through (e.g. DEL 0x7F)."""
    records, undo = _capture_audit()
    try:
        with app.test_client() as c:
            tok = _fresh_token(c)
            c.post(
                "/login",
                data={"username": "alice", "_csrf_token": tok},
                headers={"User-Agent": "good\x7fbad"},
            )
        joined = " | ".join(records)
        # The DEL byte must not appear in the rendered audit line; the
        # bracketing characters around it must remain.
        assert "\x7f" not in joined, "DEL byte leaked into audit log"
        assert 'ua="goodbad"' in joined, joined
    finally:
        undo()


def test_db_path_env_override(app):
    """P14: DOCMANAGER_DB_PATH must override the default DB location."""
    import importlib
    import os as _os

    custom = os.path.join(tempfile.gettempdir(), "docmgr_test_override.db")
    _os.environ["DOCMANAGER_DB_PATH"] = custom
    try:
        if "app" in sys.modules:
            del sys.modules["app"]
        mod = importlib.import_module("app")
        assert mod._DB_PATH == _os.path.realpath(custom), mod._DB_PATH
    finally:
        _os.environ.pop("DOCMANAGER_DB_PATH", None)
        try:
            _os.remove(custom)
        except OSError:
            pass
        if "app" in sys.modules:
            del sys.modules["app"]
        importlib.import_module("app")


def test_ipv6_prefix_bucketing(app):
    """P14: IPv6 addresses in the same /64 must collapse to a single rate-
    limit bucket; otherwise an attacker on a /64 can defeat the limiter."""
    import importlib

    mod = importlib.import_module("app")
    k1 = mod._rate_limit_key("2001:db8::1")
    k2 = mod._rate_limit_key("2001:db8::ffff:ffff:ffff:ffff")
    k3 = mod._rate_limit_key("2001:db8:1::1")  # different /64
    assert k1 == k2, f"same /64 produced different keys: {k1!r} vs {k2!r}"
    assert k1 != k3, f"different /64s collapsed: {k1!r} == {k3!r}"
    # IPv4 should NOT be collapsed.
    v4a = mod._rate_limit_key("10.0.0.1")
    v4b = mod._rate_limit_key("10.0.0.2")
    assert v4a != v4b, "IPv4 host addresses collapsed"


def test_ipv6_garbage_address_safe(app):
    """P14: a malformed IP must not crash the rate limiter."""
    import importlib

    mod = importlib.import_module("app")
    k = mod._rate_limit_key("not-an-ip")
    assert k == "not-an-ip" or k.startswith("v"), k
    k = mod._rate_limit_key("")
    assert k == "-"
    k = mod._rate_limit_key(None)
    assert k == "-"


def test_rate_limit_gc_threshold_env_configurable(app):
    """P14: RATE_LIMIT_GC_THRESHOLD must be readable from env."""
    import importlib
    import os as _os

    _os.environ["RATE_LIMIT_GC_THRESHOLD"] = "128"
    try:
        if "app" in sys.modules:
            del sys.modules["app"]
        mod = importlib.import_module("app")
        assert mod._login_limiter._gc_threshold == 128, mod._login_limiter._gc_threshold
        assert mod._upload_limiter._gc_threshold == 128, (
            mod._upload_limiter._gc_threshold
        )
    finally:
        _os.environ.pop("RATE_LIMIT_GC_THRESHOLD", None)
        if "app" in sys.modules:
            del sys.modules["app"]
        importlib.import_module("app")


def test_500_handler_logs_method(app):
    """P14: 500 audit record must include method, not just path. Calls the
    handler directly inside a test request context so we don't have to fight
    Flask's PROPAGATE_EXCEPTIONS testing-mode behavior."""
    import importlib

    mod = importlib.import_module("app")
    records, undo = _capture_audit()
    try:
        with app.test_request_context("/some/explosive/path", method="POST"):
            body, status = mod._e500(RuntimeError("simulated"))
            assert status == 500
            assert body == "Internal Server Error"
        joined = " | ".join(records)
        assert "event=server_error" in joined, joined
        assert "method=POST" in joined, joined
        assert "path=/some/explosive/path" in joined, joined
    finally:
        undo()


def test_csp_no_unsafe_inline(app):
    """P15: tightened CSP must not contain 'unsafe-inline'."""
    with app.test_client() as c:
        r = c.get("/")
        csp = r.headers.get("Content-Security-Policy", "")
        assert "unsafe-inline" not in csp, csp
        # form-action 'self' must also be present (added in pass 15).
        assert "form-action" in csp, csp


def test_logout_rate_limited(app):
    """P15: more than LOGOUT_RATE_LIMIT_PER_MIN logouts/min/IP must 429."""
    import importlib

    mod = importlib.import_module("app")
    mod._logout_limiter._buckets.clear()
    mod._login_limiter._buckets.clear()
    with app.test_client() as c:
        _login(c, "alice")
        statuses = []
        for _ in range(70):
            tok = _fresh_token(c)
            r = c.post("/logout", data={"_csrf_token": tok})
            statuses.append(r.status_code)
            if r.status_code == 429:
                break
        assert 429 in statuses, f"never hit /logout 429: {statuses}"


# ---- Runner ---------------------------------------------------------------

TESTS = [
    test_login_csrf_required,
    test_login_rejects_bad_username,
    test_session_rotation_on_login,
    test_upload_path_traversal_blocked,
    test_upload_dangerous_extension_blocked,
    test_double_extension_blocked,
    test_concurrent_upload_collision_no_clobber,
    test_upload_failure_rolls_back_db_row,
    test_view_document_requires_auth,
    test_search_requires_auth,
    test_idor_blocked_on_view_document,
    test_search_no_sql_injection,
    test_search_results_scoped_to_owner,
    test_search_like_wildcards_escaped,
    test_security_headers,
    test_secret_key_not_hardcoded,
    test_debug_off_by_default,
    test_search_response_is_text_plain,
    test_session_lifetime_bounded,
    test_vary_cookie_header_present,
    test_audit_logs_login,
    test_audit_logs_csrf_denied,
    test_audit_logs_idor_attempt,
    test_audit_logs_upload_ok,
    test_zero_byte_upload_rejected,
    test_oversized_upload_returns_413,
    test_search_strips_nul_bytes,
    test_upload_unauth_redirects,
    test_filename_with_nul_byte_sanitized,
    test_login_rate_limited,
    test_upload_rate_limited,
    test_vary_merge_does_not_duplicate,
    test_leading_dot_filename_sanitized,
    test_audit_log_includes_user_agent,
    test_audit_user_agent_strips_control_bytes,
    test_rate_limit_env_configurable,
    test_rate_limit_env_clamped,
    test_rate_limit_env_garbage_falls_back,
    test_logout_clears_session,
    test_logout_requires_csrf,
    test_logout_audit_event,
    test_session_cookie_name_renamed,
    test_template_includes_logout_button,
    test_audit_kwargs_strip_control_bytes,
    test_audit_path_log_injection_blocked,
    test_db_path_is_absolute,
    test_db_writes_survive_chdir,
    test_logout_emits_cookie_deletion,
    test_search_response_bounded,
    test_no_relative_db_paths_in_source,
    test_db_path_env_override,
    test_ipv6_prefix_bucketing,
    test_ipv6_garbage_address_safe,
    test_rate_limit_gc_threshold_env_configurable,
    test_500_handler_logs_method,
    test_csp_no_unsafe_inline,
    test_logout_rate_limited,
]


def main():
    app_module = _bootstrap()
    app = app_module.app
    app.testing = True
    failures = 0
    for t in TESTS:
        # Each test gets a fresh DB + uploads dir + rate-limit state.
        try:
            os.remove("documents.db")
        except OSError:
            pass
        for f in os.listdir(app.config["UPLOAD_FOLDER"]):
            try:
                os.remove(os.path.join(app.config["UPLOAD_FOLDER"], f))
            except OSError:
                pass
        app_module.init_db()
        # Reset rate-limiter state so tests are order-independent.
        for lim_attr in ("_login_limiter", "_upload_limiter", "_logout_limiter"):
            lim = getattr(app_module, lim_attr, None)
            if lim is not None:
                lim._buckets.clear()
        try:
            t(app)
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"  FAIL  {t.__name__}: {e}")
        except Exception as e:
            failures += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print()
    if failures:
        print(f"{failures} test(s) failed")
        sys.exit(1)
    print(f"All {len(TESTS)} tests passed")


if __name__ == "__main__":
    main()
