from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    send_from_directory,
    abort,
    Response,
)
import os
import sqlite3
import secrets
import hmac
import re
import logging
import threading
import time
import ipaddress
from collections import deque
from datetime import timedelta
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- SECURITY: trust X-Forwarded-* only when an explicit proxy hop count
# is configured. Without this the rate limiter and audit log would record
# the proxy's address instead of the real client when fronted by nginx etc.
_trusted_proxies = 0
try:
    _trusted_proxies = int(os.environ.get("TRUSTED_PROXY_COUNT", "0"))
except ValueError:
    _trusted_proxies = 0
if _trusted_proxies > 0:
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=_trusted_proxies,
        x_proto=_trusted_proxies,
        x_host=_trusted_proxies,
    )

# --- SECURITY: dedicated audit logger ------------------------------------
# Records security-relevant events independently of the request log so
# operators have an evidence trail for incident response. Falls back to
# stderr if no AUDIT_LOG_FILE is configured. All fields written here are
# already validated upstream (see _USERNAME_RE), so log injection via
# newline-in-username is not possible.
audit_log = logging.getLogger("docmanager.audit")
audit_log.setLevel(logging.INFO)
if not audit_log.handlers:
    _audit_path = os.environ.get("AUDIT_LOG_FILE")
    if _audit_path:
        try:
            from logging.handlers import RotatingFileHandler

            # 10 MiB per file, keep 5 rotations = ~50 MiB max audit footprint.
            _h = RotatingFileHandler(
                _audit_path,
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
            )
        except OSError:
            _h = logging.StreamHandler()
    else:
        _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s AUDIT %(levelname)s %(message)s"))
    audit_log.addHandler(_h)
    audit_log.propagate = False


def _scrub(s, max_len=256):
    """Reduce an arbitrary string to printable ASCII, truncating to max_len.
    Used everywhere a value is rendered into an audit line so log injection
    via control bytes (newlines, NUL, DEL, etc.) is structurally impossible."""
    if s is None:
        return "-"
    s = str(s)
    if len(s) > max_len:
        s = s[:max_len]
    return "".join(ch for ch in s if 32 <= ord(ch) < 127)


def _audit(event, **fields):
    """Emit a single structured audit line. Every field is scrubbed of control
    bytes so a malicious value cannot split the line, smuggle a fake event,
    or otherwise corrupt downstream log parsing."""
    parts = [f"event={_scrub(event, 64)}"]
    try:
        ip = request.remote_addr or "-"
    except Exception:
        ip = "-"
    parts.append(f"ip={_scrub(ip, 64)}")
    user = "-"
    try:
        user = session.get("user", "-") if session else "-"
    except Exception as _exc:
        # Best-effort: never let audit logging itself crash a request.
        audit_log.debug("session lookup failed in _audit: %s", _exc)
    parts.append(f"user={_scrub(user, 64)}")
    # Sanitized User-Agent for attribution. Trim hard and strip control bytes.
    try:
        ua = request.headers.get("User-Agent") or "-"
    except Exception:
        ua = "-"
    parts.append(f'ua="{_scrub(ua, 120)}"')
    for k, v in fields.items():
        parts.append(f"{_scrub(k, 32)}={_scrub(v, 256)}")
    audit_log.info(" ".join(parts))


# --- SECURITY: secret key from environment, never hardcoded ---------------
# Falls back to an ephemeral random key so a misconfigured deploy is fail-safe
# (sessions invalidated on restart) instead of fail-open with a guessable key.
_env_secret = os.environ.get("FLASK_SECRET_KEY")
if not _env_secret:
    _env_secret = secrets.token_hex(32)
    app.logger.warning(
        "FLASK_SECRET_KEY not set; using ephemeral key. "
        "Sessions will be invalidated on restart."
    )
app.secret_key = _env_secret

# --- SECURITY: harden cookies, cap upload size, bound session lifetime ----
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower()
    in ("1", "true", "yes"),
    # Renamed from default 'session' so the cookie doesn't fingerprint Flask.
    SESSION_COOKIE_NAME="docmgr_session",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MiB cap mitigates upload DoS
    PREFERRED_URL_SCHEME="https",
    # Sliding 8-hour session lifetime caps the blast radius of a stolen cookie.
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# Resolve once so traversal checks compare canonical absolute paths.
_UPLOAD_ABS = os.path.realpath(UPLOAD_FOLDER)

# SECURITY: resolve the DB path once at import time. Without this a later
# os.chdir() (e.g., by a daemonizer or test harness) would silently open a
# different documents.db and split application state. Operators can relocate
# the DB by setting DOCMANAGER_DB_PATH; default is alongside the app.
_DB_PATH = os.path.realpath(os.environ.get("DOCMANAGER_DB_PATH") or "documents.db")

# --- SECURITY: deny clearly dangerous upload extensions -------------------
# Defense in depth on top of forced attachment download below.
_BLOCKED_EXTENSIONS = {
    ".php",
    ".phtml",
    ".phar",
    ".py",
    ".pyc",
    ".pyo",
    ".pyw",
    ".cgi",
    ".pl",
    ".rb",
    ".sh",
    ".bash",
    ".zsh",
    ".exe",
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".so",
    ".dylib",
    ".jsp",
    ".jspx",
    ".asp",
    ".aspx",
    ".ashx",
    ".htaccess",
    ".htpasswd",
    ".html",
    ".htm",
    ".xhtml",
    ".svg",
    ".js",
    ".mjs",
}

# Allowed username charset (alnum + . _ -); enforces L2.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# --- SECURITY: bucket key derivation -------------------------------------
# Defends against an attacker on a /64 IPv6 prefix rotating through 2**64
# addresses to defeat per-IP rate limiting. We collapse IPv6 to /64 and
# leave IPv4 as a /32 (the host address itself).
def _rate_limit_key(ip):
    if not ip:
        return "-"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        # /64 prefix as canonical string
        net = ipaddress.IPv6Network(f"{ip}/64", strict=False)
        return f"v6:{net.network_address}"
    return f"v4:{ip}"


# --- SECURITY: minimal in-process per-IP rate limiter --------------------
# Sliding-window counter using only stdlib. Not a substitute for a real
# WAF/edge limiter, but it cuts brute-force attempts to a manageable rate.
class _RateLimiter:
    def __init__(self, limit, window_seconds, gc_threshold=4096):
        self.limit = limit
        self.window = window_seconds
        self._gc_threshold = gc_threshold
        self._buckets = {}  # bucket_key -> deque[float]
        self._lock = threading.Lock()

    def hit(self, key):
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            dq = self._buckets.get(key)
            if dq is None:
                dq = deque()
                self._buckets[key] = dq
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.limit:
                return False
            dq.append(now)
            # Periodic GC: drop empty/stale buckets when the map grows large.
            if len(self._buckets) > self._gc_threshold:
                stale = [k for k, d in self._buckets.items() if not d or d[-1] < cutoff]
                for k in stale:
                    self._buckets.pop(k, None)
            return True


def _int_env(name, default, lo=1, hi=10000):
    """Parse a positive integer env var, clamping to [lo, hi] and falling
    back to ``default`` on any parse error. Defends against operator typos."""
    try:
        v = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


# Defaults: 10 login/min/IP, 60 uploads/min/IP, 60 logouts/min/IP.
_RATE_LIMIT_GC_THRESHOLD = _int_env(
    "RATE_LIMIT_GC_THRESHOLD", 4096, lo=64, hi=1_000_000
)
_login_limiter = _RateLimiter(
    limit=_int_env("LOGIN_RATE_LIMIT_PER_MIN", 10),
    window_seconds=60,
    gc_threshold=_RATE_LIMIT_GC_THRESHOLD,
)
_upload_limiter = _RateLimiter(
    limit=_int_env("UPLOAD_RATE_LIMIT_PER_MIN", 60),
    window_seconds=60,
    gc_threshold=_RATE_LIMIT_GC_THRESHOLD,
)
_logout_limiter = _RateLimiter(
    limit=_int_env("LOGOUT_RATE_LIMIT_PER_MIN", 60),
    window_seconds=60,
    gc_threshold=_RATE_LIMIT_GC_THRESHOLD,
)


def init_db():
    conn = sqlite3.connect(_DB_PATH)
    try:
        c = conn.cursor()
        c.execute(
            "CREATE TABLE IF NOT EXISTS documents "
            "(id INTEGER PRIMARY KEY, filename TEXT, owner TEXT, content TEXT)"
        )
        conn.commit()
    finally:
        conn.close()


init_db()


# --- SECURITY: response hardening headers ---------------------------------
@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    )
    # HSTS is a no-op over plain HTTP; safe to set unconditionally so it
    # takes effect the moment the deployment is fronted by TLS.
    resp.headers.setdefault(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
    )
    # Disable all powerful browser features by default; allow-list as needed.
    resp.headers.setdefault("Permissions-Policy", "()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    resp.headers.setdefault("Cache-Control", "no-store")
    # Make per-user cache-key dependence explicit; defense in depth on top of
    # Cache-Control: no-store. Token-based comparison so a custom upstream
    # value like "MyCookieHeader" cannot mask a missing Cookie token.
    existing_vary = resp.headers.get("Vary", "")
    tokens = [t.strip() for t in existing_vary.split(",") if t.strip()]
    if not any(t.lower() == "cookie" for t in tokens):
        tokens.append("Cookie")
        resp.headers["Vary"] = ", ".join(tokens)
    return resp


# --- SECURITY: CSRF protection (synchronizer-token pattern) ---------------
def _get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def _inject_csrf():
    # Exposes csrf_token() to Jinja so templates can render the hidden field.
    return {"csrf_token": _get_csrf_token}


@app.before_request
def _csrf_protect():
    # All sessions are sliding-permanent so PERMANENT_SESSION_LIFETIME applies.
    session.permanent = True
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("_csrf_token") or request.headers.get(
            "X-CSRF-Token", ""
        )
        expected = session.get("_csrf_token", "")
        if not expected or not sent or not hmac.compare_digest(sent, expected):
            _audit("csrf_denied", path=request.path, method=request.method)
            abort(403)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    # Touch CSRF token early so the first form submission has a valid pair.
    _get_csrf_token()
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    # SECURITY: per-IP rate limit before any work. Bucket key collapses
    # IPv6 to /64 to defeat prefix-rotation evasion.
    if not _login_limiter.hit(_rate_limit_key(request.remote_addr)):
        _audit("login_denied", reason="rate_limited")
        abort(429)
    username = (request.form.get("username") or "").strip()
    # SECURITY: reject empty / overlong / non-conforming usernames.
    if not _USERNAME_RE.match(username):
        _audit("login_denied", reason="invalid_username")
        abort(400)
    # SECURITY: rotate the session on privilege change to defeat fixation.
    session.clear()
    session["user"] = username
    session["_csrf_token"] = secrets.token_urlsafe(32)
    _audit("login_ok", username=username)
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    """Drop the current session. CSRF-protected by the global before_request
    handler. Idempotent: safe to POST even when not logged in (clears the
    pre-auth CSRF token cookie too)."""
    # SECURITY: rate-limited so a malicious script cannot use /logout for
    # request amplification or audit-log noise generation.
    if not _logout_limiter.hit(_rate_limit_key(request.remote_addr)):
        _audit("logout_denied", reason="rate_limited")
        abort(429)
    user = session.get("user", "-")
    session.clear()
    _audit("logout", username=user)
    return redirect(url_for("index"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    # SECURITY: per-IP rate limit before any work. Bucket key collapses
    # IPv6 to /64 to defeat prefix-rotation evasion.
    if not _upload_limiter.hit(_rate_limit_key(request.remote_addr)):
        _audit("upload_denied", reason="rate_limited")
        abort(429)
    if "file" not in request.files:
        return redirect(url_for("index"))
    file = request.files["file"]
    if not file or not file.filename:
        return redirect(url_for("index"))

    # SECURITY: reject zero-byte uploads. Without this an attacker can spam
    # /upload to inflate the row count and exhaust inodes/quota for free.
    # We seek the stream to determine length without buffering it.
    try:
        stream = file.stream
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(0)
    except Exception:
        size = -1
    if size == 0:
        _audit("upload_denied", reason="empty_file")
        abort(400)

    # SECURITY: strip any path component / dangerous chars.
    safe_name = secure_filename(file.filename)
    if not safe_name:
        abort(400)

    # SECURITY: extension denylist applied to EVERY dot-separated segment so
    # double-extension payloads like "shell.php.jpg" cannot slip through a
    # downstream web server that interprets the inner extension.
    lowered_parts = safe_name.lower().split(".")
    for part in lowered_parts[1:]:
        if ("." + part) in _BLOCKED_EXTENSIONS:
            abort(400)

    # SECURITY (TOCTOU + race fix): atomically claim the destination filename
    # via O_CREAT|O_EXCL. The previous "exists?-then-write" loop allowed two
    # parallel uploads of the same name to clobber each other. On collision we
    # retry with a numeric suffix; the kernel guarantees only one creator wins.
    base, ext_part = os.path.splitext(safe_name)
    fd = None
    final_name = None
    final_path = None
    for attempt in range(10000):
        candidate_name = safe_name if attempt == 0 else f"{base}_{attempt}{ext_part}"
        candidate_path = os.path.join(_UPLOAD_ABS, candidate_name)
        # Confirm the resolved path is still inside the upload dir.
        try:
            real_candidate = os.path.realpath(candidate_path)
            if os.path.commonpath([real_candidate, _UPLOAD_ABS]) != _UPLOAD_ABS:
                abort(400)
        except ValueError:
            # commonpath raises on cross-root paths -> deny.
            abort(400)
        try:
            fd = os.open(
                real_candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            final_name = candidate_name
            final_path = real_candidate
            break
        except FileExistsError:
            continue
    if fd is None:
        abort(409)

    # SECURITY: bind the disk write and the DB insert into a single atomic
    # unit. The DB row is staged but not committed until the file is fully
    # written; if anything fails we rollback the row AND unlink the file so
    # there are never half-written or orphaned uploads.
    conn = sqlite3.connect(_DB_PATH)
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO documents (filename, owner, content) VALUES (?, ?, ?)",
            (final_name, session["user"], "placeholder"),
        )
        with os.fdopen(fd, "wb") as out:
            file.save(out)
        conn.commit()
    except Exception:
        # Best-effort rollback of both DB and disk state. We log instead of
        # silently swallowing so audit logs still record the partial failure.
        try:
            conn.rollback()
        except Exception:
            app.logger.exception("upload: rollback failed")
        try:
            os.remove(final_path)
        except OSError:
            app.logger.exception("upload: cleanup unlink failed")
        _audit("upload_failed", filename=final_name)
        abort(500)
    finally:
        conn.close()
    _audit("upload_ok", filename=final_name)
    return redirect(url_for("index"))


@app.route("/documents/<int:doc_id>")
@login_required
def view_document(doc_id):
    conn = sqlite3.connect(_DB_PATH)
    try:
        c = conn.cursor()
        # SECURITY: IDOR fix — bind the lookup to the current user.
        c.execute(
            "SELECT filename, owner FROM documents WHERE id=? AND owner=?",
            (doc_id, session["user"]),
        )
        row = c.fetchone()
    finally:
        conn.close()
    if not row:
        # 404 (not 403) so attackers cannot enumerate which IDs exist.
        _audit("view_denied", doc_id=doc_id)
        abort(404)

    # SECURITY: re-sanitize the stored name in case any legacy/poisoned row
    # exists in the DB from before this fix.
    serve_name = secure_filename(row[0] or "")
    if not serve_name:
        _audit("view_denied", doc_id=doc_id, reason="bad_stored_name")
        abort(404)
    _audit("view_ok", doc_id=doc_id, filename=serve_name)

    # send_from_directory enforces traversal safety against _UPLOAD_ABS.
    # Force attachment download with a neutral MIME type so HTML/SVG/JS
    # uploads cannot execute as stored XSS in a browser.
    return send_from_directory(
        _UPLOAD_ABS,
        serve_name,
        as_attachment=True,
        download_name=serve_name,
        mimetype="application/octet-stream",
    )


@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    # SECURITY: strip control characters (incl. NUL) so the query string
    # cannot smuggle log-injection or terminator bytes into anything that
    # later consumes it. Also hard-cap length to bound work.
    query = "".join(ch for ch in query if ch >= " " or ch in "\t")
    if len(query) > 256:
        query = query[:256]

    # SECURITY: parameterized query + escape LIKE wildcards (% and _) so the
    # search cannot be coerced into matching unintended rows.
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    like_pattern = f"%{escaped}%"

    conn = sqlite3.connect(_DB_PATH)
    try:
        c = conn.cursor()
        # SECURITY: scope results to the current user (broken access control fix)
        # and select an explicit column list. Also bound result count.
        results = c.execute(
            "SELECT id, filename, owner, content FROM documents "
            "WHERE owner=? AND filename LIKE ? ESCAPE '\\' LIMIT 100",
            (session["user"], like_pattern),
        ).fetchall()
    finally:
        conn.close()
    # SECURITY: serve as text/plain so the body cannot be interpreted as HTML
    # if any future change loosens upstream input sanitization. Use mimetype
    # without an explicit charset so Flask appends exactly one.
    return Response(str(results), mimetype="text/plain")


# --- SECURITY: generic error handlers (no internal detail leakage) --------
@app.errorhandler(400)
def _e400(_):
    return ("Bad Request", 400)


@app.errorhandler(403)
def _e403(_):
    return ("Forbidden", 403)


@app.errorhandler(404)
def _e404(_):
    return ("Not Found", 404)


@app.errorhandler(409)
def _e409(_):
    return ("Conflict", 409)


@app.errorhandler(413)
def _e413(_):
    return ("Payload Too Large", 413)


@app.errorhandler(429)
def _e429(_):
    return ("Too Many Requests", 429)


@app.errorhandler(500)
def _e500(e):
    # Log the underlying cause so operators can investigate, but never leak
    # it to the client. We log path + method (no query string -> no
    # accidental leakage of sensitive parameters).
    try:
        path = request.path
        method = request.method
    except Exception:
        path = "-"
        method = "-"
    app.logger.exception("unhandled 500 on %s %s: %s", method, path, e)
    _audit("server_error", path=path, method=method)
    return ("Internal Server Error", 500)


if __name__ == "__main__":
    # SECURITY: never enable the Werkzeug debugger by default. Opt-in via env.
    debug_flag = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug_flag, port=5000)
