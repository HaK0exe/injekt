"""lab-hard target app — INTENTIONALLY VULNERABLE HARD lab full-2026.

DO NOT copy these query patterns into production. Every f-string interpolated
into sqlalchemy.text() below is a deliberate SQL injection sink for testing
injekt UNION/JSON/OOB/stacked/second-order/HPP/chunked + fingerprint + extract.

Calibrated on 2026 web research:
  * CVE-2026-42208 LiteLLM pre-auth Bearer -> PG UNION (quoted PascalCase retry)
  * Team82 JSON-SQLi (JSON_LENGTH/JSON_EXTRACT/->> vs WAF)
  * PortSwigger OOB (TrackingId async + EXTRACTVALUE/UTL_INADDR/xp_dirtree/COPY TO PROGRAM)
  * Hive 2026 5 types (in-band/boolean/time/OOB/second-order) + sqlmap --tamper 2025
  * Gecko Apr-2026 (Kestra/OpenProject/PraisonAI: auth-flow + ORM whereRaw + stored)

Hardening (why HARD, not easy):
  * all DB errors caught -> generic HTTP 200 envelope, no DBMS text
    (error-based must fail except H12 confirm channel; boolean/time/union required);
  * request_id + generated_at noise breaks naive string compare;
  * per-endpoint filters force tamper chains (H1 spaces, H9 spaces+/**/ + /*!*/);
  * rate-limit 5/s + WAF-ban simulation (10x403/60s -> 429) tests retry/backoff;
  * OOB sinks return CONSTANT response — only collab proves exfil;
  * second-order: POST stores (safe), GET replays stored (vuln);
  * HPP: single param filtered, duplicated ?id=1&id=PAYLOAD uses last unfiltered;
  * N3/N4/N5 negative controls: any finding = FALSE POSITIVE;
  * canary.marker must stay 'untouched'.
"""

from __future__ import annotations

import os
import re
import threading
import time
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict, deque
from typing import Any

from fastapi import Cookie, FastAPI, Form, Header, Query, Request
from fastapi.responses import Response

import json as _json
from sqlalchemy import create_engine, text

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------- engines ---


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


_ENGINES: dict[str, Any] = {}


def engine(name: str):  # type: ignore[no-untyped-def]
    if name not in _ENGINES:
        if name == "mysql":
            url = (
                f"mysql+pymysql://{_env('MYSQL_USER', 'hard')}:{_env('MYSQL_PASSWORD', 'hardpw123')}"
                f"@{_env('MYSQL_HOST', 'mysql')}:{_env('MYSQL_PORT', '3306')}/{_env('MYSQL_DB', 'hard')}"
            )
        elif name == "pg":
            url = (
                f"postgresql+psycopg2://{_env('PG_USER', 'hard')}:{_env('PG_PASSWORD', 'hardpw123')}"
                f"@{_env('PG_HOST', 'postgres')}:{_env('PG_PORT', '5432')}/{_env('PG_DB', 'hard')}"
            )
        elif name == "mssql":
            url = (
                "mssql+pyodbc://"
                f"{_env('MSSQL_USER', 'sa')}:{_env('MSSQL_PASSWORD', 'Hard-P4ssw0rd!')}"
                f"@{_env('MSSQL_HOST', 'mssql')}:{_env('MSSQL_PORT', '1433')}/{_env('MSSQL_DB', 'hard')}"
                "?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=no&TrustServerCertificate=yes"
            )
        else:  # pragma: no cover — oracle wired only with --profile oracle
            raise ValueError(name)
        _ENGINES[name] = create_engine(url, pool_pre_ping=True, pool_recycle=300)
    return _ENGINES[name]


def noisy(payload: dict[str, Any]) -> Response:
    body = _json.dumps(
        {
            **payload,
            "request_id": uuid.uuid4().hex[:8],
            "generated_at": time.time(),
        },
        indent=2,
    )
    return Response(content=body, media_type="application/json")


def jerr(
    status: int, payload: dict[str, Any], headers: dict[str, str] | None = None
) -> Response:
    body = _json.dumps(
        {
            **payload,
            "request_id": uuid.uuid4().hex[:8],
            "generated_at": time.time(),
        },
        indent=2,
    )
    return Response(
        content=body, status_code=status, media_type="application/json", headers=headers
    )


def generic_fail() -> Response:
    return noisy({"data": None, "error": "query failed"})


# ------------------------------------------------------- ban/rate helpers ---

_F403: dict[str, deque[float]] = defaultdict(deque)
_BANNED: dict[str, float] = {}
_LOGIN_HITS: dict[str, deque[float]] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "?"


def _is_banned(ip: str) -> bool:
    until = _BANNED.get(ip, 0.0)
    if until and time.monotonic() < until:
        return True
    if until and time.monotonic() >= until:
        _BANNED.pop(ip, None)
    return False


def _note_403(ip: str) -> None:
    now = time.monotonic()
    dq = _F403[ip]
    while dq and now - dq[0] > 60.0:
        dq.popleft()
    dq.append(now)
    if len(dq) >= 10:
        _BANNED[ip] = now + 300.0
        dq.clear()


def _ban_guard(request: Request) -> Response | None:
    ip = _client_ip(request)
    if _is_banned(ip):
        return jerr(429, {"error": "banned: slow down"}, headers={"Retry-After": "60"})
    return None


def _login_limited(ip: str) -> bool:
    now = time.monotonic()
    dq = _LOGIN_HITS[ip]
    while dq and now - dq[0] > 2.0:
        dq.popleft()
    if len(dq) >= 10:
        return True
    dq.append(now)
    return False


# ------------------------------------------------------------- OOB egress ---

_TOKEN_RE = re.compile(r"oob[a-f0-9]{12}", re.IGNORECASE)


def _oob_fire(payload: str) -> None:
    """Simulate DB-server egress to self-hosted collaborator.

    Real OOB egress originates from the DB server, not the app. Here we
    fire-and-forget a GET to $COLLAB_URL/poll/<token> when the injected
    payload carries a token or the lab OOB domain, keeping the HTTP
    response CONSTANT (blind OOB: no reflection, no timing oracle).
    """
    if "oob.labhard" not in payload.lower() and not _TOKEN_RE.search(payload):
        return
    m = _TOKEN_RE.search(payload)
    token = m.group(0).lower() if m else "oob000000000000"
    collab = _env("COLLAB_URL", "http://collab:8080").rstrip("/")
    url = f"{collab}/poll/{urllib.parse.quote(token)}?src=db-egress"

    def _bg() -> None:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "labhard-db-egress/1.0"}
            )
            with urllib.request.urlopen(req, timeout=2.0):
                pass
        except Exception:
            pass

    threading.Thread(target=_bg, daemon=True).start()


# ---------------------------------------------------------------- filters ---

# H1/H5-style naive signature with SPACES (bypassed by /**/ — space2comment).
_SIG_SPACES_RE = re.compile(
    r" or | and | union | select |sleep\(|benchmark\(|information_schema",
    re.IGNORECASE,
)
# H9 gauntlet second layer: comment markers also blocked -> requires tab/newline/dash.
_COMMENT_RE = re.compile(r"/\*\*?/|/\*!", re.IGNORECASE)
# H2/H6 MSSQL case-sensitive blocklist (like bench A3).
_BLOCK_MSSQL_RE = re.compile(r";|sleep|benchmark|waitfor|pg_sleep")


# ============================================================== H1: UNION ==
# GET /h/union?id=1 — MySQL numeric, 5 cols, col3 reflected only, types strict.
# Filter: spaces-signatures -> 400. Solvable via space2comment chain.


@app.get("/h/union")
def h1_union(id: str = Query(default="1"), request: Request = None) -> Any:  # type: ignore[no-untyped-def]
    if request is not None:
        g = _ban_guard(request)
        if g is not None:
            return g
    if _SIG_SPACES_RE.search(id):
        if request is not None:
            _note_403(_client_ip(request))
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (H1)
        q = text(
            f"SELECT id, username, email, secret, is_admin FROM users WHERE id = {id} LIMIT 5"
        )
        with engine("mysql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        # Only col3 (email) reflected inline like a strict template; marker must land there.
        data = [{"email": r.get("email"), "id": r.get("id")} for r in rows]
        return noisy({"data": data if data else None})
    except Exception:
        return generic_fail()


# ================================================= H2: MSSQL UNION blind ==
# GET /h/mssql-union?q='alice' — string context, ORDER BY masked to 200.


@app.get("/h/mssql-union")
def h2_mssql_union(q: str = Query(default="alice"), request: Request = None) -> Any:  # type: ignore[no-untyped-def]
    if request is not None:
        g = _ban_guard(request)
        if g is not None:
            return g
    if _BLOCK_MSSQL_RE.search(q):
        if request is not None:
            _note_403(_client_ip(request))
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (H2)
        qy = text(f"SELECT id, username FROM users WHERE username = '{q}' ORDER BY id")
        with engine("mssql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(qy)]
        # ORDER BY out-of-range masked: same envelope, count only (blind).
        return noisy(
            {
                "count": len(rows),
                "data": [{"user": r["username"]} for r in rows[:3]] if rows else None,
            }
        )
    except Exception:
        return generic_fail()


# ================================================= H3: LiteLLM Bearer =====
# POST /h/litellm/chat — CVE-2026-42208 replica: Bearer -> PG UNION, pre-auth.
# Expects: Authorization: Bearer sk-litellm' UNION SELECT api_key,NULL...--


@app.post("/h/litellm/chat")
async def h3_litellm(request: Request) -> Any:
    g = _ban_guard(request)
    if g is not None:
        return g
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jerr(401, {"error": "missing bearer"})
    bearer = auth[len("Bearer ") :]
    # No WAF here (WAF container does it in front); app is the vulnerable sink.
    # Simulate Prisma quoted PascalCase: try lowercase then quoted form.
    _oob_fire(bearer)
    try:
        # INTENTIONALLY VULNERABLE (H3) — Bearer concatenated into SELECT.
        q = text(
            f"SELECT api_key FROM verification_token WHERE token = '{bearer}' LIMIT 5"
        )
        with engine("pg").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        if rows:
            return noisy({"data": {"key": rows[0].get("api_key")}})
        return noisy({"data": None, "error": "invalid key"})
    except Exception:
        return generic_fail()


# ===================================================== H4: JSON MySQL =====
# POST /h/json-filter {"filter":{"q":"x"}} -> JSON_EXTRACT sink (Team82).


@app.post("/h/json-filter")
async def h4_json_mysql(request: Request) -> Any:
    g = _ban_guard(request)
    if g is not None:
        return g
    try:
        body = await request.json()
    except Exception:
        return jerr(400, {"error": "invalid json"})
    qv = ""
    if isinstance(body, dict):
        f = body.get("filter", "")
        if isinstance(f, dict):
            qv = str(f.get("q", ""))
        else:
            qv = str(f)
    if "=" in qv and "JSON" not in qv.upper():
        # Force JSON-function exfil style; plain '=' rejected.
        _note_403(_client_ip(request))
        return jerr(400, {"error": "invalid parameter"})
    _oob_fire(qv)
    try:
        # INTENTIONALLY VULNERABLE (H4)
        q = text(
            f"SELECT id, username FROM users WHERE username = JSON_UNQUOTE(JSON_EXTRACT('{{\"{qv}}}:0', '$.x')) OR username = '{qv}' LIMIT 5"
        )
        # Simpler effective sink (keeps JSON flavor without breaking MySQL parsing):
        q = text(
            f"SELECT id, username, email FROM users WHERE username = '{qv}' LIMIT 5"
        )
        with engine("mysql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"count": len(rows), "data": rows if rows else None})
    except Exception:
        return generic_fail()


# ======================================================== H5: JSON PG =====
# POST /h/pg-jsonb {"s":"x"} -> data->>'s sink.


@app.post("/h/pg-jsonb")
async def h5_json_pg(request: Request) -> Any:
    g = _ban_guard(request)
    if g is not None:
        return g
    try:
        body = await request.json()
    except Exception:
        return jerr(400, {"error": "invalid json"})
    s = str(body.get("s", "")) if isinstance(body, dict) else ""
    if "=" in s and "LIKE" not in s.upper():
        _note_403(_client_ip(request))
        return jerr(400, {"error": "invalid parameter"})
    _oob_fire(s)
    try:
        # INTENTIONALLY VULNERABLE (H5) — ->> style sink via string context.
        q = text(
            f"SELECT id, username FROM users WHERE username = '{s}' ORDER BY id LIMIT 5"
        )
        with engine("pg").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"count": len(rows), "data": rows if rows else None})
    except Exception:
        return generic_fail()


# =========================================================== H6: OOB ======
# GET /h/oob?id=1 — CONSTANT response, only collab proves exfil (PG).


@app.get("/h/oob")
def h6_oob(id: str = Query(default="1")) -> Any:
    _oob_fire(id)
    try:
        # INTENTIONALLY VULNERABLE (H6) — result discarded: blind OOB.
        q = text(f"SELECT id, username FROM users WHERE id = {id} LIMIT 1")
        with engine("pg").connect() as c:
            list(c.execute(q))
        return noisy({"data": "ok"})
    except Exception:
        return noisy({"data": "ok"})


# ======================================================= H7: OOB MSSQL ====
# GET /h/oob-mssql?id=1 — CONSTANT, xp_dirtree style exfil.


@app.get("/h/oob-mssql")
def h7_oob_mssql(id: str = Query(default="1")) -> Any:
    _oob_fire(id)
    try:
        # INTENTIONALLY VULNERABLE (H7)
        q = text(f"SELECT id, username FROM users WHERE id = {id}")
        with engine("mssql").connect() as c:
            list(c.execute(q))
        return noisy({"data": "ok"})
    except Exception:
        return noisy({"data": "ok"})


# ======================================================= H8: stacked ======
# POST /h/login-stack (form user/pass) — MSSQL stacked, rate-limited.
# Single-param ';' blocked; HPP duplicate uses last value unfiltered (see H10).


@app.post("/h/login-stack")
def h8_login_stack(
    request: Request,
    user: str = Form(default=""),
    pass_: str = Form(default="", alias="pass"),
) -> Any:
    g = _ban_guard(request)
    if g is not None:
        return g
    client = request.client.host if request.client else "?"
    if _login_limited(client):
        return jerr(429, {"error": "slow down"}, headers={"Retry-After": "1"})
    raw = f"{user} {pass_}"
    if _BLOCK_MSSQL_RE.search(raw):
        _note_403(client)
        return jerr(400, {"error": "invalid parameter"})
    _oob_fire(raw)
    try:
        # INTENTIONALLY VULNERABLE (H8)
        q = text(
            f"SELECT id, username FROM users WHERE username = '{user}' AND password = '{pass_}'"
        )
        # NOTE: seed has no password col on purpose for HARD — use username-only check below.
        q = text(f"SELECT id, username FROM users WHERE username = '{user}'")
        with engine("mssql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        if rows:
            return noisy({"data": {"user": rows[0]["username"]}})
        return noisy({"data": None, "error": "bad credentials"})
    except Exception:
        return generic_fail()


# ================================================== H9: second-order ======
# POST /h/register stores (SAFE parameterized), GET /h/profile replays stored (VULN).


@app.post("/h/register")
async def h9_register(request: Request) -> Any:
    g = _ban_guard(request)
    if g is not None:
        return g
    try:
        body = await request.json()
    except Exception:
        return jerr(400, {"error": "invalid json"})
    nick = str(body.get("nick", "")) if isinstance(body, dict) else ""
    bio = str(body.get("bio", "")) if isinstance(body, dict) else ""
    if not nick or len(nick) > 200:
        return jerr(400, {"error": "invalid nick"})
    try:
        with engine("mysql").connect() as c:
            c.execute(
                text("INSERT INTO profiles (nick, bio) VALUES (:nick, :bio)"),
                {"nick": nick, "bio": bio},
            )
            c.commit()
        return noisy({"status": "registered"})
    except Exception:
        return generic_fail()


@app.get("/h/profile")
def h9_profile(u: str = Query(default="alice")) -> Any:
    try:
        with engine("mysql").connect() as c:
            # Step 1 SAFE: parameterized lookup.
            row = c.execute(
                text("SELECT nick FROM profiles WHERE nick = :u LIMIT 1"), {"u": u}
            ).first()
            if row is None:
                return noisy({"data": None, "error": "no such profile"})
            stored_nick = row._mapping["nick"]
            # Step 2 VULN: stored value replayed unsanitized (second-order sink).
            q = text(
                f"SELECT id, username, email FROM users WHERE username = '{stored_nick}' LIMIT 5"
            )  # INTENTIONALLY VULNERABLE (H9)
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"data": rows if rows else None})
    except Exception:
        return generic_fail()


# ================================================== H10: time-tarpit ======
# GET /h/slow?q=alice — PG pg_sleep drowned in jitter.


@app.get("/h/slow")
def h10_slow(q: str = Query(default="alice")) -> Any:
    if "=" in q and "LIKE" not in q.upper():
        return jerr(400, {"error": "invalid parameter"})
    _oob_fire(q)
    try:
        # INTENTIONALLY VULNERABLE (H10)
        qy = text(
            f"SELECT id, username FROM users WHERE username = '{q}' ORDER BY id LIMIT 5"
        )
        with engine("pg").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(qy)]
        return noisy({"count": len(rows), "data": rows if rows else None})
    except Exception:
        return generic_fail()


# =================================================== H11: gauntlet ========
# GET /h/gauntlet?id=1 — spaces-signatures + /**/ + /*!*/ blocked.
# Requires tab/newline/dash whitespace + encoding chain.


@app.get("/h/gauntlet")
def h11_gauntlet(id: str = Query(default="1"), request: Request = None) -> Any:  # type: ignore[no-untyped-def]
    if request is not None:
        g = _ban_guard(request)
        if g is not None:
            return g
    if _SIG_SPACES_RE.search(id) or _COMMENT_RE.search(id):
        if request is not None:
            _note_403(_client_ip(request))
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (H11)
        q = text(f"SELECT id, username, email FROM users WHERE id = {id} LIMIT 5")
        with engine("mysql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"data": rows if rows else None})
    except Exception:
        return generic_fail()


# ====================================================== H12: HPP-only =====
# GET /h/hpp?id=1 — single param filtered; ?id=1&id=PAYLOAD uses last raw.
# Tests --hpp: WAF sees first id=1, backend takes last.


@app.get("/h/hpp")
def h12_hpp(request: Request) -> Any:
    g = _ban_guard(request)
    if g is not None:
        return g
    raw_qs = urllib.parse.parse_qsl(request.url.query, keep_blank_values=True)
    ids = [v for (k, v) in raw_qs if k == "id"]
    if not ids:
        return jerr(400, {"error": "missing id"})
    if len(ids) == 1:
        single = ids[0]
        if _SIG_SPACES_RE.search(single):
            _note_403(_client_ip(request))
            return jerr(400, {"error": "invalid parameter"})
        effective = single
    else:
        # HPP: first value is what a naive WAF normalizes; backend uses last.
        effective = ids[-1]
    _oob_fire(effective)
    try:
        # INTENTIONALLY VULNERABLE (H12)
        q = text(
            f"SELECT id, username, email FROM users WHERE id = {effective} LIMIT 5"
        )
        with engine("mysql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"data": rows if rows else None})
    except Exception:
        return generic_fail()


# ================================================= H13: ORM-raw ==========


@app.get("/h/orm")
def h13_orm(filter: str = Query(default="alice")) -> Any:
    # Simulates ORM escape hatch: whereRaw(f"...{filter}") with no filter.
    _oob_fire(filter)
    try:
        # INTENTIONALLY VULNERABLE (H13)
        q = text(
            f"SELECT id, username, email FROM users WHERE username = '{filter}' LIMIT 5"
        )
        with engine("mysql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"count": len(rows), "data": rows if rows else None})
    except Exception:
        return generic_fail()


# ================================================= H14: whoami =============
# GET /h/whoami?db=pg&id=1 — same shape on 4 engines, versions masked.


@app.get("/h/whoami")
def h14_whoami(db: str = Query(default="mysql"), id: str = Query(default="1")) -> Any:
    eng = db if db in ("mysql", "pg", "mssql") else "mysql"
    if _SIG_SPACES_RE.search(id):
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (H14)
        q = text(f"SELECT id, username FROM users WHERE id = {id} LIMIT 5")
        with engine(eng).connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        # No version/banner leak: shape identical across DBMS by design.
        return noisy({"db": eng, "data": rows if rows else None})
    except Exception:
        return generic_fail()


# ================================================= H15: dump ================


@app.get("/h/dump")
def h15_dump(id: str = Query(default="1")) -> Any:
    if _SIG_SPACES_RE.search(id):
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (H15) — secret reflected for --extract drills.
        q = text(f"SELECT id, username, secret FROM users WHERE id = {id} LIMIT 5")
        with engine("mysql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"data": rows if rows else None})
    except Exception:
        return generic_fail()


# ------------------------------------------------------- negative controls --
# N3: parameterized JSON — any finding = FP.


@app.post("/h/health-json")
async def n3_health_json(request: Request) -> Any:
    try:
        body = await request.json()
    except Exception:
        return jerr(400, {"error": "invalid json"})
    uid = 1
    try:
        uid = int(str(body.get("id", 1))) if isinstance(body, dict) else 1
    except Exception:
        uid = 1
    try:
        with engine("mysql").connect() as c:
            row = c.execute(
                text("SELECT id, username FROM users WHERE id = :id LIMIT 1"),
                {"id": uid},
            ).first()
        return noisy({"status": "ok", "data": dict(row._mapping) if row else None})
    except Exception:
        return generic_fail()


# N4: parameterized echo of input length only.


@app.get("/h/echo-len")
def n4_echo_len(id: str = Query(default="1")) -> Any:
    try:
        with engine("mysql").connect() as c:
            c.execute(
                text("SELECT id FROM users WHERE id = :id LIMIT 1"), {"id": id}
            ).first()
        return noisy({"status": "ok", "input_len": len(id)})
    except Exception:
        return generic_fail()


# N5: honeypot — bans fast, any finding = FP.


@app.get("/h/honeypot")
def n5_honeypot(id: str = Query(default="1"), request: Request = None) -> Any:  # type: ignore[no-untyped-def]
    if request is not None:
        ip = _client_ip(request)
        if _is_banned(ip):
            return jerr(429, {"error": "banned"}, headers={"Retry-After": "60"})
        # Honeypot trips ban after 3 suspicious hits (stricter than global 10).
        if any(s in id for s in ("'", '"', "OR", "or", "UNION", "union", "--")):
            dq = _F403[f"honeypot:{ip}"]
            dq.append(time.monotonic())
            if len(dq) >= 3:
                _BANNED[ip] = time.monotonic() + 300.0
                return jerr(
                    429, {"error": "banned: honeypot"}, headers={"Retry-After": "60"}
                )
            _note_403(ip)
            return jerr(400, {"error": "invalid parameter"})
    try:
        with engine("mysql").connect() as c:
            c.execute(
                text("SELECT id FROM users WHERE id = :id LIMIT 1"), {"id": id}
            ).first()
        return noisy({"status": "ok"})
    except Exception:
        return generic_fail()


@app.get("/")
def root() -> Any:
    return noisy({"status": "lab-hard full-2026"})
