"""bench target app — INTENTIONALLY VULNERABLE benchmark lab (Phase 1).

DO NOT copy these query patterns into production. Every f-string interpolated
into sqlalchemy.text() below is a deliberate SQL injection sink for benchmarking
injekt vs sqlmap vs ghauri. Each sink is marked INTENTIONALLY VULNERABLE.

Hardening (what makes this target non-basic):
  * all DB errors are caught -> generic HTTP 200 envelope, no stack trace,
    no DBMS error text (error-based must fail; boolean/time must work);
  * every response carries random `request_id` + `generated_at` noise so naive
    string-compare diffing breaks (real baseline/diff required);
  * per-endpoint application filters (whitespace / `=` / case-sensitive keyword
    blocklist) force tamper usage;
  * /api/login is rate-limited (5/s per IP -> 429), testing retry/backoff;
  * /api/health + /api/canary are fully parameterized negative controls:
    any finding there is a FALSE POSITIVE;
  * `canary` table row must stay 'untouched' — runner checks it after every
    run to flag destructive payloads.
"""

from __future__ import annotations

import os
import re
import time
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
                f"mysql+pymysql://{_env('MYSQL_USER', 'bench')}:{_env('MYSQL_PASSWORD', 'bench')}"
                f"@{_env('MYSQL_HOST', 'mysql')}:{_env('MYSQL_PORT', '3306')}/{_env('MYSQL_DB', 'bench')}"
            )
        elif name == "pg":
            url = (
                f"postgresql+psycopg2://{_env('PG_USER', 'bench')}:{_env('PG_PASSWORD', 'bench')}"
                f"@{_env('PG_HOST', 'postgres')}:{_env('PG_PORT', '5432')}/{_env('PG_DB', 'bench')}"
            )
        elif name == "mssql":
            url = (
                "mssql+pyodbc://"
                f"{_env('MSSQL_USER', 'sa')}:{_env('MSSQL_PASSWORD', 'Bench-P4ssw0rd!')}"
                f"@{_env('MSSQL_HOST', 'mssql')}:{_env('MSSQL_PORT', '1433')}/{_env('MSSQL_DB', 'bench')}"
                "?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=no&TrustServerCertificate=yes"
            )
        else:  # pragma: no cover
            raise ValueError(name)
        # pool_pre_ping: DBs may still be starting when the app boots.
        _ENGINES[name] = create_engine(url, pool_pre_ping=True, pool_recycle=300)
    return _ENGINES[name]


def noisy(payload: dict[str, Any]) -> Response:
    """Wrap payload in the standard envelope with anti-naive-diff noise.

    Pretty-printed (indent=2) like a typical PHP/legacy backend: scanners
    get whitespace-separated tokens to diff. Compact single-token bodies
    would collapse whitespace-token Jaccard to 0 for EVERY response and
    prove nothing about detection quality.
    """
    body = _json.dumps(
        {
            **payload,
            "request_id": uuid.uuid4().hex[:8],
            "generated_at": time.time(),
        },
        indent=2,
    )
    return Response(content=body, media_type="application/json")


def jerr(status: int, payload: dict[str, Any], headers: dict[str, str] | None = None) -> Response:
    """Pretty-printed error envelope (block pages are whitespace-rich too)."""
    body = _json.dumps(
        {
            **payload,
            "request_id": uuid.uuid4().hex[:8],
            "generated_at": time.time(),
        },
        indent=2,
    )
    return Response(content=body, status_code=status, media_type="application/json", headers=headers)


def generic_fail() -> Response:
    # Same envelope, same HTTP 200 — no oracle for error-based techniques.
    return noisy({"data": None, "error": "query failed"})


# --------------------------------------------------------------- A1: MySQL --
# GET /api/users?id=1 — boolean/time. Naive signature filter (like a cheap
# WAF): literal ` or ` / ` and ` / ` union ` / ` select ` / `sleep(` etc.
# with SPACES, case-insensitive -> 400. `/**/` breaks the signatures while
# the baked `-- -` terminator survives intact (this is the realistic
# space2comment scenario: a raw-whitespace block would ALSO kill the
# terminator and make the sink unsolvable — deliberately not done here).

_SIG_RE = re.compile(
    r" or | and | union | select |sleep\(|benchmark\(|information_schema",
    re.IGNORECASE,
)


@app.get("/api/users")
def users(id: str = Query(default="1")) -> Any:
    if _SIG_RE.search(id):
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (A1)
        q = text(f"SELECT id, username, email FROM users WHERE id = {id} LIMIT 5")
        with engine("mysql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"data": rows})
    except Exception:
        return generic_fail()


# ------------------------------------------------------------- A2: Postgres --
# GET /api/search?q=alice — boolean blind, EQUALITY sink (exact username
# match: 1 row legit, 3 rows TRUE, 0 rows FALSE, always 200).
# App filter: `=` rejected -> forces LIKE-based exfil (equaltolike-style).
# NOTE: a LIKE '%...%' sink would make leading `LIKE '%'` always-true and
# break OR-based differentials — equality keeps TRUE/FALSE coherent.


@app.get("/api/search")
def search(q: str = Query(default="")) -> Any:
    if "=" in q:
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (A2)
        qy = text(
            f"SELECT id, username FROM users WHERE username = '{q}' ORDER BY id LIMIT 10"
        )
        with engine("pg").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(qy)]
        return noisy({"count": len(rows), "data": rows})
    except Exception:
        return generic_fail()


# ---------------------------------------------------------------- A3: MSSQL --
# POST /api/login (form user=/pass=) — boolean/stacked. Case-SENSITIVE
# blocklist: lowercase `;|sleep|benchmark|waitfor|pg_sleep` -> 400, so
# mixed-case (`WaItFoR`, `;` hidden in case tricks won't help — `;` is
# literal) ... `;` is blocked literally: stacked needs HPP/chunked or
# prefix tricks. Rate-limited 5/s per IP -> 429 (tests retry/backoff).

_BLOCK_RE = re.compile(r";|sleep|benchmark|waitfor|pg_sleep")
_HITS: dict[str, deque[float]] = defaultdict(deque)
_LOGIN_WINDOW_S = 2.0
_LOGIN_MAX_HITS = 10  # ~= 5 req/s per IP


def _login_limited(ip: str) -> bool:
    now = time.monotonic()
    dq = _HITS[ip]
    while dq and now - dq[0] > _LOGIN_WINDOW_S:
        dq.popleft()
    if len(dq) >= _LOGIN_MAX_HITS:
        return True
    dq.append(now)
    return False


@app.post("/api/login")
def login(
    request: Request,
    user: str = Form(default=""),
    pass_: str = Form(default="", alias="pass"),
) -> Any:
    client = request.client.host if request.client else "?"
    if _login_limited(client):
        return jerr(429, {"error": "slow down"}, headers={"Retry-After": "1"})
    raw = f"{user} {pass_}"
    if _BLOCK_RE.search(raw):
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (A3)
        q = text(
            f"SELECT id, username FROM users WHERE username = '{user}' AND password = '{pass_}'"
        )
        with engine("mssql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        if rows:
            return noisy({"data": {"user": rows[0]["username"]}})
        return noisy({"data": None, "error": "bad credentials"})
    except Exception:
        return generic_fail()


# ------------------------------------------------------- A4: PG via Cookie --
# GET /api/track, Cookie sess= — boolean via Cookie param.


@app.get("/api/track")
def track(sess: str | None = Cookie(default=None)) -> Any:
    if sess is None:
        return noisy({"data": None, "error": "no session"})
    if not re.fullmatch(r"[0-9A-Za-z'\" ()=/*-]+", sess):
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (A4)
        # NOTE: LIMIT 5 (not 1) so TRUE (3 rows) differs from baseline (1 row).
        q = text(f"SELECT id, username FROM users WHERE id = {sess} LIMIT 5")
        with engine("pg").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"data": rows if rows else None})
    except Exception:
        return generic_fail()


# ------------------------------------------------------ A5: MySQL via Header --
# GET /api/debug, Header X-User-Id: — boolean/error via header param.
# Numeric trust-boundary header (gateway-set user id): legit "1" yields one
# row, so the baseline is valid and TRUE/FALSE differentials are coherent.


@app.get("/api/debug")
def debug(x_user_id: str = Header(default="1", alias="X-User-Id")) -> Any:
    if _SIG_RE.search(x_user_id):
        return jerr(400, {"error": "invalid parameter"})
    try:
        # INTENTIONALLY VULNERABLE (A5)
        # NOTE: LIMIT 5 (not 1) so TRUE (3 rows) differs from baseline (1 row).
        q = text(f"SELECT id, username FROM users WHERE id = {x_user_id} LIMIT 5")
        with engine("mysql").connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        return noisy({"data": rows if rows else None})
    except Exception:
        return generic_fail()


# ------------------------------------------------------- negative controls --
# N1: fully parameterized — any finding here is a FALSE POSITIVE.


@app.get("/api/health")
def health(id: int = Query(default=1)) -> Any:
    try:
        with engine("mysql").connect() as c:
            row = c.execute(
                text("SELECT id, username FROM users WHERE id = :id LIMIT 1"),
                {"id": id},
            ).first()
        return noisy({"status": "ok", "data": dict(row._mapping) if row else None})
    except Exception:
        return generic_fail()


# N2: parameterized echo — reflects only input LENGTH (no content oracle),
# so content-based "detections" here are FPs.


@app.get("/api/canary")
def canary_probe(id: str = Query(default="1")) -> Any:
    try:
        with engine("mysql").connect() as c:
            c.execute(
                text("SELECT id FROM users WHERE id = :id LIMIT 1"), {"id": id}
            ).first()
        return noisy({"status": "ok", "input_len": len(id)})
    except Exception:
        return generic_fail()


@app.get("/")
def root() -> Any:
    return noisy({"status": "bench lab phase 1"})
