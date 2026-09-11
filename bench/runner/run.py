#!/usr/bin/env python3
"""bench/runner/run.py — Phase 1 reproducible runner (stdlib only).

Usage (from bench/):
  python3 runner/run.py reset                        # reseed all 3 DBs
  python3 runner/run.py check-canary                 # verify tripwire rows
  python3 runner/run.py run --tool injekt --scenario A1 [--mode power|stealth]
  python3 runner/run.py pin                          # freeze digests/versions -> versions.lock
  python3 runner/run.py versions                     # print tool versions (no docker needed)
  python3 runner/run.py compare --baseline B --candidate C
  python3 runner/run.py matrix [--history reports/history.jsonl]
  python3 runner/selftest.py                         # offline smoke test (no docker)

Official results run on a dedicated runner; local runs are for development.
sqlmap/ghauri live-run wiring is Phase 1b (parsers implemented, raw logs kept,
history/compare/matrix already tool-agnostic).

Exit codes:
  0  success / no regression
  1  `compare` found a regression (candidate missed a baseline detection)
  2  spec/load error (unknown scenario, bad compare spec, missing history)
  3  canary TRIPPED — destructive payloads detected, `run` REJECTED
     (summary + history rows are still written for forensics, with
     `canary_intact: false`; the non-zero exit is the rejection signal)
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shlex
import subprocess
import sys
import time
import tomllib
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
REPORTS = os.path.join(BENCH, "reports")
RAWDIR = os.path.join(REPORTS, "raw")
HISTORY = os.path.join(REPORTS, "history.jsonl")
MYSQL_ROOT = ("mysql", "-h127.0.0.1", "-uroot", "-prootpw")
MSSQL_PW = "Bench-P4ssw0rd!"

# Per-scenario flag overrides so the harness, not luck, stays under the
# A3 rate-limit (~5/s per IP). Everything else uses the mode defaults.
SCENARIO_FLAGS = {
    "A3": {
        "power": ["--threads", "4", "--rate-limit", "4"],
        "stealth": ["--threads", "2", "--rate-limit", "3"],
    }
}

MODES = {
    # power: detection/speed, OPSEC handicap neutralised.
    "power": [
        "--threads",
        "10",
        "--jitter",
        "200,100",
        "--rate-limit",
        "20",
        "--level",
        "3",
        "--techniques",
        "boolean,error,time,stacked",
    ],
    # stealth: discretion, stock tool behaviour.
    "stealth": [
        "--threads",
        "2",
        "--jitter",
        "1200,400",
        "--rate-limit",
        "3",
        "--level",
        "1",
        "--techniques",
        "boolean,error",
    ],
}

# Engine log counter, e.g. "engine done ... requests=123". Independent channel
# from the JSON report's `request_count` (log line vs serialized field), used
# by cross_check_requests(). Both originate engine-side, so this catches
# serialization/stale-file bugs — not engine miscounts. The official runner
# cross-checks against WAF/nginx access logs (see README).
ENGINE_REQUESTS_RE = re.compile(r"requests=(\d+)")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def dk(*args: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
    """Run `docker ...` with the docker group (tool shells may lack it).

    Goes through `newgrp docker` with the command as stdin script, so no
    sudo/sg needed. Returns the inner command's result.
    """
    script = f"cd {shlex.quote(BENCH)} && exec " + shlex.join(["docker", *args]) + "\n"
    return subprocess.run(
        ["newgrp", "docker"], input=script, capture_output=True, text=True, env=env
    )


def compose(*args: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
    return dk("compose", *args, env=env)


def load_scenarios() -> dict:
    with open(os.path.join(HERE, "scenarios.toml"), "rb") as f:
        return tomllib.load(f)


def utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def sanitize_version(raw: str, limit: int = 200) -> str:
    """One-line, ANSI-free version string for versions.lock / history."""
    one_line = " ".join(ANSI_RE.sub("", raw).split())
    return one_line[:limit].strip()


# ------------------------------------------------------------------ DB ops --


def reset() -> None:
    print("[reset] mysql ...")
    # Pipe via shell redirection inside the newgrp script (stdin is taken).
    script = (
        f"cd {shlex.quote(BENCH)} && "
        "docker compose exec -T mysql mysql -uroot -prootpw < db/mysql/seed.sql\n"
    )
    r = subprocess.run(
        ["newgrp", "docker"], input=script, capture_output=True, text=True
    )
    print("  rc =", r.returncode, (r.stdout or "")[-200:], (r.stderr or "")[-300:])
    print("[reset] postgres ...")
    env = dict(os.environ, PGPASSWORD="bench")
    r = compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "bench",
        "-d",
        "bench",
        "-q",
        "-f",
        "/docker-entrypoint-initdb.d/01-seed.sql",
        env=env,
    )
    print("  rc =", r.returncode, (r.stderr or "")[-300:])
    print("[reset] mssql ...")
    r = compose(
        "exec",
        "-T",
        "mssql",
        "/opt/mssql-tools18/bin/sqlcmd",
        "-S",
        "localhost",
        "-U",
        "sa",
        "-P",
        MSSQL_PW,
        "-C",
        "-i",
        "/seed/seed.sql",
        env=env,
    )
    print("  rc =", r.returncode, (r.stdout or "")[-300:], (r.stderr or "")[-300:])


def canary_intact(trip: dict[str, str]) -> bool:
    """Pure canary verdict: every DB marker must read exactly 'untouched'.

    Empty/missing markers (docker down, query failed) count as tripped:
    a run whose non-destructiveness cannot be proven is rejected.
    """
    return bool(trip) and all(v == "untouched" for v in trip.values())


def run_verdict(summary: dict) -> int:
    """Exit code for a finished `run` summary: 3 when any repeat tripped the
    canary (run REJECTED), else 0. History/summary rows are kept for forensics;
    the non-zero exit is the rejection signal (C1 canary bloquant)."""
    for arm in (summary.get("arms") or {}).values():
        for r in arm.get("repeats", []):
            if not r.get("canary_intact", False):
                return 3
    return 0


def canary() -> dict[str, str]:
    out: dict[str, str] = {}
    r = compose(
        "exec",
        "-T",
        "mysql",
        "mysql",
        "-uroot",
        "-prootpw",
        "-N",
        "-e",
        "SELECT marker FROM bench.canary WHERE id=1",
    )
    out["mysql"] = r.stdout.strip()
    env = dict(os.environ, PGPASSWORD="bench")
    r = compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "bench",
        "-d",
        "bench",
        "-tA",
        "-c",
        "SELECT marker FROM canary WHERE id=1",
        env=env,
    )
    out["postgres"] = r.stdout.strip()
    r = compose(
        "exec",
        "-T",
        "mssql",
        "/opt/mssql-tools18/bin/sqlcmd",
        "-S",
        "localhost",
        "-U",
        "sa",
        "-P",
        MSSQL_PW,
        "-C",
        "-d",
        "bench",
        "-h-1",
        "-Q",
        "SET NOCOUNT ON; SELECT marker FROM canary WHERE id=1;",
        env=env,
    )
    out["mssql"] = r.stdout.strip()
    return out


# ------------------------------------------------------------------- tools --


def injekt_bin() -> list[str]:
    explicit = os.environ.get("INJEKT_BIN")
    if explicit:
        return [explicit]
    release = os.path.join(BENCH, "..", "target", "release", "injekt")
    if os.path.exists(release):
        return [release]
    return [
        "cargo",
        "run",
        "-q",
        "--manifest-path",
        os.path.join(BENCH, "..", "Cargo.toml"),
        "--",
    ]


_SEED_SUPPORT: dict[str, bool] = {}


def injekt_supports_seed() -> bool:
    """Probe once per process whether the injekt binary accepts `--seed`.

    The flag is provenance-only until the scheduler consumes it; old binaries
    predate it, so the harness omits it (with a warning) instead of failing.
    """
    key = " ".join(injekt_bin())
    if key not in _SEED_SUPPORT:
        try:
            r = subprocess.run(
                injekt_bin() + ["--help"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            _SEED_SUPPORT[key] = "--seed" in (r.stdout or "")
        except (OSError, subprocess.TimeoutExpired):
            _SEED_SUPPORT[key] = False
    return _SEED_SUPPORT[key]


def tool_version(name: str) -> str:
    """Best-effort one-line version for history.jsonl / pin / versions."""
    cmds = {
        # --version prints `injekt x.y.z` (one line). `info` is human/ANSI
        # output and must NOT be used here (it produced the garbage
        # `tool:injekt` line in versions.lock before the C1 fix).
        "injekt": injekt_bin() + ["--version"],
        "sqlmap": ["sqlmap", "--version"],
        "ghauri": ["ghauri", "--version"],
    }
    cmd = cmds.get(name)
    if cmd is None:
        return f"(unknown tool: {name})"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        ver = sanitize_version((r.stdout or "") + " " + (r.stderr or ""))
        return ver or "(empty version output)"
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"(unavailable: {e})"


def run_injekt(
    scen: dict,
    mode: str,
    out_path: str,
    timeout_s: int,
    extra: list[str] | None = None,
    seed: int | None = None,
) -> dict:
    # injekt requires --output as a RELATIVE path; run with cwd=BENCH.
    rel_out = os.path.relpath(out_path, BENCH)
    cmd = injekt_bin() + [
        "--no-banner",
        "--allow-private",
        "--force",  # reproducible harness: overwrite per-repeat reports
        "--target",
        scen["url"],
        "--output",
        rel_out,
    ]
    if seed is not None:
        if injekt_supports_seed():
            cmd += ["--seed", str(seed)]
        else:
            print(
                "[warn] injekt binary predates --seed; "
                f"recording seed={seed} as provenance only",
                file=sys.stderr,
            )
    if scen.get("method"):
        cmd += ["--method", scen["method"]]
    if scen.get("data"):
        cmd += ["--data", scen["data"]]
    if scen.get("cookies"):
        cmd += ["--cookies", scen["cookies"]]
    if scen.get("headers"):
        cmd += ["--headers", scen["headers"]]
    sink = scen.get("sink", "")
    if sink.startswith("cookie:"):
        cmd += ["--params", f"cookie:{sink.split(':', 1)[1]}"]
    elif sink.startswith("header:"):
        cmd += ["--params", f"header:{sink.split(':', 1)[1]}"]
    mode_flags = list(MODES[mode])
    scen_override = SCENARIO_FLAGS.get(scen["id"], {}).get(mode, [])
    if scen_override:
        # Overrides replace mode values (clap rejects duplicate flags).
        drop = set()
        it = iter(range(0, len(scen_override), 2))
        for i in it:
            drop.add(scen_override[i])
        filtered = []
        skip_next = False
        for j, tok in enumerate(mode_flags):
            if skip_next:
                skip_next = False
                continue
            if tok in drop:
                skip_next = True
                continue
            filtered.append(tok)
        mode_flags = filtered
    cmd += mode_flags
    cmd += list(extra or [])
    print("[run]", " ".join(cmd))
    t0 = time.monotonic()
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, cwd=BENCH
        )
        dt = time.monotonic() - t0
        return {
            "rc": r.returncode,
            "elapsed_s": round(dt, 1),
            "stdout": r.stdout,
            "stderr": r.stderr,
            "stdout_tail": r.stdout[-2000:],
            "stderr_tail": r.stderr[-2000:],
            "timeout": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "rc": None,
            "elapsed_s": timeout_s,
            "stdout": "",
            "stderr": "TIMEOUT",
            "stdout_tail": "",
            "stderr_tail": "TIMEOUT",
            "timeout": True,
        }


def parse_injekt_report(path: str) -> dict:
    try:
        with open(path) as f:
            rep = json.load(f)
    except (OSError, ValueError) as e:
        return {
            "detected": False,
            "techniques": [],
            "params": [],
            "dbms": [],
            "confidence": None,
            "request_count": None,
            "elapsed_s": None,
            "parse_error": str(e),
        }
    findings = rep.get("findings", []) or []
    confs = [f.get("confidence") for f in findings]
    confs = [c for c in confs if isinstance(c, (int, float))]
    return {
        "detected": bool(findings),
        "techniques": sorted({f.get("technique", "?") for f in findings}),
        "params": sorted({f.get("parameter", "?") for f in findings}),
        "dbms": sorted({str(f.get("dbms", "?")) for f in findings}),
        "confidence": max(confs) if confs else None,
        "request_count": rep.get("request_count"),
        # The JSON report carries no timing; the caller fills elapsed_s from
        # the wall clock (run_injekt's `elapsed_s`). Key present so all three
        # parsers share one normalized shape.
        "elapsed_s": None,
    }


# ------------------------------------------------- sqlmap/ghauri parsers --

# sqlmap technique labels ("Type:" lines) -> normalized technique names.
_SQLMAP_TECHNIQUES = [
    ("boolean-based blind", "boolean"),
    ("error-based", "error"),
    ("time-based blind", "time"),
    ("union query", "union"),
    ("stacked queries", "stacked"),
    ("inline query", "inline"),
]

# Positive detection markers (sqlmap core; ghauri mirrors this wording).
_POSITIVE_MARKERS = [
    "sqlmap identified the following injection point(s)",
    "ghauri identified the following injection point(s)",
]
# Definitive negative marker. Weaker "might not be injectable" heuristics are
# NOT treated as negative (they appear alongside later positive findings).
_NEGATIVE_MARKER = "all tested parameters do not appear to be injectable"

_PARAM_RE = re.compile(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)")
_DBMS_RES = [
    re.compile(r"the back-end DBMS is ([^\n\[\]]+)"),
    re.compile(r"back-end DBMS:\s*'?([^'\n]+)'?"),
    re.compile(r"DBMS:\s*([A-Za-z][\w ]+)"),
]


def _parse_sqlmap_style(text: str, tool: str) -> dict:
    """Shared parser for sqlmap-style stdout logs (sqlmap + ghauri).

    ghauri deliberately mirrors sqlmap's output (`Parameter:` / `Type:` /
    `Title:` / `Payload:` / `the back-end DBMS is ...`), so one core covers
    both; if upstream wording drifts, the kept raw logs are the fix source.
    Neither tool prints a numeric confidence or a total HTTP request count in
    normal output, so those stay None (same keys, null values — shape holds).
    Request counts come from `run --tool injekt` reports, or in future wiring
    from sqlmap's `-t` traffic file; see README.
    """
    lowered = text.lower()
    techniques: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(("type:", "title:")):
            low = stripped.lower()
            for needle, norm in _SQLMAP_TECHNIQUES:
                if needle in low:
                    techniques.add(norm)
    params: set[str] = set()
    for m in _PARAM_RE.finditer(text):
        name, place = m.group(1).strip(), m.group(2).strip().lower()
        if name and name.lower() != "none":
            params.add(f"{name}@{place}")
    dbms: list[str] = []
    for rx in _DBMS_RES:
        m = rx.search(text)
        if m:
            val = " ".join(m.group(1).strip().rstrip(".,").split())
            if val:
                dbms = [val]
                break
    positive = any(m in lowered for m in _POSITIVE_MARKERS) or bool(techniques)
    negative = _NEGATIVE_MARKER in lowered
    return {
        "detected": bool(positive and not (negative and not techniques)),
        "techniques": sorted(techniques),
        "params": sorted(params),
        "dbms": dbms,
        "confidence": None,
        "request_count": None,
        "elapsed_s": None,
        "tool": tool,
    }


def parse_sqlmap(text: str) -> dict:
    """Parse sqlmap stdout log text into the normalized result shape."""
    return _parse_sqlmap_style(text, "sqlmap")


def parse_ghauri(text: str) -> dict:
    """Parse ghauri stdout log text into the normalized result shape."""
    return _parse_sqlmap_style(text, "ghauri")


# ------------------------------------------------------- request x-check --


def cross_check_requests(stdout_full: str, report_count) -> dict:
    """Compare the engine log counter (`requests=N`) with the JSON report.

    Returns {"engine_requests", "report_requests", "match", "note"} where
    match is True/False, or None when the engine line is absent (old binary,
    timeout, crash) — then the check is *skipped*, never failed silently.

    NOTE: engine logs carry ANSI escapes around the `=` (tracing formats
    `requests` + key-color + `=` + value-color + `123`), so the log is
    sanitized before matching — a bare requests-equals-digits regex misses
    real log lines.
    """
    clean = ANSI_RE.sub("", stdout_full or "")
    m = ENGINE_REQUESTS_RE.search(clean)
    engine = int(m.group(1)) if m else None
    if engine is None:
        return {
            "engine_requests": None,
            "report_requests": report_count,
            "match": None,
            "note": "skipped: no engine requests=N counter in log",
        }
    if not isinstance(report_count, int):
        return {
            "engine_requests": engine,
            "report_requests": report_count,
            "match": None,
            "note": "skipped: report request_count missing/unparsable",
        }
    if engine != report_count:
        return {
            "engine_requests": engine,
            "report_requests": report_count,
            "match": False,
            "note": f"MISMATCH: engine log requests={engine} != "
            f"report request_count={report_count}",
        }
    return {
        "engine_requests": engine,
        "report_requests": report_count,
        "match": True,
        "note": "ok",
    }


# ------------------------------------------------------------- history --


def append_history(entry: dict, path: str = HISTORY) -> str:
    """Append one JSON line to the history file (creating dirs as needed)."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return path


def load_history_rows(path: str) -> list[dict]:
    """Read a history.jsonl file, skipping blanks; warn on corrupt lines."""
    rows: list[dict] = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError as e:
                print(
                    f"[warn] {path}:{lineno}: skipping corrupt line ({e})",
                    file=sys.stderr,
                )
    return rows


def rows_from_summary(summary: dict) -> list[dict]:
    """Expand a `run` summary JSON (with arms/repeats) into history-like rows.

    Lets `compare` diff old summary files that predate history.jsonl.
    """
    rows: list[dict] = []
    for arm, s in (summary.get("arms") or {}).items():
        for r in s.get("repeats", []):
            rows.append(
                {
                    "ts": summary.get("ts", ""),
                    "run_id": summary.get("run_id", ""),
                    "tool": summary.get("tool", ""),
                    "tool_version": summary.get("tool_version", ""),
                    "scenario": summary.get("scenario", ""),
                    "mode": summary.get("mode", ""),
                    "arm": arm,
                    "repeat": r.get("repeat"),
                    "seed": r.get("seed"),
                    "result": {
                        "detected": r.get("detected", False),
                        "techniques": r.get("techniques", []),
                        "params": r.get("params", []),
                        "dbms": r.get("dbms", []),
                        "confidence": r.get("confidence"),
                        "request_count": r.get("request_count"),
                        "elapsed_s": r.get("elapsed_s"),
                        "rc": r.get("rc"),
                    },
                    "report": r.get("report", ""),
                    "canary_intact": r.get("canary_intact"),
                }
            )
    return rows


def resolve_spec(spec: str, history_path: str) -> tuple[list[dict], str]:
    """Resolve a compare spec: existing file, else a run-id prefix in history.

    Returns (rows, label). Raises FileNotFoundError / ValueError on failure.
    """
    if os.path.isfile(spec):
        if spec.endswith(".summary.json"):
            with open(spec) as f:
                return rows_from_summary(json.load(f)), spec
        return load_history_rows(spec), spec
    if not os.path.isfile(history_path):
        raise FileNotFoundError(
            f"spec {spec!r} is not a file and history {history_path!r} "
            "does not exist (cannot resolve as run-id)"
        )
    rows = [
        r
        for r in load_history_rows(history_path)
        if str(r.get("run_id", "")).startswith(spec)
    ]
    if not rows:
        raise ValueError(
            f"spec {spec!r} matches no file and no run_id in {history_path!r}"
        )
    return rows, f"{history_path} [run_id^={spec}] ({len(rows)} runs)"


def _avg(vals: list) -> float | None:
    nums = [v for v in vals if isinstance(v, (int, float))]
    if not nums:
        return None
    return sum(nums) / len(nums)


def _fmt(v, width: int = 0, digits: int = 1) -> str:
    if v is None:
        s = "-"
    elif isinstance(v, float):
        s = f"{v:.{digits}f}"
    else:
        s = str(v)
    return s.rjust(width) if width else s


def aggregate(rows: list[dict]) -> dict[tuple, dict]:
    """Group history rows by (scenario, mode, arm) with detection/avg stats."""
    groups: dict[tuple, dict] = {}
    for r in rows:
        res = r.get("result", {}) or {}
        key = (r.get("scenario", "?"), r.get("mode", "?"), r.get("arm", "?"))
        g = groups.setdefault(key, {"n": 0, "detected_n": 0, "reqs": [], "elapsed": []})
        g["n"] += 1
        if res.get("detected"):
            g["detected_n"] += 1
        if isinstance(res.get("request_count"), (int, float)):
            g["reqs"].append(res["request_count"])
        if isinstance(res.get("elapsed_s"), (int, float)):
            g["elapsed"].append(res["elapsed_s"])
    for g in groups.values():
        g["detected_any"] = g["detected_n"] > 0
        g["avg_req"] = _avg(g["reqs"])
        g["avg_elapsed"] = _avg(g["elapsed"])
    return groups


def cmd_compare(baseline: str, candidate: str, history_path: str) -> int:
    try:
        base_rows, base_label = resolve_spec(baseline, history_path)
    except (FileNotFoundError, ValueError, OSError) as e:
        print(f"compare: baseline error: {e}", file=sys.stderr)
        return 2
    try:
        cand_rows, cand_label = resolve_spec(candidate, history_path)
    except (FileNotFoundError, ValueError, OSError) as e:
        print(f"compare: candidate error: {e}", file=sys.stderr)
        return 2
    base = aggregate(base_rows)
    cand = aggregate(cand_rows)
    print(f"baseline : {base_label} ({len(base_rows)} runs)")
    print(f"candidate: {cand_label} ({len(cand_rows)} runs)")
    print(
        f"{'scenario':<9}{'mode/arm':<17}{'base_det':<9}{'cand_det':<9}"
        f"{'base_req':>9}{'cand_req':>9}{'base_t':>8}{'cand_t':>8}  verdict"
    )
    regressions: list[str] = []
    fp_warns: list[str] = []
    for key in sorted(set(base) | set(cand)):
        scen, mode, arm = key
        b, c = base.get(key, {}), cand.get(key, {})
        b_det = b.get("detected_any", False) if b else False
        c_det = c.get("detected_any", False) if c else False
        b_n, c_n = b.get("n", 0), c.get("n", 0)
        if b and c:
            if b_det and not c_det:
                verdict = "REGRESSION"
                regressions.append(f"{scen} {mode}/{arm}")
            elif c_det and not b_det:
                verdict = "IMPROVED"
            elif b_det and c_det:
                verdict = "OK"
            else:
                verdict = "SAME-MISS"
        elif b:
            verdict = "BASE-ONLY"
            if b_det:
                verdict = "REGRESSION(missing)"
                regressions.append(f"{scen} {mode}/{arm} (absent in candidate)")
        else:
            verdict = "CAND-ONLY"
        print(
            f"{scen:<9}{mode + '/' + arm:<17}"
            f"{('YES' if b_det else 'no') + (f'({b_n})' if b else ''):<9}"
            f"{('YES' if c_det else 'no') + (f'({c_n})' if c else ''):<9}"
            f"{_fmt(b.get('avg_req'), 9)}{_fmt(c.get('avg_req'), 9)}"
            f"{_fmt(b.get('avg_elapsed'), 8)}{_fmt(c.get('avg_elapsed'), 8)}"
            f"  {verdict}"
        )
        if scen.startswith("N") and c_det:
            fp_warns.append(
                f"[warn] {scen} {mode}/{arm}: candidate reports a finding on "
                "a negative control (false positive)"
            )
    for w in fp_warns:
        print(w, file=sys.stderr)
    if regressions:
        print(
            f"result: REGRESSION — candidate missed {len(regressions)} "
            f"scenario(s): {', '.join(regressions)} (exit 1)"
        )
        return 1
    print("result: no regression (exit 0)")
    return 0


def cmd_matrix(history_path: str, mode: str | None, tools: list[str]) -> int:
    if not os.path.isfile(history_path):
        print(
            f"matrix: history {history_path!r} not found — run "
            "`run.py run --scenario ...` first (it appends to history.jsonl)",
            file=sys.stderr,
        )
        return 2
    rows = load_history_rows(history_path)
    if mode:
        rows = [r for r in rows if r.get("mode") == mode]
    if tools:
        rows = [r for r in rows if r.get("tool") in tools]
    if not rows:
        print("matrix: no rows after filtering (exit 2)", file=sys.stderr)
        return 2
    by_tool: dict[str, list[dict]] = {}
    for r in rows:
        by_tool.setdefault(r.get("tool", "?"), []).append(r)
    filt = f" (mode={mode})" if mode else ""
    print(f"matrix from {history_path}{filt}: {len(rows)} runs")
    print(
        f"{'tool':<9}{'scenarios':<11}{'detected':<11}{'repeats':<11}"
        f"{'avg_req':>9}{'avg_time_s':>11}"
    )
    for tool in sorted(by_tool):
        trows = by_tool[tool]
        scen_ids = sorted({r.get("scenario", "?") for r in trows})
        det_scens = sorted(
            {
                r.get("scenario", "?")
                for r in trows
                if (r.get("result") or {}).get("detected")
            }
        )
        det_rep = sum(1 for r in trows if (r.get("result") or {}).get("detected"))
        print(
            f"{tool:<9}{len(scen_ids):<11}{str(f'{len(det_scens)}/{len(scen_ids)}'):<11}"
            f"{str(f'{det_rep}/{len(trows)}'):<11}"
            f"{_fmt(_avg([(r.get('result') or {}).get('request_count') for r in trows]), 9)}"
            f"{_fmt(_avg([(r.get('result') or {}).get('elapsed_s') for r in trows]), 11)}"
        )
        print(
            f"  scenarios: {','.join(scen_ids)} detected: {','.join(det_scens) or '-'}"
        )
    return 0


# --------------------------------------------------------------------- pin --


def pin() -> None:
    images = [
        "mysql:8.4",
        "postgres:17-alpine",
        "mcr.microsoft.com/mssql/server:2022-latest",
        "owasp/modsecurity-crs:nginx",
    ]
    lines = [
        "# bench/versions.lock — frozen official-run references.\n",
        f"# pinned_at {utc_now()} (UTC). Regenerate: python3 runner/run.py pin\n",
    ]
    for img in images:
        r = dk("image", "inspect", img, "--format", "{{.RepoDigests}}")
        lines.append(f"{img}  {r.stdout.strip() or '(not pulled)'}\n")
    for name in ("injekt", "sqlmap", "ghauri"):
        lines.append(f"tool:{name}  {tool_version(name)}\n")
    with open(os.path.join(BENCH, "versions.lock"), "w") as f:
        f.writelines(lines)
    print("".join(lines))


def cmd_versions() -> int:
    """Print all 3 tool versions (live probe, no docker, no file write)."""
    for name in ("injekt", "sqlmap", "ghauri"):
        print(f"tool:{name}  {tool_version(name)}")
    return 0


# -------------------------------------------------------------------- main --


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("reset")
    sub.add_parser("check-canary")
    sub.add_parser("pin")
    sub.add_parser(
        "versions",
        help="print live tool versions (no docker, no file write)",
    )
    p = sub.add_parser("run")
    p.add_argument("--tool", default="injekt", choices=["injekt"])
    p.add_argument("--scenario", required=True)
    p.add_argument("--mode", default="power", choices=list(MODES))
    p.add_argument(
        "--repeats",
        type=int,
        default=None,
        help="repeats per arm (default: scenarios.toml [defaults] repeats, now 5)",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="base deterministic seed; repeat i uses base+i "
        "(default: scenarios.toml [defaults] seed). Passed as injekt --seed "
        "when the binary supports it, always recorded as provenance.",
    )
    p.add_argument(
        "--history",
        default=HISTORY,
        help="history.jsonl path to append per-repeat lines to",
    )
    p.add_argument("--arm", default="all", choices=["all", "stock", "evasion"])
    c = sub.add_parser(
        "compare",
        help="diff baseline vs candidate result sets; exit 1 on regression",
    )
    c.add_argument(
        "--baseline",
        required=True,
        help="history.jsonl path (or .summary.json) or run-id prefix in --history",
    )
    c.add_argument(
        "--candidate",
        required=True,
        help="history.jsonl path (or .summary.json) or run-id prefix in --history",
    )
    c.add_argument("--history", default=HISTORY)
    m = sub.add_parser(
        "matrix",
        help="compact per-tool table (detected counts, avg requests/time)",
    )
    m.add_argument("--history", default=HISTORY)
    m.add_argument("--mode", default=None, choices=list(MODES))
    m.add_argument(
        "--tool",
        action="append",
        default=[],
        help="filter to a tool; repeatable (default: all tools)",
    )
    args = ap.parse_args()

    if args.cmd == "reset":
        reset()
        return 0
    if args.cmd == "check-canary":
        trip = canary()
        print(json.dumps(trip, indent=2))
        if not canary_intact(trip):
            print(
                "[FAIL] canary TRIPPED — run invalid (exit 3)",
                file=sys.stderr,
            )
            return 3
        return 0
    if args.cmd == "pin":
        pin()
        return 0
    if args.cmd == "versions":
        return cmd_versions()
    if args.cmd == "compare":
        return cmd_compare(args.baseline, args.candidate, args.history)
    if args.cmd == "matrix":
        return cmd_matrix(args.history, args.mode, args.tool)

    cfg = load_scenarios()
    scen = next((s for s in cfg["scenario"] if s["id"] == args.scenario), None)
    if scen is None:
        print(f"unknown scenario {args.scenario}", file=sys.stderr)
        return 2
    repeats = args.repeats or cfg["defaults"]["repeats"]
    timeout_s = cfg["defaults"]["timeout_s"]
    seed_base = args.seed if args.seed is not None else cfg["defaults"].get("seed", 42)
    os.makedirs(REPORTS, exist_ok=True)
    os.makedirs(RAWDIR, exist_ok=True)

    run_id = f"{utc_now().replace(':', '').replace('-', '')}-{args.tool}-{scen['id']}-{args.mode}-{uuid.uuid4().hex[:8]}"
    tool_ver = tool_version(args.tool)

    arms: list[tuple[str, list[str]]] = [("stock", [])]
    if args.arm == "evasion":
        arms = []
    if scen.get("evasion") and args.arm in ("all", "evasion"):
        arms.append(("evasion", list(scen["evasion"])))
    if args.arm == "evasion" and not scen.get("evasion"):
        print(f"scenario {scen['id']} has no evasion profile", file=sys.stderr)
        return 2
    if args.arm == "stock":
        arms = [arms[0]]

    summary: dict = {
        "tool": args.tool,
        "tool_version": tool_ver,
        "scenario": scen["id"],
        "mode": args.mode,
        "run_id": run_id,
        "ts": utc_now(),
        "seed_base": seed_base,
        "expected": scen.get("expected", []),
        "negative": scen.get("negative", False),
        "arms": {},
    }
    for arm, extra in arms:
        results = []
        for i in range(repeats):
            seed = seed_base + i
            print(
                f"=== {scen['id']} {args.mode}/{arm} repeat {i + 1}/{repeats} seed={seed} ==="
            )
            reset()
            time.sleep(2)
            out = os.path.join(
                REPORTS, f"{args.tool}-{scen['id']}-{args.mode}-{arm}-r{i + 1}.json"
            )
            proc = run_injekt(scen, args.mode, out, timeout_s, extra, seed)
            parsed = parse_injekt_report(out)
            parsed["elapsed_s"] = proc["elapsed_s"]
            xcheck = cross_check_requests(
                proc.get("stdout", ""), parsed.get("request_count")
            )
            if xcheck["match"] is False:
                print(
                    f"[WARN] request_count MISMATCH on {scen['id']} "
                    f"{args.mode}/{arm} r{i + 1}: {xcheck['note']}",
                    file=sys.stderr,
                )
            trip = canary()
            intact = canary_intact(trip)
            raw_base = os.path.join(RAWDIR, f"{run_id}-{arm}-r{i + 1}")
            raw_out, raw_err = raw_base + ".stdout.log", raw_base + ".stderr.log"
            try:
                with open(raw_out, "w") as f:
                    f.write(proc.get("stdout", ""))
                with open(raw_err, "w") as f:
                    f.write(proc.get("stderr", ""))
            except OSError as e:
                print(f"[warn] could not write raw logs: {e}", file=sys.stderr)
                raw_out, raw_err = "", ""
            entry = {
                "repeat": i + 1,
                "seed": seed,
                "rc": proc["rc"],
                "elapsed_s": proc["elapsed_s"],
                "stdout_tail": proc["stdout_tail"],
                "stderr_tail": proc["stderr_tail"],
                "timeout": proc["timeout"],
                **parsed,
                "engine_requests": xcheck["engine_requests"],
                "request_count_match": xcheck["match"],
                "request_count_note": xcheck["note"],
                "report": os.path.relpath(out, BENCH),
                "raw_stdout": os.path.relpath(raw_out, BENCH) if raw_out else "",
                "raw_stderr": os.path.relpath(raw_err, BENCH) if raw_err else "",
                "canary": trip,
                "canary_intact": intact,
            }
            results.append(entry)
            append_history(
                {
                    "ts": utc_now(),
                    "run_id": run_id,
                    "tool": args.tool,
                    "tool_version": tool_ver,
                    "scenario": scen["id"],
                    "mode": args.mode,
                    "arm": arm,
                    "repeat": i + 1,
                    "seed": seed,
                    "result": {
                        "detected": parsed["detected"],
                        "techniques": parsed["techniques"],
                        "params": parsed["params"],
                        "dbms": parsed["dbms"],
                        "confidence": parsed["confidence"],
                        "request_count": parsed["request_count"],
                        "elapsed_s": proc["elapsed_s"],
                        "rc": proc["rc"],
                    },
                    "report": os.path.relpath(out, BENCH),
                    "raw_stdout": os.path.relpath(raw_out, BENCH) if raw_out else "",
                    "raw_stderr": os.path.relpath(raw_err, BENCH) if raw_err else "",
                    "canary_intact": intact,
                    "request_count_match": xcheck["match"],
                },
                args.history,
            )
            print(json.dumps(results[-1], indent=2)[:1500])
        summary["arms"][arm] = {
            "extra_flags": extra,
            "repeats": results,
            "detect_rate": sum(1 for r in results if r["detected"]) / len(results),
            "canary_intact_all": all(r["canary_intact"] for r in results),
        }

    spath = os.path.join(REPORTS, f"{args.tool}-{scen['id']}-{args.mode}.summary.json")
    with open(spath, "w") as f:
        json.dump(summary, f, indent=2)
    for arm, s in summary["arms"].items():
        print(
            f"[{arm}] detect_rate =",
            s["detect_rate"],
            "canary_intact_all =",
            s["canary_intact_all"],
        )
    print("summary ->", spath)
    print("history ->", args.history)
    verdict = run_verdict(summary)
    if verdict != 0:
        print(
            "[FAIL] canary TRIPPED — destructive payloads detected, "
            "run REJECTED (exit 3); see summary/history canary_intact=false rows",
            file=sys.stderr,
        )
    return verdict


if __name__ == "__main__":
    raise SystemExit(main())
