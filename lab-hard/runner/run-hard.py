#!/usr/bin/env python3
"""lab-hard/runner/run-hard.py — HARD runner full-2026 (stdlib only).

Usage (from lab-hard/):
  python3 runner/run-hard.py reset
  python3 runner/run-hard.py check-canary
  python3 runner/run-hard.py run --scenario H1 [--mode power|stealth] [--arm all|stock|evasion|hpp|oob]
  python3 runner/run-hard.py compare --baseline B --candidate C
  python3 runner/run-hard.py matrix [--history reports/history-hard.jsonl]
  python3 runner/run-hard.py versions

Mirrors bench/runner/run.py semantics: exit 0 ok, 1 compare regression,
2 spec/load error, 3 canary TRIPPED (run REJECTED, rows still written).

Ports/pw differ from bench: mysql 9360/roothardpw, pg 9432, mssql 9533,
db name `hard`. OOB scenarios (H6/H7) get an `oob` arm with
--oob-domain/--oob-poll-url; their `stock` arm (no collab flags) must fail.
H8/H12 get an `hpp` arm with --hpp.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
HARD = os.path.dirname(HERE)
REPORTS = os.path.join(HARD, "reports")
RAWDIR = os.path.join(REPORTS, "raw")
HISTORY = os.path.join(REPORTS, "history-hard.jsonl")
SCENARIOS = os.path.join(HARD, "runner", "scenarios-hard.toml")

MYSQL_ROOT_PW = "roothardpw"
MSSQL_PW = "Hard-P4ssw0rd!"
OOB_DOMAIN = "oob.labhard"
OOB_POLL = "http://127.0.0.1:9080/poll/{token}"

MODES = {
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
        "boolean,error,time,union,stacked,json",
    ],
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
# Stay under the H8 5/s per-IP rate limit regardless of mode.
SCENARIO_FLAGS = {
    "H8": {
        "power": ["--threads", "4", "--rate-limit", "4"],
        "stealth": ["--threads", "2", "--rate-limit", "3"],
    },
}

ENGINE_RE = re.compile(r"requests=(\d+)")


def sh(*args: str, cwd: str = HARD, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), cwd=cwd, capture_output=True, text=True, timeout=timeout
    )


def injekt_bin() -> list[str]:
    env = os.environ.get("INJEKT_BIN")
    if env:
        return [env]
    rel = os.path.join(HARD, "..", "target", "release", "injekt")
    if os.path.exists(rel):
        return [os.path.abspath(rel)]
    return ["cargo", "run", "-q", "--"]


_SEED_OK: bool | None = None


def injekt_supports_seed() -> bool:
    global _SEED_OK
    if _SEED_OK is None:
        try:
            p = sh(*injekt_bin(), "--help", timeout=60)
            _SEED_OK = "--seed" in (p.stdout + p.stderr)
        except Exception:
            _SEED_OK = False
    return bool(_SEED_OK)


def tool_version() -> str:
    try:
        p = sh(*injekt_bin(), "--version", timeout=60)
        out = (p.stdout + p.stderr).strip().splitlines()
        return out[0][:200] if out else "injekt unknown"
    except Exception as e:
        return f"(unavailable: {e})"


def load_scenarios() -> tuple[dict, list[dict]]:
    try:
        with open(SCENARIOS, "rb") as f:
            doc = tomllib.load(f)
    except Exception as e:
        print(f"spec/load error: {e}", file=sys.stderr)
        sys.exit(2)
    defaults = doc.get("defaults", {})
    scenarios = doc.get("scenario", [])
    return defaults, scenarios


def reset() -> int:
    cmds = [
        (
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "mysql",
                "mysql",
                "-uroot",
                f"-p{MYSQL_ROOT_PW}",
                "hard",
            ],
            "db/mysql/seed.sql",
            "mysql",
        ),
        (
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "-e",
                "PGPASSWORD=hardpw123",
                "postgres",
                "psql",
                "-U",
                "hard",
                "-d",
                "hard",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                "/docker-entrypoint-initdb.d/01-seed.sql",
            ],
            None,
            "postgres",
        ),
        (
            [
                "docker",
                "compose",
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
                "hard",
                "-i",
                "/seed/seed.sql",
            ],
            None,
            "mssql",
        ),
    ]
    rc = 0
    for base, stdin_file, label in cmds:
        try:
            inp = open(os.path.join(HARD, stdin_file)).read() if stdin_file else None
            p = subprocess.run(
                base, input=inp, cwd=HARD, capture_output=True, text=True, timeout=120
            )
            ok = p.returncode == 0
            print(f"reset {label}: {'ok' if ok else 'FAILED'}")
            if not ok:
                print(p.stdout[-2000:] + p.stderr[-2000:])
                rc = 1
        except FileNotFoundError:
            print(f"reset {label}: docker unavailable — skipping (honest skip)")
            rc = 1
        except Exception as e:
            print(f"reset {label}: {e}")
            rc = 1
    time.sleep(2)
    return rc


def _q(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, cwd=HARD, capture_output=True, text=True, timeout=30)
        return (p.stdout + p.stderr).strip()
    except Exception:
        return ""


def canary() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        seed = open(os.path.join(HARD, "db/mysql/seed.sql")).read()
        _ = seed  # keep linters quiet about unused path intent
    except Exception:
        pass
    mysql = _q(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "mysql",
            "mysql",
            "-N",
            "-uroot",
            f"-p{MYSQL_ROOT_PW}",
            "hard",
            "-e",
            "SELECT marker FROM canary WHERE id=1;",
        ]
    )
    out["mysql"] = mysql.split()[-1] if mysql else ""
    pg = _q(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "-e",
            "PGPASSWORD=hardpw123",
            "postgres",
            "psql",
            "-U",
            "hard",
            "-d",
            "hard",
            "-tA",
            "-c",
            "SELECT marker FROM canary WHERE id=1;",
        ]
    )
    out["pg"] = pg.split()[-1] if pg else ""
    ms = _q(
        [
            "docker",
            "compose",
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
            "hard",
            "-h-1",
            "-Q",
            "SET NOCOUNT ON; SELECT marker FROM canary WHERE id=1;",
        ]
    )
    out["mssql"] = ms.split()[-1] if ms else ""
    return out


def canary_intact(trip: dict[str, str]) -> bool:
    return bool(trip) and all(v == "untouched" for v in trip.values())


def cmd_canary() -> int:
    trip = canary()
    for k, v in trip.items():
        print(f"{k}: {v!r}")
    ok = canary_intact(trip)
    print("canary:", "INTACT" if ok else "TRIPPED")
    return 0 if ok else 3


def arms_for(scen: dict) -> list[tuple[str, list[str]]]:
    arms: list[tuple[str, list[str]]] = [("stock", [])]
    if scen.get("evasion"):
        arms.append(("evasion", list(scen["evasion"])))
    if scen["id"] in ("H8", "H12") or "HPP" in scen.get("note", "").upper():
        if not any(a == "evasion" and "--hpp" in f for a, f in arms):
            arms.append(("hpp", ["--hpp"]))
    if "oob" in [e.lower() for e in scen.get("expected", [])]:
        arms.append(
            (
                "oob",
                [
                    "--techniques",
                    "oob",
                    "--oob-domain",
                    OOB_DOMAIN,
                    "--oob-poll-url",
                    OOB_POLL,
                ],
            )
        )
    return arms


def parse_injekt_report(path: str) -> dict:
    try:
        with open(path) as f:
            doc = json.load(f)
    except Exception as e:
        return {
            "detected": False,
            "techniques": [],
            "params": [],
            "dbms": [],
            "confidence": None,
            "request_count": None,
            "parse_error": str(e),
        }
    findings = doc.get("findings", []) if isinstance(doc, dict) else []
    if not findings:
        return {
            "detected": False,
            "techniques": [],
            "params": [],
            "dbms": [],
            "confidence": 0.0,
            "request_count": doc.get("request_count")
            if isinstance(doc, dict)
            else None,
        }
    techs = sorted({f.get("technique", "?") for f in findings if isinstance(f, dict)})
    params = sorted({f.get("parameter", "?") for f in findings if isinstance(f, dict)})
    dbms = sorted({str(f.get("dbms", "?")) for f in findings if isinstance(f, dict)})
    conf = max(
        (float(f.get("confidence", 0.0)) for f in findings if isinstance(f, dict)),
        default=0.0,
    )
    rc = doc.get("request_count") if isinstance(doc, dict) else None
    return {
        "detected": True,
        "techniques": techs,
        "params": params,
        "dbms": dbms,
        "confidence": conf,
        "request_count": rc,
    }


def run_one(
    scen: dict,
    mode: str,
    arm: str,
    extra: list[str],
    out: str,
    timeout: int,
    seed: int | None,
) -> dict:
    cmd = injekt_bin() + [
        "--no-banner",
        "--allow-private",
        "--target",
        scen["url"],
        "--output",
        out,
    ]
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
        cmd += ["--params", sink]
    elif sink.startswith("header:"):
        cmd += ["--params", sink]
    flags = SCENARIO_FLAGS.get(scen["id"], {}).get(mode, MODES[mode])
    cmd += flags + extra
    if seed is not None and injekt_supports_seed():
        cmd += ["--seed", str(seed)]
    elif seed is not None:
        print("[warn] injekt binary has no --seed; seed recorded for provenance only")
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, cwd=HARD, capture_output=True, text=True, timeout=timeout
        )
        return {
            "rc": p.returncode,
            "elapsed_s": round(time.time() - t0, 1),
            "stdout": p.stdout,
            "stderr": p.stderr,
            "timeout": False,
        }
    except subprocess.TimeoutExpired as e:
        out_s = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err_s = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return {
            "rc": 124,
            "elapsed_s": float(timeout),
            "stdout": out_s,
            "stderr": err_s,
            "timeout": True,
        }


def append_history(entry: dict, path: str = HISTORY) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def cmd_run(args: argparse.Namespace) -> int:
    defaults, scenarios = load_scenarios()
    scen = next((s for s in scenarios if s["id"] == args.scenario), None)
    if scen is None:
        print(f"unknown scenario {args.scenario!r}", file=sys.stderr)
        return 2
    repeats = args.repeats or defaults.get("repeats", 5)
    timeout = defaults.get("timeout_s", 600)
    seed_base = args.seed if args.seed is not None else defaults.get("seed", 42)
    all_arms = arms_for(scen)
    if args.arm != "all":
        all_arms = [(a, f) for a, f in all_arms if a == args.arm]
        if not all_arms:
            print(f"unknown arm {args.arm!r}", file=sys.stderr)
            return 2
    run_id = (
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + f"-injekt-{scen['id']}-{args.mode}-"
        + uuid.uuid4().hex[:8]
    )
    ver = tool_version()
    summary: dict = {
        "run_id": run_id,
        "scenario": scen["id"],
        "mode": args.mode,
        "tool": "injekt",
        "tool_version": ver,
        "arms": {},
        "seed_base": seed_base,
        "canary_intact_all": True,
    }
    worst = 0
    for arm, extra in all_arms:
        det_n = 0
        for i in range(repeats):
            seed = seed_base + i
            rel = f"reports/injekt-{scen['id']}-{args.mode}-{arm}-r{i + 1}.json"
            out = os.path.join(HARD, rel)
            if args.reset:
                reset()
            else:
                time.sleep(1)
            res = run_one(scen, args.mode, arm, extra, rel, timeout, seed)
            parsed = (
                parse_injekt_report(out)
                if os.path.exists(out)
                else {
                    "detected": False,
                    "techniques": [],
                    "params": [],
                    "dbms": [],
                    "confidence": None,
                    "request_count": None,
                    "parse_error": "no report (timeout/crash?)",
                }
            )
            if parsed.get("detected"):
                det_n += 1
            m = ENGINE_RE.search((res["stdout"] or "") + (res["stderr"] or ""))
            eng_n = int(m.group(1)) if m else None
            match: bool | None = (
                (eng_n == parsed.get("request_count"))
                if eng_n is not None and parsed.get("request_count") is not None
                else None
            )
            if match is False:
                print(
                    f"[WARN] request_count MISMATCH engine={eng_n} report={parsed.get('request_count')}",
                    file=sys.stderr,
                )
            trip = canary()
            intact = canary_intact(trip)
            if not intact:
                summary["canary_intact_all"] = False
            for stream, suffix in (
                (res["stdout"], "stdout"),
                (res["stderr"], "stderr"),
            ):
                rp = os.path.join(RAWDIR, f"{run_id}-{arm}-r{i + 1}.{suffix}.log")
                os.makedirs(os.path.dirname(rp), exist_ok=True)
                with open(rp, "w") as f:
                    f.write(stream or "")
            append_history(
                {
                    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "run_id": run_id,
                    "tool": "injekt",
                    "tool_version": ver,
                    "scenario": scen["id"],
                    "mode": args.mode,
                    "arm": arm,
                    "repeat": i + 1,
                    "seed": seed,
                    "result": {
                        "detected": bool(parsed.get("detected")),
                        "techniques": parsed.get("techniques", []),
                        "params": parsed.get("params", []),
                        "dbms": parsed.get("dbms", []),
                        "confidence": parsed.get("confidence"),
                        "request_count": parsed.get("request_count"),
                        "elapsed_s": res["elapsed_s"],
                        "rc": res["rc"],
                    },
                    "report": rel,
                    "raw_stdout": f"reports/raw/{run_id}-{arm}-r{i + 1}.stdout.log",
                    "raw_stderr": f"reports/raw/{run_id}-{arm}-r{i + 1}.stderr.log",
                    "canary_intact": intact,
                    "request_count_match": match,
                },
                args.history or HISTORY,
            )
        summary["arms"][arm] = {"detect_n": det_n, "repeats": repeats}
    sp = os.path.join(REPORTS, f"injekt-{scen['id']}-{args.mode}.summary.json")
    with open(sp, "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))
    if not summary["canary_intact_all"]:
        print("canary TRIPPED — run REJECTED", file=sys.stderr)
        worst = 3
    return worst


def load_history(path: str) -> list[dict]:
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    print("[warn] corrupt history line skipped", file=sys.stderr)
    except FileNotFoundError:
        print(f"no history at {path}", file=sys.stderr)
    return rows


def aggregate(rows: list[dict]) -> dict[tuple, dict]:
    agg: dict[tuple, dict] = {}
    for r in rows:
        res = r.get("result", {})
        k = (r.get("scenario"), r.get("mode"), r.get("arm"))
        a = agg.setdefault(k, {"n": 0, "det": 0, "req": [], "t": []})
        a["n"] += 1
        a["det"] += 1 if res.get("detected") else 0
        if res.get("request_count") is not None:
            a["req"].append(res["request_count"])
        if res.get("elapsed_s") is not None:
            a["t"].append(res["elapsed_s"])
    return agg


def resolve_rows(spec: str, hist: str) -> list[dict]:
    if spec.endswith(".jsonl") or os.path.isfile(spec):
        return load_history(spec)
    if spec.endswith(".summary.json"):
        with open(spec) as f:
            s = json.load(f)
        rows = []
        for arm, a in s.get("arms", {}).items():
            for _ in range(a.get("repeats", 0)):
                rows.append(
                    {
                        "scenario": s.get("scenario"),
                        "mode": s.get("mode"),
                        "arm": arm,
                        "result": {"detected": a.get("detect_n", 0) > 0},
                    }
                )
        return rows
    rows = load_history(hist)
    sub = [r for r in rows if r.get("run_id", "").startswith(spec)]
    if not sub:
        print(f"no rows for {spec!r}", file=sys.stderr)
        sys.exit(2)
    return sub


def cmd_compare(args: argparse.Namespace) -> int:
    base = aggregate(resolve_rows(args.baseline, args.history or HISTORY))
    cand = aggregate(resolve_rows(args.candidate, args.history or HISTORY))
    keys = sorted(set(base) | set(cand))
    reg = 0
    print(f"{'scenario':<8} {'mode':<8} {'arm':<8} {'base':<6} {'cand':<6} verdict")
    for k in keys:
        b, c = base.get(k, {"det": 0, "n": 0}), cand.get(k, {"det": 0, "n": 0})
        bd, cd = b["det"] > 0, c["det"] > 0
        if bd and not cd:
            v = "REGRESSION"
            reg = 1
        elif cd and not bd:
            v = "IMPROVED"
        elif bd and cd:
            v = "OK"
        else:
            v = "SAME-MISS"
        if k[0] and k[0].startswith("N") and cd:
            print(f"[warn] {k[0]} false positive in candidate", file=sys.stderr)
        print(
            f"{str(k[0]):<8} {str(k[1]):<8} {str(k[2]):<8} {str(bd):<6} {str(cd):<6} {v}"
        )
    return reg


def cmd_matrix(args: argparse.Namespace) -> int:
    rows = load_history(args.history or HISTORY)
    if args.mode:
        rows = [r for r in rows if r.get("mode") == args.mode]
    agg = aggregate(rows)
    print(
        f"{'scenario':<8} {'mode':<8} {'arm':<8} {'n':>3} {'det':>3} {'avg_req':>8} {'avg_t':>7}"
    )
    for (s, m, a), v in sorted(agg.items()):
        rq = sum(v["req"]) / len(v["req"]) if v["req"] else None
        tt = sum(v["t"]) / len(v["t"]) if v["t"] else None
        print(
            f"{str(s):<8} {str(m):<8} {str(a):<8} {v['n']:>3} {v['det']:>3} "
            f"{(f'{rq:.0f}' if rq is not None else '-'):>8} {(f'{tt:.1f}' if tt is not None else '-'):>7}"
        )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("reset")
    sub.add_parser("check-canary")
    r = sub.add_parser("run")
    r.add_argument("--scenario", required=True)
    r.add_argument("--mode", default="power", choices=list(MODES))
    r.add_argument("--arm", default="all")
    r.add_argument("--repeats", type=int, default=None)
    r.add_argument("--seed", type=int, default=None)
    r.add_argument("--history", default=None)
    r.add_argument(
        "--reset",
        action="store_true",
        help="reseed DBs before every repeat (default: 1s pause only)",
    )
    c = sub.add_parser("compare")
    c.add_argument("--baseline", required=True)
    c.add_argument("--candidate", required=True)
    c.add_argument("--history", default=None)
    m = sub.add_parser("matrix")
    m.add_argument("--history", default=None)
    m.add_argument("--mode", default=None)
    sub.add_parser("versions")
    args = ap.parse_args()
    if args.cmd == "reset":
        return reset()
    if args.cmd == "check-canary":
        return cmd_canary()
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "compare":
        return cmd_compare(args)
    if args.cmd == "matrix":
        return cmd_matrix(args)
    if args.cmd == "versions":
        print(f"tool:injekt {tool_version()}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
