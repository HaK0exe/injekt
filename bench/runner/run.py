#!/usr/bin/env python3
"""bench/runner/run.py — Phase 1 reproducible runner (stdlib only).

Usage (from bench/):
  python3 runner/run.py reset                        # reseed all 3 DBs
  python3 runner/run.py check-canary                 # verify tripwire rows
  python3 runner/run.py run --tool injekt --scenario A1 [--mode power|stealth]
  python3 runner/run.py pin                          # freeze digests/versions -> versions.lock

Official results run on a dedicated runner; local runs are for development.
sqlmap/ghauri matrix wiring is Phase 1b (parsers stubbed, raw logs kept).
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
REPORTS = os.path.join(BENCH, "reports")
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
    )
    print("  rc =", r.returncode, (r.stdout or "")[-300:], (r.stderr or "")[-300:])


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


def run_injekt(
    scen: dict, mode: str, out_path: str, timeout_s: int, extra: list[str] | None = None
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
    cmd += scen_override
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
            "stdout_tail": r.stdout[-2000:],
            "stderr_tail": r.stderr[-2000:],
            "timeout": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "rc": None,
            "elapsed_s": timeout_s,
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
            "request_count": None,
            "parse_error": str(e),
        }
    findings = rep.get("findings", []) or []
    return {
        "detected": bool(findings),
        "techniques": sorted({f.get("technique", "?") for f in findings}),
        "params": sorted({f.get("parameter", "?") for f in findings}),
        "dbms": sorted({str(f.get("dbms", "?")) for f in findings}),
        "request_count": rep.get("request_count"),
    }


# --------------------------------------------------------------------- pin --


def pin() -> None:
    images = [
        "mysql:8.4",
        "postgres:17-alpine",
        "mcr.microsoft.com/mssql/server:2022-latest",
        "owasp/modsecurity-crs:nginx",
    ]
    lines = ["# bench/versions.lock — frozen official-run references.\n"]
    for img in images:
        r = dk("image", "inspect", img, "--format", "{{.RepoDigests}}")
        lines.append(f"{img}  {r.stdout.strip() or '(not pulled)'}\n")
    for name, cmd in {
        "injekt": injekt_bin() + ["--no-banner", "info"],
        "sqlmap": ["sqlmap", "--version"],
        "ghauri": ["ghauri", "--version"],
    }.items():
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            ver = (r.stdout.strip() + " " + r.stderr.strip()).strip()[:200]
        except (OSError, subprocess.TimeoutExpired) as e:
            ver = f"(unavailable: {e})"
        lines.append(f"tool:{name}  {ver}\n")
    with open(os.path.join(BENCH, "versions.lock"), "w") as f:
        f.writelines(lines)
    print("".join(lines))


# -------------------------------------------------------------------- main --


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("reset")
    sub.add_parser("check-canary")
    sub.add_parser("pin")
    p = sub.add_parser("run")
    p.add_argument("--tool", default="injekt", choices=["injekt"])
    p.add_argument("--scenario", required=True)
    p.add_argument("--mode", default="power", choices=list(MODES))
    p.add_argument("--repeats", type=int, default=None)
    p.add_argument("--arm", default="all", choices=["all", "stock", "evasion"])
    args = ap.parse_args()

    if args.cmd == "reset":
        reset()
        return 0
    if args.cmd == "check-canary":
        print(json.dumps(canary(), indent=2))
        return 0
    if args.cmd == "pin":
        pin()
        return 0

    cfg = load_scenarios()
    scen = next((s for s in cfg["scenario"] if s["id"] == args.scenario), None)
    if scen is None:
        print(f"unknown scenario {args.scenario}", file=sys.stderr)
        return 2
    repeats = args.repeats or cfg["defaults"]["repeats"]
    timeout_s = cfg["defaults"]["timeout_s"]
    os.makedirs(REPORTS, exist_ok=True)

    arms = [("stock", [])]
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
        "scenario": scen["id"],
        "mode": args.mode,
        "expected": scen.get("expected", []),
        "negative": scen.get("negative", False),
        "arms": {},
    }
    for arm, extra in arms:
        results = []
        for i in range(repeats):
            print(f"=== {scen['id']} {args.mode}/{arm} repeat {i + 1}/{repeats} ===")
            reset()
            time.sleep(2)
            out = os.path.join(
                REPORTS, f"{args.tool}-{scen['id']}-{args.mode}-{arm}-r{i + 1}.json"
            )
            proc = run_injekt(scen, args.mode, out, timeout_s, extra)
            parsed = parse_injekt_report(out)
            trip = canary()
            intact = all(v == "untouched" for v in trip.values())
            results.append(
                {
                    "repeat": i + 1,
                    **proc,
                    **parsed,
                    "canary": trip,
                    "canary_intact": intact,
                }
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
