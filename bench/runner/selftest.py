#!/usr/bin/env python3
"""bench/runner/selftest.py — offline smoke test for the bench harness.

No docker, no network, no target needed. Exercises:
  - parse_injekt_report / parse_sqlmap / parse_ghauri on fixture strings
  - cross_check_requests (match / mismatch / skipped)
  - compare (regression exit 1, clean exit 0, run-id specs,
    v0.3-baseline vs v0.4-regressed named REGRESSION, N1/N2 FP warnings)
  - canary verdict (intact vs tripped/destructive → run REJECTED exit 3)
  - matrix (compact table over a 3-tool history fixture)
  - history.jsonl validity (one JSON object per line)

Usage:  python3 bench/runner/selftest.py   (exit 0 = all green)
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run as R  # noqa: E402  (bench runner under test)

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(
        ("PASS " if cond else "FAIL ")
        + name
        + (f" — {detail}" if detail and not cond else "")
    )
    if not cond:
        FAILURES.append(name + (f": {detail}" if detail else ""))


SQLMAP_VULN = """\
        _
 ___ ___| |_____ ___ ___  {1.10.7#stable}
|_ -| . | |     | .'| . |
|___|_  |_|_|_|_|__,|  _|
      |_|           |_|   http://sqlmap.org

[*] starting @ 12:00:00
[INFO] testing connection to the target URL
[INFO] checking if the target is protected by some kind of WAF/IPS
[INFO] testing if GET parameter 'id' is dynamic
[INFO] confirming that GET parameter 'id' is dynamic
[INFO] GET parameter 'id' is dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
[INFO] testing for SQL injection on GET parameter 'id'
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
sqlmap identified the following injection point(s) with a total of 0 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 1234 FROM (SELECT(SLEEP(5)))abcd)
---
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[*] ending @ 12:01:00
"""

SQLMAP_CLEAN = """\
[*] starting @ 12:00:00
[INFO] testing if GET parameter 'id' is dynamic
[WARNING] GET parameter 'id' does not appear to be dynamic
[WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
[CRITICAL] all tested parameters do not appear to be injectable.
[*] ending @ 12:00:05
"""

GHAURI_VULN = """\
Ghauri v0.8.4 (https://github.com/r0oth3x49/ghauri)
[INFO] starting @ 12:00:00
[INFO] testing connection to the target URL
[INFO] checking if the target is protected by some kind of WAF/IPS
[INFO] testing if GET parameter 'id' is dynamic
[INFO] GET parameter 'id' is dynamic
ghauri identified the following injection point(s) with a total of 0 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234
---
[INFO] the back-end DBMS is PostgreSQL
[*] ending @ 12:00:30
"""

GHAURI_CLEAN = """\
Ghauri v0.8.4 (https://github.com/r0oth3x49/ghauri)
[INFO] starting @ 12:00:00
[WARNING] heuristic test shows that GET parameter 'id' might not be injectable
[CRITICAL] all tested parameters do not appear to be injectable.
[*] ending @ 12:00:05
"""


def hist_line(
    run_id,
    tool,
    scen,
    mode,
    arm,
    rep,
    detected,
    req,
    elapsed,
    seed=42,
    tool_version=None,
):
    return {
        "ts": "2026-09-09T12:00:00Z",
        "run_id": run_id,
        "tool": tool,
        "tool_version": tool_version or f"{tool} test",
        "scenario": scen,
        "mode": mode,
        "arm": arm,
        "repeat": rep,
        "seed": seed,
        "result": {
            "detected": detected,
            "techniques": ["boolean"] if detected else [],
            "params": ["id@get"] if detected else [],
            "dbms": ["MySQL"] if detected else [],
            "confidence": 0.7 if detected else None,
            "request_count": req,
            "elapsed_s": elapsed,
            "rc": 0,
        },
        "report": f"reports/{tool}-{scen}-{mode}-{arm}-r{rep}.json",
        "canary_intact": True,
        "request_count_match": True,
    }


def main() -> int:
    # --- injekt parser: full shape incl. provenance-era keys ----------------
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(
            {
                "target": "http://127.0.0.1:8000/api/users?id=1",
                "findings": [
                    {
                        "parameter": "id@query",
                        "technique": "Boolean",
                        "confidence": 0.74,
                        "dbms": None,
                    }
                ],
                "request_count": 143,
                "version": "0.3.0",
                "seed": 42,
                "profile": None,
                "techniques": ["boolean"],
                "level": 3,
                "tampers": ["space2comment"],
            },
            f,
        )
        injekt_path = f.name
    p = R.parse_injekt_report(injekt_path)
    check("injekt.detected", p["detected"] is True)
    check("injekt.request_count", p["request_count"] == 143)
    check("injekt.confidence", p["confidence"] == 0.74, repr(p.get("confidence")))
    check(
        "injekt.shape",
        set(p) >= {"detected", "dbms", "confidence", "request_count", "elapsed_s"},
    )
    os.unlink(injekt_path)
    p = R.parse_injekt_report("/nonexistent/path.json")
    check("injekt.missing-file", p["detected"] is False and p["request_count"] is None)

    # --- sqlmap parser -------------------------------------------------------
    s = R.parse_sqlmap(SQLMAP_VULN)
    check("sqlmap.detected", s["detected"] is True)
    check(
        "sqlmap.techniques",
        s["techniques"] == ["boolean", "time"],
        repr(s["techniques"]),
    )
    check("sqlmap.params", s["params"] == ["id@get"], repr(s["params"]))
    check("sqlmap.dbms", s["dbms"] == ["MySQL"], repr(s["dbms"]))
    check(
        "sqlmap.shape",
        set(s) >= {"detected", "dbms", "confidence", "request_count", "elapsed_s"},
    )
    s = R.parse_sqlmap(SQLMAP_CLEAN)
    check("sqlmap.clean", s["detected"] is False and s["techniques"] == [])

    # --- ghauri parser -------------------------------------------------------
    g = R.parse_ghauri(GHAURI_VULN)
    check("ghauri.detected", g["detected"] is True)
    check("ghauri.techniques", g["techniques"] == ["boolean"], repr(g["techniques"]))
    check("ghauri.dbms", g["dbms"] == ["PostgreSQL"], repr(g["dbms"]))
    check(
        "ghauri.shape",
        set(g) >= {"detected", "dbms", "confidence", "request_count", "elapsed_s"},
    )
    g = R.parse_ghauri(GHAURI_CLEAN)
    check("ghauri.clean", g["detected"] is False)
    check(
        "parsers.same-shape",
        set(R.parse_sqlmap(SQLMAP_VULN)) == set(R.parse_ghauri(GHAURI_VULN)),
    )

    # --- cross-check ---------------------------------------------------------
    ok = R.cross_check_requests("... engine done state=Done requests=143 ...", 143)
    check("xcheck.match", ok["match"] is True, repr(ok))
    bad = R.cross_check_requests("... requests=143 ...", 150)
    check("xcheck.mismatch", bad["match"] is False, repr(bad))
    skip = R.cross_check_requests("no counter here", 150)
    check("xcheck.skipped", skip["match"] is None, repr(skip))
    # real engine log line carries ANSI around `=` (tracing key/value colors)
    ansi = "[INFO] engine done \x1b[3mstate\x1b[0m\x1b[2m=\x1b[0mDone \x1b[3mrequests\x1b[0m\x1b[2m=\x1b[0m143"
    check("xcheck.ansi", R.cross_check_requests(ansi, 143)["match"] is True, repr(ansi))
    check(
        "xcheck.ansi-mismatch",
        R.cross_check_requests(ansi, 150)["match"] is False,
    )

    # --- compare / matrix over fixture histories -----------------------------
    with tempfile.TemporaryDirectory() as td:
        base = os.path.join(td, "base.jsonl")
        cand = os.path.join(td, "cand.jsonl")
        rows_base = [
            hist_line("run-base", "injekt", "A1", "power", "stock", 1, True, 123, 23.4),
            hist_line(
                "run-base", "injekt", "A1", "power", "evasion", 1, True, 143, 29.8
            ),
            hist_line("run-base", "injekt", "A2", "power", "stock", 1, True, 200, 40.0),
        ]
        rows_cand = [
            hist_line("run-cand", "injekt", "A1", "power", "stock", 1, True, 125, 24.1),
            hist_line(
                "run-cand", "injekt", "A1", "power", "evasion", 1, True, 150, 31.0
            ),
            hist_line(
                "run-cand", "injekt", "A2", "power", "stock", 1, False, 198, 39.5
            ),
        ]
        for path, rows in ((base, rows_base), (cand, rows_cand)):
            with open(path, "w") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")
        # json-lines validity: every line parses
        for path in (base, cand):
            with open(path) as f:
                for i, line in enumerate(f, 1):
                    try:
                        json.loads(line)
                    except ValueError:
                        check(f"jsonl.valid:{os.path.basename(path)}:{i}", False)
        check("jsonl.valid", True)

        rc = R.cmd_compare(base, cand, os.path.join(td, "history.jsonl"))
        check("compare.regression-exit-1", rc == 1, f"rc={rc}")
        rc = R.cmd_compare(base, base, os.path.join(td, "history.jsonl"))
        check("compare.clean-exit-0", rc == 0, f"rc={rc}")
        # run-id spec form against --history
        hist = os.path.join(td, "history.jsonl")
        with open(hist, "w") as f:
            for r in rows_base + rows_cand:
                f.write(json.dumps(r) + "\n")
        rc = R.cmd_compare("run-base", "run-cand", hist)
        check("compare.run-id-exit-1", rc == 1, f"rc={rc}")
        rc = R.cmd_compare("run-base", "run-base", hist)
        check("compare.run-id-exit-0", rc == 0, f"rc={rc}")
        rc = R.cmd_compare("run-base", "no-such-run", hist)
        check("compare.bad-spec-exit-2", rc == 2, f"rc={rc}")

        # --- C1 DoD: v0.3 baseline vs v0.4-regressed candidate ----------------
        # Named versions (not just run-ids): candidate misses A2 and fires on
        # the N1 negative control → exit 1 + FP warning on stderr.
        v03 = os.path.join(td, "v03.jsonl")
        v04 = os.path.join(td, "v04.jsonl")
        rows_v03 = [
            hist_line(
                "run-v03",
                "injekt",
                "A1",
                "power",
                "stock",
                1,
                True,
                123,
                23.4,
                tool_version="injekt 0.3.0",
            ),
            hist_line(
                "run-v03",
                "injekt",
                "A2",
                "power",
                "stock",
                1,
                True,
                200,
                40.0,
                tool_version="injekt 0.3.0",
            ),
            hist_line(
                "run-v03",
                "injekt",
                "N1",
                "power",
                "stock",
                1,
                False,
                50,
                9.1,
                tool_version="injekt 0.3.0",
            ),
        ]
        rows_v04 = [
            hist_line(
                "run-v04",
                "injekt",
                "A1",
                "power",
                "stock",
                1,
                True,
                120,
                22.9,
                tool_version="injekt 0.4.0",
            ),
            hist_line(
                "run-v04",
                "injekt",
                "A2",
                "power",
                "stock",
                1,
                False,
                198,
                39.5,
                tool_version="injekt 0.4.0",
            ),
            hist_line(
                "run-v04",
                "injekt",
                "N1",
                "power",
                "stock",
                1,
                True,
                52,
                9.4,
                tool_version="injekt 0.4.0",
            ),
        ]
        for path, rows in ((v03, rows_v03), (v04, rows_v04)):
            with open(path, "w") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = R.cmd_compare(v03, v04, os.path.join(td, "history.jsonl"))
        out_txt, err_txt = buf_out.getvalue(), buf_err.getvalue()
        check("compare.v03-v04-regression-exit-1", rc == 1, f"rc={rc}")
        check(
            "compare.v03-v04-verdict",
            "REGRESSION" in out_txt and "A2" in out_txt,
            out_txt[-300:],
        )
        check(
            "compare.v03-v04-fp-warning-n1",
            "N1" in err_txt and "false positive" in err_txt,
            err_txt[-300:],
        )

        # FP warning alone (no missed detection): warns on N1+N2 but exits 0.
        fp_base = os.path.join(td, "fp_base.jsonl")
        fp_cand = os.path.join(td, "fp_cand.jsonl")
        rows_fp_base = [
            hist_line("fp-b", "injekt", "A1", "power", "stock", 1, True, 123, 23.4),
            hist_line("fp-b", "injekt", "N1", "power", "stock", 1, False, 50, 9.1),
            hist_line("fp-b", "injekt", "N2", "power", "stock", 1, False, 51, 9.2),
        ]
        rows_fp_cand = [
            hist_line("fp-c", "injekt", "A1", "power", "stock", 1, True, 121, 23.0),
            hist_line("fp-c", "injekt", "N1", "power", "stock", 1, True, 52, 9.4),
            hist_line("fp-c", "injekt", "N2", "power", "stock", 1, True, 53, 9.5),
        ]
        for path, rows in ((fp_base, rows_fp_base), (fp_cand, rows_fp_cand)):
            with open(path, "w") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = R.cmd_compare(fp_base, fp_cand, os.path.join(td, "history.jsonl"))
        err_txt = buf_err.getvalue()
        check("compare.fp-only-exit-0", rc == 0, f"rc={rc}")
        check(
            "compare.fp-warning-n1-n2",
            "N1" in err_txt and "N2" in err_txt and "false positive" in err_txt,
            err_txt[-300:],
        )

        # --- canary: destructive run is REJECTED ------------------------------
        intact_trip = {
            "mysql": "untouched",
            "postgres": "untouched",
            "mssql": "untouched",
        }
        check("canary.intact", R.canary_intact(intact_trip) is True)
        check(
            "canary.tripped-mysql",
            R.canary_intact({**intact_trip, "mysql": "MODIFIED"}) is False,
        )
        check(
            "canary.empty-rejected",
            R.canary_intact({}) is False
            and R.canary_intact({"mysql": "", "postgres": "", "mssql": ""}) is False,
        )
        ok_summary = {
            "arms": {"stock": {"repeats": [{"canary_intact": True, "detected": True}]}}
        }
        bad_summary = {
            "arms": {
                "stock": {
                    "repeats": [
                        {"canary_intact": True, "detected": True},
                        {"canary_intact": False, "detected": True},
                    ]
                }
            }
        }
        check("canary.verdict-intact-exit-0", R.run_verdict(ok_summary) == 0)
        check("canary.verdict-tripped-exit-3", R.run_verdict(bad_summary) == 3)
        check("canary.verdict-empty-exit-0", R.run_verdict({"arms": {}}) == 0)

        # 3-tool matrix fixture
        mrows = [
            hist_line("m1", "injekt", "A1", "power", "stock", 1, True, 123, 23.4),
            hist_line("m1", "injekt", "A2", "power", "stock", 1, False, 200, 40.0),
            hist_line("m2", "sqlmap", "A1", "power", "stock", 1, True, None, 61.0),
            hist_line("m2", "sqlmap", "A2", "power", "stock", 1, True, None, 55.0),
            hist_line("m3", "ghauri", "A1", "power", "stock", 1, False, None, 33.0),
        ]
        mhist = os.path.join(td, "mhistory.jsonl")
        with open(mhist, "w") as f:
            for r in mrows:
                f.write(json.dumps(r) + "\n")
        rc = R.cmd_matrix(mhist, None, [])
        check("matrix.exit-0", rc == 0, f"rc={rc}")
        rc = R.cmd_matrix(os.path.join(td, "missing.jsonl"), None, [])
        check("matrix.missing-exit-2", rc == 2, f"rc={rc}")

    # --- CLI entry points (offline: --help only) ------------------------------
    for argv in (["compare", "--help"], ["matrix", "--help"], ["run", "--help"]):
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "run.py"), *argv],
            capture_output=True,
            text=True,
        )
        check(f"cli.{argv[0]}-help", r.returncode == 0, r.stderr[-200:])
    r = subprocess.run(
        [sys.executable, os.path.join(HERE, "run.py"), "versions"],
        capture_output=True,
        text=True,
    )
    check(
        "cli.versions", r.returncode == 0 and "tool:injekt" in r.stdout, r.stdout[-200:]
    )

    print(f"\n{len(FAILURES)} failure(s)")
    for f in FAILURES:
        print("  FAILED:", f)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
