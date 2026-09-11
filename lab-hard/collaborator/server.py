#!/usr/bin/env python3
"""lab-hard OOB collaborator — stdlib only, self-hosted.

HTTP: GET /poll/<token> -> {"seen": bool, "token": ..., "interactions": [...]}
      GET /health -> {"ok": true}
      Any other GET with a token in Host/path is logged as blind hit.
DNS:  minimal UDP parser logging QNAMEs containing oob[0-9a-f]{12}.

Compatible with injekt HttpPollVerifier ({token} placeholder).
Tokens: oob + 12 hex (see src/techniques/oob/payloads.rs new_token()).

Egress originates from the target DB server in real OOB; in this lab the
app fires a fire-and-forget GET here to simulate that egress. Never use a
third-party collaborator for lab runs.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import BaseRequestHandler, TCPServer, UDPServer


class FastHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer without reverse-DNS in server_bind.

    Upstream HTTPServer.server_bind() calls socket.getfqdn(host), which
    issues a PTR lookup for 0.0.0.0 and hangs where DNS is filtered.
    The server name is only used for the Server: header / URLs — the
    literal bind address is a correct value here.
    """

    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = port


TOKEN_RE = re.compile(r"\boob[a-f0-9]{12}\b")
STORE: dict[str, list[dict]] = {}
LOCK = threading.Lock()


def record(token: str, kind: str, remote: str, raw: str) -> None:
    token = token.lower()
    if not TOKEN_RE.fullmatch(token):
        return
    with LOCK:
        STORE.setdefault(token, []).append(
            {"ts": time.time(), "type": kind, "remote": remote, "raw": raw[:512]}
        )


class H(BaseHTTPRequestHandler):
    server_version = "lab-hard-collab/1.0"

    def log_message(self, *a):  # type: ignore[no-untyped-def]
        logging.info(" ".join(map(str, a)))

    def _json(self, obj: dict, code: int = 200) -> None:
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _ingest(self, kind: str) -> None:
        host = self.headers.get("Host", "")
        for tok in TOKEN_RE.findall(f"{host} {self.path}"):
            record(tok, kind, self.client_address[0], f"{host} {self.requestline}")

    def do_GET(self) -> None:
        # /poll/* is our read API, never an egress signal: ingest first,
        # but skip the poll path itself so polling never self-confirms.
        if not self.path.startswith("/poll"):
            self._ingest("http")
        m = re.search(r"/poll/([A-Za-z0-9_-]+)", self.path)
        tok = m.group(1).lower() if m else None
        if tok is None and "token=" in self.path:
            q = re.search(r"token=([A-Za-z0-9_-]+)", self.path)
            tok = q.group(1).lower() if q else None
        if tok:
            with LOCK:
                hits = list(STORE.get(tok, []))
            return self._json({"seen": bool(hits), "token": tok, "interactions": hits})
        if self.path == "/health":
            return self._json({"ok": True})
        return self._json({"ok": True, "logged": True})

    do_POST = do_GET


class DNS(BaseRequestHandler):
    def handle(self) -> None:
        data, _sock = self.request
        try:
            i, labels = 12, []
            while i < len(data) and data[i] != 0 and len(labels) < 16:
                n = data[i]
                i += 1
                labels.append(data[i : i + n].decode("ascii", "ignore"))
                i += n
            qname = ".".join(labels).lower()
            for tok in TOKEN_RE.findall(qname):
                record(tok, "dns", self.client_address[0], qname)
                logging.info("DNS %s <- %s", tok, qname)
        except Exception as e:
            logging.debug("dns parse: %s", e)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--http", type=int, default=8080)
    ap.add_argument("--dns-port", type=int, default=5353)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    threading.Thread(
        target=UDPServer(("0.0.0.0", a.dns_port), DNS).serve_forever, daemon=True
    ).start()
    logging.info("DNS log :%d HTTP :%d", a.dns_port, a.http)
    FastHTTPServer(("0.0.0.0", a.http), H).serve_forever()
