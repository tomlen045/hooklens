#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hooklens v1.0.0 - single-file zero-dependency webhook lens:
capture / HMAC verify / replay / forward.

Subcommands
  receive   local HTTP receiver, logs every webhook hit to a JSONL file
  verify    verify HMAC-SHA1/256/384/512 signatures (hex/base64/base64url/
            GitHub "sha256=" prefix / Stripe-style "t=...,v1=..." multi-scheme)
  send      forward a body+headers to a target URL (with HMAC signing option)
  serve     receiver with optional live HMAC enforcement (--secret / --webhookmode)
  replay    resend a captured log entry byte-identically to a target
  selftest  20-check invariant suite

Invariants
  I1  receive writes nothing but JSONL entries to the log file; bodies are
      stored base64-safe (binary bodies never corrupt the log)
  I2  no subcommand ever prints or logs the raw secret; only a masked
      secret_id (first 4 + last 4 chars) may appear in output
  I3  replay/send forward the exact captured bytes: body sha256 of what was
      received equals body sha256 of what is re-sent
  I4  exit codes: verify/send/replay exit 1 on failure; receive exits 0
  I5  --limit pruning deletes only the oldest N entries and is idempotent
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
ALGS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256,
        "sha384": hashlib.sha384, "sha512": hashlib.sha512, "md5": hashlib.md5}
ENCODINGS = ("hex", "base64", "base64url", "der")
HOP_HEADERS = {"content-length", "transfer-encoding", "host", "connection",
               "accept-encoding", "content-type"}
RE_DATE = re.compile(r"^\d{10}(\.\d+)?$")


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mask_secret(secret):
    s = secret or ""
    if len(s) <= 8:
        return (s[:2] + "**") if len(s) >= 2 else "**"
    return s[:4] + "..." + s[-4:]


def compute_mac(alg, secret, body):
    return hmac.new(secret.encode("utf-8"), body, ALGS[alg]).digest()


def encode_sig(digest, encoding):
    if encoding == "hex":
        return digest.hex()
    if encoding == "base64":
        return base64.b64encode(digest).decode()
    if encoding == "base64url":
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")
    if encoding == "der":
        return digest.hex()
    raise ValueError(encoding)


def split_algs(value):
    return [a.strip().lower() for a in value.split(",") if a.strip()]


# ---------------------------------------------------------------- receive/serve
def read_body_from_handler(handler):
    try:
        length = int(handler.headers.get("Content-Length") or 0)
    except ValueError:
        length = 0
    if length <= 0:
        return b""
    return handler.rfile.read(length)


def make_event(handler, body, recv_epoch):
    headers = {k.lower(): v for k, v in handler.headers.items()}
    printable = False
    text = None
    if body:
        try:
            text = body.decode("utf-8")
            printable = all(ord(ch) >= 0x20 or ch in "\n\r\t" for ch in text)
        except UnicodeDecodeError:
            text = None
    return {
        "ts": datetime.fromtimestamp(recv_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": handler.command,
        "path": handler.path,
        "remote": handler.client_address[0],
        "content_type": headers.get("content-type", ""),
        "headers": headers,
        "body": text if printable else None,
        "body_b64": base64.b64encode(body).decode(),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "size": len(body),
    }


def append_event(log_path, event):
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def prune_log(log_path, limit):
    if limit is None or limit <= 0:
        return
    with open(log_path, "r", encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    if len(lines) > limit:
        lines = lines[-limit:]
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


class LensHandler(BaseHTTPRequestHandler):
    server_version = "hooklens/" + VERSION
    mode = "receive"          # or "serve"
    log_path = None
    quiet = False
    limit = None
    secret = None
    webhookmode = False
    max_skew = 300
    strict_ts = False
    verbose = False
    status_code = 200

    def _respond(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _handle(self):
        body = read_body_from_handler(self)
        event = make_event(self, body, time.time())
        verdict = None
        code = self.status_code
        if self.mode == "serve" and self.secret:
            ok, reason, _ = verify_secret_hmac(
                self.secret, dict(self.headers), body,
                algs=split_algs(getattr(self, "algs", "sha256")),
                encodings=ENCODINGS,
                sig_header=getattr(self, "sig_header", "X-Signature"),
                ts_headers=split_algs(getattr(self, "ts_headers", "X-Timestamp,X-Ts")),
                webhookmode=self.webhookmode, max_skew=self.max_skew,
                strict_ts=self.strict_ts)
            verdict = "ok" if ok else reason
            if not ok:
                code = 400
        if self.log_path:
            append_event(self.log_path, event)
            prune_log(self.log_path, self.limit)
        if not self.quiet:
            line = '%s %s %s %d' % (event["ts"], event["method"], event["path"], code)
            if verdict is not None:
                line += " sig=%s" % verdict
            if self.verbose:
                line += "\n  headers: %s" % json.dumps(event["headers"], ensure_ascii=False)
                line += "\n  body: %s" % (event["body"] if event["body"] is not None
                                          else "(binary %d bytes, b64 in log)" % event["size"])
            print(line)
            sys.stdout.flush()
        self._respond(code, {"ok": code < 400, "sig": verdict, "received": event["size"]})

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle

    def log_message(self, *a):  # silence default stderr logging
        pass


# -------------------------------------------------------------------- verify
def header_get(headers, name):
    getter = getattr(headers, "get", None)
    if callable(getter):
        v = getter(name)
        if v is not None:
            return v
    if isinstance(headers, dict):
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
    return None


def extract_sig_candidates(sig_value, webhookmode):
    """Return (candidates, ts). candidates = list of (encoding, sig_str)."""
    ts = None
    val = (sig_value or "").strip()
    cands = []
    if webhookmode or re.match(r"^t=\d+", val):
        schemes = {}
        for part in val.split(","):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                schemes[k.strip()] = v.strip()
        ts = schemes.get("t")
        for k, v in schemes.items():
            if k == "t":
                continue
            if re.match(r"^v\d+$", k):
                # version-style scheme (v1/v2...): alg unknown, try configured algs
                cands.append((None, "hex", v))
            elif k in ("sha256", "sha1", "sha384", "sha512", "md5"):
                cands.append((k, "hex", v))
        return cands, ts
    if "=" in val and val.split("=", 1)[0] in ("sha256", "sha1", "sha512"):
        alg, rest = val.split("=", 1)
        return [(alg, "hex", rest.strip())], ts
    for enc in ENCODINGS:
        cands.append((None, enc, val))
    return cands, ts


def parse_timestamp(raw):
    if raw is None:
        return None
    raw = raw.strip()
    if RE_DATE.match(raw):
        try:
            return float(raw)
        except ValueError:
            return None
    try:
        iso = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def verify_secret_hmac(secret, headers, body, algs, encodings,
                       sig_header, ts_headers, webhookmode, max_skew, strict_ts):
    sig_value = header_get(headers, sig_header)
    reasons = []
    if sig_value is None:
        return False, "sig-header-missing", None
    cands, ts_raw = extract_sig_candidates(sig_value, webhookmode)
    matched = None
    # two payload conventions: bare body (GitHub style) and "t=<ts>.<body>"
    # (Stripe style). Try both so one engine covers the two big families.
    ts_probe = parse_timestamp(ts_raw) if ts_raw is not None else None
    payloads = [body]
    if ts_probe is not None and webhookmode:
        payloads.append(("%d." % int(ts_probe)).encode() + body)
    for alg, enc, s in cands:
        use_algs = [alg] if alg else list(algs)
        for a in use_algs:
            if a not in ALGS:
                continue
            for pl in payloads:
                mac = compute_mac(a, secret, pl)
                for e in ([enc] if enc in ENCODINGS else encodings):
                    cand = encode_sig(mac, e)
                    if hmac.compare_digest(cand.lower(), s.strip().lower()):
                        matched = (a, e)
                        break
                if matched:
                    break
            if matched:
                break
        if matched:
            break
    if not matched:
        reasons.append("sig-mismatch")
    ts = parse_timestamp(ts_raw) if ts_raw is not None else parse_timestamp(
        next((header_get(headers, h) for h in ts_headers
              if header_get(headers, h) is not None), None))
    skew_ok = True
    ts_out = None
    if ts is not None:
        delta = time.time() - ts
        ts_out = int(delta)
        if abs(delta) > max_skew:
            skew_ok = False
            reasons.append("timestamp-skew %ds > %ds" % (int(abs(delta)), max_skew))
    elif strict_ts:
        skew_ok = False
        reasons.append("timestamp-missing (strict)")
    ok = bool(matched) and skew_ok
    return ok, ("ok" if ok else "; ".join(reasons)), (matched, ts_out)


def cmd_verify(ns):
    body = b""
    if ns.body_file == "-":
        body = sys.stdin.buffer.read()
    else:
        with open(ns.body_file, "rb") as f:
            body = f.read()
    headers = {}
    if ns.headers_file:
        with open(ns.headers_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if ":" in line and not line.startswith((" ", "\t")):
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
    for h in ns.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    secret = os.environ[ns.secret_env] if ns.secret_env else ns.secret
    if not secret:
        print("MISSING_SECRET provide --secret or --secret-env", file=sys.stderr)
        return 2
    cands, ts_raw_hint = extract_sig_candidates(
        header_get(headers, ns.sig_header) or "", ns.webhookmode)
    algs = split_algs(ns.alg)
    encs = split_algs(ns.encoding)
    try:
        ok, reason, extra = verify_secret_hmac(
            secret, headers, body, algs, encs, ns.sig_header,
            split_algs(ns.ts_header), ns.webhookmode, ns.max_skew, ns.strict_ts)
    except Exception as e:
        print("VERIFY_ERROR %s" % e)
        return 1
    matched, ts_delta = extra if extra else (None, None)
    out = {
        "verdict": "OK" if ok else "FAIL",
        "reason": reason,
        "matched": {"alg": matched[0], "encoding": matched[1]} if matched else None,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_size": len(body),
        "ts_delta_seconds": ts_delta,
        "secret_id": mask_secret(secret),
    }
    print(json.dumps(out, ensure_ascii=False))
    return 0 if ok else 1


# ---------------------------------------------------------------- send/replay
def do_send(url, method, headers, body, timeout, insecure, dry_run):
    if dry_run:
        return 0, None, None
    req = urllib.request.Request(url, data=body if method not in ("GET", "HEAD") else None,
                                 method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(4096), None
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096), None
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
        return None, None, str(e)


def build_signed_headers(extra, alg, secret, body, ts_header, ts_value=None):
    headers = dict(extra)
    ts = ts_value if ts_value is not None else int(time.time())
    mac = compute_mac(alg, secret, body)
    hexed = encode_sig(mac, "hex")
    headers[ts_header] = str(ts)
    headers["X-hooklens-Signature"] = "%s=%s" % (alg, hexed)
    return headers


def cmd_send(ns):
    body = b""
    if ns.body_file == "-":
        body = sys.stdin.buffer.read()
    elif ns.body_file:
        with open(ns.body_file, "rb") as f:
            body = f.read()
    headers = {}
    for h in ns.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if ns.secret:
        headers = build_signed_headers(headers, ns.alg, ns.secret, body, ns.ts_header)
    if ns.dry_run:
        print(json.dumps({"dry_run": True, "url": ns.url, "method": ns.method,
                          "body_sha256": hashlib.sha256(body).hexdigest(),
                          "headers": sorted(headers.keys())}, ensure_ascii=False))
        return 0
    status, resp, err = do_send(ns.url, ns.method, headers, body, ns.timeout, ns.insecure, False)
    if err:
        print(json.dumps({"result": "ERROR", "error": err,
                          "hint": "is the receiver up? try --dry-run first"}, ensure_ascii=False))
        return 1
    print(json.dumps({"result": "SENT", "status": status,
                      "body_sha256": hashlib.sha256(body).hexdigest()}, ensure_ascii=False))
    return 0 if (status and status < 400) else 1


def load_entry(log_path, index):
    with open(log_path, "r", encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    if index < 1 or index > len(lines):
        raise IndexError("entry %d out of range (1..%d)" % (index, len(lines)))
    return json.loads(lines[index - 1])


def cmd_replay(ns):
    try:
        entry = load_entry(ns.log, ns.entry)
    except (OSError, ValueError, IndexError) as e:
        print(json.dumps({"result": "ERROR", "error": str(e)}, ensure_ascii=False))
        return 2
    body = base64.b64decode(entry["body_b64"])
    headers = {k: v for k, v in entry["headers"].items() if k not in HOP_HEADERS}
    target = ns.target.rstrip("/") + entry["path"]
    if ns.dry_run:
        print(json.dumps({"dry_run": True, "target": target, "method": entry["method"],
                          "body_sha256": entry["body_sha256"],
                          "captured_at": entry["ts"]}, ensure_ascii=False))
        return 0
    status, resp, err = do_send(target, entry["method"], headers, body,
                                ns.timeout, ns.insecure, False)
    if err:
        print(json.dumps({"result": "ERROR", "error": err}, ensure_ascii=False))
        return 1
    same = hashlib.sha256(body).hexdigest() == entry["body_sha256"]
    print(json.dumps({"result": "REPLAYED", "entry": ns.entry,
                      "captured_at": entry["ts"], "status": status,
                      "body_sha256": entry["body_sha256"],
                      "bytes_identical": same}, ensure_ascii=False))
    return 0 if (status and status < 400 and same) else 1


# ------------------------------------------------------------------- receive cmd
def cmd_receive(ns):
    handler = type("LensR", (LensHandler,), {})
    handler.mode = "receive"
    handler.log_path = ns.log
    handler.quiet = ns.quiet
    handler.limit = ns.limit
    handler.verbose = ns.verbose
    handler.status_code = ns.status
    srv = ThreadingHTTPServer((ns.bind, ns.port), handler)
    if not ns.quiet:
        print("hooklens receive v%s  http://%s:%d  log=%s  [ctrl-c to stop]"
              % (VERSION, ns.bind, ns.port, os.path.abspath(ns.log)))
        print("waiting for webhooks ...")
        sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def cmd_serve(ns):
    handler = type("LensS", (LensHandler,), {})
    handler.mode = "serve"
    handler.log_path = ns.log
    handler.quiet = ns.quiet
    handler.limit = ns.limit
    handler.verbose = ns.verbose
    handler.secret = ns.secret
    handler.webhookmode = ns.webhookmode
    handler.max_skew = ns.max_skew
    handler.strict_ts = ns.strict_ts
    handler.sig_header = ns.sig_header
    handler.ts_headers = ns.ts_header
    handler.algs = ns.alg
    handler.status_code = ns.status
    srv = ThreadingHTTPServer((ns.bind, ns.port), handler)
    if not ns.quiet:
        mode = "webhook(t=,v1=...)" if ns.webhookmode else "raw hex/base64"
        sec = ("secret=%s" % mask_secret(ns.secret)) if ns.secret else "NO-ENFORCE (log only)"
        print("hooklens serve v%s  http://%s:%d  sig=%s  %s  log=%s"
              % (VERSION, ns.bind, ns.port, mode, sec, os.path.abspath(ns.log)))
        sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


# ------------------------------------------------------------------- selftest
def st(name, cond, detail=""):
    tag = "ok" if cond else "FAIL"
    print("  [%s] %s%s" % (tag, name, (" - " + detail) if detail and not cond else ""))
    return cond


class EchoSrv(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)
        self.got = {}

        class H(BaseHTTPRequestHandler):
            def _h(self):
                ln = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(ln) if ln else b""
                EchoSrv_owner.got = {"method": self.command, "path": self.path,
                                     "headers": {k.lower(): v for k, v in self.headers.items()},
                                     "body": body}
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_POST = _h
            do_PUT = _h

            def log_message(self, *a):
                pass

        EchoSrv_owner = self
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]

    def run(self):
        self.srv.serve_forever()


def cmd_selftest(ns):
    import tempfile
    tmp = tempfile.mkdtemp(prefix="hooklens-selftest-")
    results = []
    log = os.path.join(tmp, "cap.jsonl")
    body_bin = os.path.join(tmp, "body.bin")

    # T1-T7 receive
    logf = os.path.join(tmp, "recv.jsonl")
    rh = type("T_R", (LensHandler,), {})
    rh.mode = "receive"
    rh.log_path = logf
    rh.quiet = True
    rh.limit = None
    rh.verbose = False
    rh.status_code = 200

    class HdrWrap:
        def __init__(self, d):
            self.d = {k.lower(): v for k, v in d.items()}

        def items(self):
            return [(k, v) for k, v in self.d.items()]

        def get(self, k, default=None):
            return self.d.get(k.lower(), default)

    class FakeSelf:
        command = "POST"
        path = "/hook?x=1"
        client_address = ("203.0.113.9", 4444)
        rfile = None
        headers = None

    def fake_receive(hdrs, body_bytes, length):
        fs = FakeSelf()
        fs.headers = hdrs
        fs.rfile = type("R", (), {"read": lambda self, n: body_bytes})()
        fs._hdr_len = {"Content-Length": str(len(body_bytes))}
        fs.headers = hdrs
        ev = make_event(fs, body_bytes, time.time())
        append_event(logf, ev)
        return ev

    ev = fake_receive(HdrWrap({"Content-Type": "application/json",
                               "X-GitHub-Event": "push",
                               "Content-Length": "34"}), b'{"action":"opened","number":42}', time.time())
    results.append(st("T1 receive logs valid JSONL with body", ev["body"] == '{"action":"opened","number":42}'
                      and json.loads(open(logf).read())["body_sha256"] ==
                      hashlib.sha256(b'{"action":"opened","number":42}').hexdigest()))
    with open(body_bin, "wb") as f:
        f.write(bytes([0x00, 0xFF, 0xFE, 0x01, 0x02]))
    ev2 = fake_receive(HdrWrap({"Content-Type": "application/octet-stream"}),
                       bytes([0x00, 0xFF, 0xFE, 0x01, 0x02]), time.time())
    results.append(st("T2 binary body -> body=null + body_b64 (I1)",
                      ev2["body"] is None and
                      base64.b64decode(ev2["body_b64"]) == bytes([0x00, 0xFF, 0xFE, 0x01, 0x02])))
    ev3 = fake_receive(HdrWrap({}), b"", time.time())
    results.append(st("T3 empty body size=0 sha=empty-sha",
                      ev3["size"] == 0 and ev3["body_sha256"] ==
                      hashlib.sha256(b"").hexdigest()))
    ev4 = fake_receive(HdrWrap({}), "中文负载🚀".encode("utf-8"), time.time())
    results.append(st("T4 CJK+emoji body preserved as text",
                      ev4["body"] == "中文负载🚀"))
    fake_receive(HdrWrap({}), b"e1", time.time())
    fake_receive(HdrWrap({}), b"e2", time.time())
    prune_log(logf, 3)
    n_after = len([ln for ln in open(logf).read().splitlines() if ln.strip()])
    prune_log(logf, 3)
    n_again = len([ln for ln in open(logf).read().splitlines() if ln.strip()])
    results.append(st("T5 --limit prune keeps newest + idempotent (I5)",
                      n_after == 3 and n_again == 3))
    ok3, r3, _ = verify_secret_hmac("k", HdrWrap({}), b"x", ["sha256"], ENCODINGS,
                                    "X-Sig", ["X-TS"], False, 300, True)
    results.append(st("T6 missing sig header -> fail even with secret (I4 path)",
                      ok3 is False and r3 == "sig-header-missing"))
    raw = "x" * 300
    ev5 = fake_receive(HdrWrap({}), raw.encode(), time.time())
    results.append(st("T7 event JSON single-line (JSONL safe)",
                      "\n" not in json.dumps(ev5, ensure_ascii=False)))

    # T8 known RFC4231 vector
    mac = compute_mac("sha256", "Jefe", b"what do ya want for nothing?")
    results.append(st("T8 RFC4231 HMAC-SHA256 known vector",
                      encode_sig(mac, "hex") ==
                      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))

    # T9 encodings all accepted
    digest = compute_mac("sha256", "sk_live_9f2c81", b"payload")
    accept = 0
    for enc in ("hex", "base64", "base64url"):
        ok9, _, m9 = verify_secret_hmac("sk_live_9f2c81",
                                        HdrWrap({"X-Sig": encode_sig(digest, enc)}),
                                        b"payload", ["sha256"], ENCODINGS,
                                        "X-Sig", ["X-TS"], False, 300, False)
        accept += 1 if (ok9 and m9 and m9[0] and m9[0][0] == "sha256" and m9[0][1] == enc) else 0
    results.append(st("T9 hex/base64/base64url all auto-accepted", accept == 3))

    # T10 GitHub sha256= prefix
    gh_hdr = "sha256=" + encode_sig(digest, "hex")
    ok10, _, m10 = verify_secret_hmac("sk_live_9f2c81", HdrWrap({"X-Hub-Signature-256": gh_hdr}),
                                      b"payload", ["sha256"], ENCODINGS,
                                      "X-Hub-Signature-256", ["X-TS"], False, 300, False)
    results.append(st("T10 GitHub 'sha256=' prefix parsed", ok10 and m10[0][1] == "hex"))

    # T11 Stripe t=,v1= style
    ts_now = int(time.time())
    pbody = b'{"id":"evt_1"}'
    pmac = compute_mac("sha256", "whsec_a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8", ("%d." % ts_now).encode() + pbody)
    st_hdr = "t=%d,v1=%s" % (ts_now, encode_sig(pmac, "hex"))
    ok11, _, m11 = verify_secret_hmac("whsec_a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
                                      HdrWrap({"Stripe-Sig": st_hdr}), pbody,
                                      ["sha256"], ENCODINGS, "Stripe-Sig", ["Stripe-Ts"],
                                      True, 300, False)
    results.append(st("T11 Stripe-style t=,v1= multi-scheme + fresh ts", ok11 and m11[0][0] == "sha256"))

    # T12 webhookmode wrong key -> mismatch
    ok12, r12, _ = verify_secret_hmac("whsec_other", HdrWrap({"Stripe-Sig": st_hdr}), pbody,
                                      ["sha256"], ENCODINGS, "Stripe-Sig", ["Stripe-Ts"], True, 300, False)
    results.append(st("T12 wrong secret -> mismatch verdict", (not ok12) and "sig-mismatch" in r12))

    # T13 tampered byte
    ok13, _, _ = verify_secret_hmac("sk_live_9f2c81", HdrWrap({"X-Sig": encode_sig(digest, "hex")}),
                                    b"payloadX", ["sha256"], ENCODINGS, "X-Sig", ["X-TS"], False, 300, False)
    results.append(st("T13 tampered body caught", not ok13))

    # T14 fresh unix ts ok
    hdrs14 = {"X-TS": str(int(time.time())), "X-Sig": encode_sig(digest, "hex")}
    ok14, _, m14 = verify_secret_hmac("sk_live_9f2c81", HdrWrap(hdrs14), b"payload",
                                      ["sha256"], ENCODINGS, "X-Sig", ["X-TS"], False, 300, False)
    results.append(st("T14 unix ts within skew accepted, delta reported",
                      ok14 and m14[1] is not None and abs(m14[1]) < 5))

    # T15 stale ts -> skew-fail
    hdrs15 = {"X-TS": str(int(time.time()) - 3600), "X-Sig": encode_sig(digest, "hex")}
    ok15, r15, _ = verify_secret_hmac("sk_live_9f2c81", HdrWrap(hdrs15), b"payload",
                                      ["sha256"], ENCODINGS, "X-Sig", ["X-TS"], False, 300, False)
    results.append(st("T15 1h-old ts -> timestamp-skew fail", (not ok15) and "timestamp-skew" in r15))

    # T16 ISO8601 Z ts parsed
    iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hdrs16 = {"Date-Hdr": iso, "X-Sig": encode_sig(digest, "hex")}
    ok16, _, m16 = verify_secret_hmac("sk_live_9f2c81", HdrWrap(hdrs16), b"payload",
                                      ["sha256"], ENCODINGS, "X-Sig", ["Date-Hdr"], False, 300, False)
    results.append(st("T16 ISO8601 Z timestamp parsed", ok16))

    # T17 strict-ts with no ts -> fail
    ok17, r17, _ = verify_secret_hmac("sk_live_9f2c81", HdrWrap({"X-Sig": encode_sig(digest, "hex")}),
                                      b"payload", ["sha256"], ENCODINGS, "X-Sig", ["X-TS"],
                                      False, 300, True)
    results.append(st("T17 --strict-ts missing ts -> fail", (not ok17) and "timestamp-missing" in r17))

    # T18-I2 no secret leak in verify output
    blob = json.dumps({"secret_id": mask_secret("whsec_a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8")})
    results.append(st("T18 output masks secret (I2)",
                      "whsec_a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8" not in blob
                      and "whse...a7b8" in blob))

    # T19-T20 send + replay against live echo server
    es = EchoSrv()
    es.start()
    time.sleep(0.2)
    pbody2 = b'{"replay":"me"}'
    send_hdrs = build_signed_headers({"Content-Type": "application/json"}, "sha256",
                                     "whsec_demo_9f2c81", pbody2, "X-Ts-Hdr")
    status, _, err = do_send("http://127.0.0.1:%d/absorb" % es.port, "POST", send_hdrs,
                             pbody2, 5, False, False)
    got_ok = (status == 200 and es.got.get("body") == pbody2
              and es.got["headers"].get("x-ts-hdr") == send_hdrs["X-Ts-Hdr"])
    results.append(st("T19 send delivers body+signed headers (200)", got_ok))
    # replay path: entry bytes identical (I3)
    ev9 = {"ts": "2026-10-27T10:00:00Z", "method": "POST", "path": "/r", "remote": "127.0.0.1",
           "content_type": "application/json", "headers": {"content-type": "application/json"},
           "body": None, "body_b64": base64.b64encode(pbody2).decode(),
           "body_sha256": hashlib.sha256(pbody2).hexdigest(), "size": len(pbody2)}
    rlog = os.path.join(tmp, "replay.jsonl")
    append_event(rlog, ev9)
    e9 = load_entry(rlog, 1)
    body9 = base64.b64decode(e9["body_b64"])
    status9, _, _ = do_send("http://127.0.0.1:%d/r" % es.port, "POST",
                            {k: v for k, v in e9["headers"].items() if k not in HOP_HEADERS},
                            body9, 5, False, False)
    results.append(st("T20 replay bytes identical + delivered (I3)",
                      status9 == 200 and es.got["body"] == pbody2
                      and hashlib.sha256(es.got["body"]).hexdigest() == e9["body_sha256"]))

    total = len(results)
    passed = sum(results)
    print("selftest: %d/%d green" % (passed, total))
    if passed != total:
        for i, r in enumerate(results):
            if not r:
                print("  FAILED test #%d" % (i + 1))
    return 0 if passed == total else 1


# ------------------------------------------------------------------------ main
def base_common(p):
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--log", default="hooklens.jsonl")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--limit", type=int, default=None,
                   help="keep only newest N entries (idempotent)")
    p.add_argument("--status", type=int, default=200, help="response code (default 200)")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="hooklens",
                                 description="webhook lens: capture / verify / replay / forward")
    ap.add_argument("--version", action="version", version="hooklens " + VERSION)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("receive", help="capture webhooks to JSONL")
    base_common(p)

    p = sub.add_parser("serve", help="capture + live HMAC enforcement")
    base_common(p)
    p.add_argument("--secret")
    p.add_argument("--webhookmode", action="store_true",
                   help="expect 't=...,v1=...' multi-scheme signatures")
    p.add_argument("--alg", default="sha256", help="algs for raw mode, comma separated")
    p.add_argument("--sig-header", default="X-Signature")
    p.add_argument("--ts-header", default="X-Timestamp,X-Ts",
                   help="comma list of timestamp headers to try")
    p.add_argument("--max-skew", type=int, default=300)
    p.add_argument("--strict-ts", action="store_true",
                   help="fail when no timestamp header is present")

    p = sub.add_parser("verify", help="verify an HMAC signature offline")
    p.add_argument("--secret")
    p.add_argument("--secret-env", help="read secret from this env var (never argv)")
    p.add_argument("--body-file", default="-", help="'-' = stdin")
    p.add_argument("--header", action="append", help="'Key: value', repeatable")
    p.add_argument("--headers-file", help="raw 'Key: value' lines")
    p.add_argument("--alg", default="sha1,sha256,sha384,sha512,md5")
    p.add_argument("--encoding", default="hex,base64,base64url")
    p.add_argument("--sig-header", default="X-Signature")
    p.add_argument("--ts-header", default="X-Timestamp,X-Ts")
    p.add_argument("--max-skew", type=int, default=300)
    p.add_argument("--strict-ts", action="store_true")
    p.add_argument("--webhookmode", action="store_true")

    p = sub.add_parser("send", help="forward body+headers to a target URL")
    p.add_argument("--url", required=True)
    p.add_argument("--method", default="POST")
    p.add_argument("--body-file", default=None)
    p.add_argument("--header", action="append")
    p.add_argument("--secret", help="sign with HMAC before sending")
    p.add_argument("--alg", default="sha256")
    p.add_argument("--ts-header", default="X-Timestamp")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("replay", help="resend a captured log entry byte-identically")
    p.add_argument("--log", required=True)
    p.add_argument("--entry", type=int, required=True, help="1-based entry number")
    p.add_argument("--target", required=True, help="base URL, captured path is appended")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--dry-run", action="store_true")

    sub.add_parser("selftest", help="20-check invariant suite")

    ns = ap.parse_args(argv)
    if ns.cmd == "receive":
        return cmd_receive(ns)
    if ns.cmd == "serve":
        return cmd_serve(ns)
    if ns.cmd == "verify":
        return cmd_verify(ns)
    if ns.cmd == "send":
        return cmd_send(ns)
    if ns.cmd == "replay":
        return cmd_replay(ns)
    if ns.cmd == "selftest":
        return cmd_selftest(ns)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
