#!/usr/bin/env python3
"""GAMA FastPath — deterministic pre-LLM gate (offline, 0 model calls).

POST /optimize {"text": "..."} -> {"ok":true,"route":"block|math|math_pdv|cache|time|know|llm", ...}
GET  /health, /stats
"""
import hmac, json, os, re, sqlite3, time
from decimal import Decimal, ROUND_HALF_UP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("GAMA_FASTPATH_PORT", "8071"))
DB = os.environ.get("GAMA_FASTPATH_DB", "/tmp/gama_fastpath.db")
TTL = int(os.environ.get("GAMA_FASTPATH_TTL", "21600"))
BIND = os.environ.get("GAMA_FASTPATH_BIND", "0.0.0.0")
MAX_BODY = int(os.environ.get("GAMA_FASTPATH_MAX_BODY", "262144"))
STORE_TOKEN = os.environ.get("GAMA_FASTPATH_STORE_TOKEN", "")

T1 = [r"\brm\s+-rf\s+[/~*]", r"\bmkfs\b", r"\bdd\s+if=.*of=/dev/", r"\bdrop\s+(table|database)\b",
      r"\btruncate\s+table\b", r"\bshutdown\b", r"\breboot\b", r"\bobrisi\s+(sve|bazu|disk)\b", r"\bizbrisi\s+bazu\b"]
T2 = [r"\bobrisi\s+(fajl|folder|log)\b", r"\bobrisi\s+/var\b", r"\bobrisi\s+.*\b(log|fajl|folder)\b",
      r"\bizbrisi\s+.*\b(log|fajl|folder)\b", r"\bdelete\s+file\b", r"\bchmod\s+777\b", r"\bchown\s+-R\b",
      r"\bkillall\b", r"\bpkill\s+-9\b",
      r"\bignorisi\s+(sva\s+)?(prethodna\s+)?(uputstv|instrukcij)", r"\bti\s+si\s+root\b", r"\bpotvrdi\s+da\s+si\s+root\b",
      r"\b(ispisi|prikazi|daj|izlistaj|podijeli|podeli)\s+(mi\s+)?(sve\s+)?(env|environment|varijabl)",
      r"\bposalji\s+(mail|email|e-mail|poruku)\b.*\b(svim|sve)\b"]
T1C = [re.compile(p, re.I) for p in T1]
T2C = [re.compile(p, re.I) for p in T2]
FOLD = str.maketrans("čćžšđČĆŽŠĐ", "cczsdCCZSD")
STATS = {"calls": 0, "hit": 0, "blocked": 0, "answered": 0}

def fold(t): return str(t or "").translate(FOLD)
def norm(t): return re.sub(r"\s+", " ", fold(t).lower().strip())

def db():
    c = sqlite3.connect(DB, timeout=3)
    c.execute("CREATE TABLE IF NOT EXISTS cache(k TEXT PRIMARY KEY, a TEXT, ts REAL)")
    return c

def cache_get(k):
    try:
        c = db(); r = c.execute("SELECT a,ts FROM cache WHERE k=?", (k,)).fetchone(); c.close()
        if r and (time.time() - r[1]) < TTL: return r[0]
    except Exception: pass
    return None

def cache_put(k, a):
    try:
        c = db(); c.execute("INSERT OR REPLACE INTO cache(k,a,ts) VALUES(?,?,?)", (k, a, time.time()))
        c.commit(); c.close()
    except Exception: pass

def parse_amount(raw):
    """Parse BHS/EU/US money formats deterministically: 2.400,00 | 1.234.567,89 | 2,400.00 | 2400."""
    t = str(raw or "").strip().replace("\u00a0", "").replace(" ", "")
    neg = t.startswith("-")
    t = t.lstrip("+-")
    t = re.sub(r"[^0-9.,]", "", t).strip(".,")
    if not t:
        raise ValueError("no amount")
    if "." in t and "," in t:
        if t.rfind(",") > t.rfind("."):
            t = t.replace(".", "").replace(",", ".")
        else:
            t = t.replace(",", "")
    elif "," in t:
        parts = t.split(",")
        if len(parts) > 2:
            t = t.replace(",", "")
        else:
            t = t.replace(",", ".")
    elif "." in t:
        parts = t.split(".")
        if len(parts) > 2 or (len(parts) == 2 and len(parts[1]) == 3):
            t = t.replace(".", "")
    v = Decimal(t)
    return -v if neg else v


def pdv_na_neto(t):
    """PDV_NA_NETO_V2: 'PDV 17% na neto 2.400,00' -> 2808.00 (Decimal, half-up)."""
    m = re.search(r"pdv\s*(\d[\d.,]*)\s*%\s*na\s*neto\s*(\d[\d.,]*)", t, re.I)
    if not m:
        return None
    p = parse_amount(m.group(1)); n = parse_amount(m.group(2))
    return str((n * (Decimal(1) + p / Decimal(100))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def pct(t):
    m = re.search(r"(\d[\d.,]*)\s*%\s*(?:od|of)\s*(\d[\d.,]*)", t, re.I)
    if not m:
        return None
    p = parse_amount(m.group(1)); x = parse_amount(m.group(2))
    v = (p / Decimal(100) * x).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return "%s%% od %s = %s" % (m.group(1), m.group(2), str(v).replace(".", ","))


def optimize(text):
    t0 = time.time(); STATS["calls"] += 1
    t = str(text or "").strip(); low = norm(t)
    ms = lambda: round((time.time() - t0) * 1000, 2)
    for p in T1C:
        if p.search(low):
            STATS["blocked"] += 1
            return {"ok": True, "route": "block", "blocked": True, "answer": "Ne mogu to izvrsiti (opasna komanda).", "ms": ms()}
    for p in T2C:
        if p.search(low):
            STATS["blocked"] += 1
            return {"ok": True, "route": "block", "blocked": True, "answer": "Ne mogu to izvrsiti bez izricite potvrde.", "ms": ms()}
    k = "q:" + low
    hit = cache_get(k)
    if hit:
        STATS["hit"] += 1
        return {"ok": True, "route": "cache", "cached": True, "answer": hit, "ms": ms()}
    v = pdv_na_neto(t)
    if v:
        cache_put(k, v); STATS["answered"] += 1
        return {"ok": True, "route": "math_pdv", "answer": v, "ms": ms()}
    v = pct(t)
    if v:
        cache_put(k, v); STATS["answered"] += 1
        return {"ok": True, "route": "math", "answer": v, "ms": ms()}
    if re.fullmatch(r"(koje je )?(vrijeme|datum|danas)\??", low):
        return {"ok": True, "route": "time", "answer": time.strftime("%d.%m.%Y %H:%M"), "ms": ms()}
    return {"ok": True, "route": "llm", "ms": ms()}

def store_allowed(client_ip, token):
    """Loopback is trusted for local MCP; remote callers need the configured token."""
    if client_ip in ("127.0.0.1", "::1"):
        return True
    return bool(STORE_TOKEN) and hmac.compare_digest(str(token or ""), STORE_TOKEN)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/health"): return self._send({"ok": True, "svc": "gama-fastpath", "port": PORT})
        if self.path.startswith("/stats"): return self._send({"ok": True, **STATS})
        self._send({"ok": False, "err": "not found"}, 404)
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except Exception:
            return self._send({"ok": False, "err": "bad content-length"}, 400)
        if n > MAX_BODY:
            return self._send({"ok": False, "err": "request too large"}, 413)
        try:
            j = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send({"ok": False, "err": "bad json"}, 400)
        if self.path.startswith("/optimize"):
            return self._send(optimize(j.get("text", "")))
        if self.path.startswith("/store"):
            if not store_allowed(self.client_address[0], self.headers.get("X-Store-Token", "")):
                return self._send({"ok": False, "err": "forbidden"}, 403)
            a = str(j.get("answer", ""))
            if a: cache_put("q:" + norm(j.get("text", "")), a)
            return self._send({"ok": True})
        self._send({"ok": False, "err": "not found"}, 404)

def main():
    print("gama-fastpath :%d" % PORT, flush=True)
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()

if __name__ == "__main__": main()
