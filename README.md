# gama-fastpath

<p align="center"><img src="assets/logo.svg" width="96" alt="GAMA logo"></p>

[![CI](https://github.com/gamai-io/gama-fastpath/actions/workflows/ci.yml/badge.svg)](https://github.com/gamai-io/gama-fastpath/actions/workflows/ci.yml)

[![Version](https://img.shields.io/badge/version-v0.1.2-22d3ee)](https://github.com/gamai-io/gama-fastpath/releases)


Deterministic **pre-LLM gate**: blocks catastrophic/destructive or env-disclosure
requests and answers money math without any model call. Offline, stdlib only.

- **Structural gate** (`dsc.gate`, pinned as a `dsc` dependency): shell requests
  are split into statements and pipelines, tokenised with `shlex`, wrappers
  (`sudo`, `env`, `xargs`, `timeout`, ...) are unwrapped, and `sh -c` payloads
  plus `$(...)`/backtick substitutions are analysed recursively. Flags may be
  reordered, quoted or abbreviated; it is the parsed argv that decides, not a
  phrase list. This repo no longer carries its own `gate.py`.
  - recursive delete/overwrite of `/`, `/etc`, home (`~`, `$HOME`) — including
    `rm -fr /`, `rm --recursive --force /`, `sudo rm -rf --no-preserve-root /`
  - `find ... -delete` / `find ... -exec rm`
  - SQL `drop` / `truncate`, and `delete`/`update` **without `WHERE`**
  - reads of `/etc/shadow`, `/etc/passwd`, `id_rsa`, `.env`, cloud credentials
  - `curl|wget ... | sh|bash|python`, `sh -c "$(curl ...)"`, `eval $(curl ...)`
  - mass outbound mail (`pošalji mejl svim kupcima`, `send email to all customers`)
  - fork bombs, `mkfs`/`dd of=/dev/sd*`, recursive `chmod`/`chown` on `/`
- Each denial returns `route:"block"`, `blocked:true`, a stable `code` and a
  human `reason` (e.g. `destructive_root_delete`, `sql_delete_without_where`,
  `sensitive_file_read`, `remote_code_exec`, `bulk_mail`).
- `T1`/`T2` regexes (`dsc.gate`) remain only as a cheap pre-filter for
  natural-language policy phrases (prompt injection), not as the gate.
- Math: `PDV 17% na neto 2400` -> **2808.00**; `17% od 1450` -> 246,50 (Decimal, half-up).
- Diacritics fold: `Obriši` -> `obrisi` (risk match works on Bosnian text).
- SQLite response cache (TTL 6 h) keyed by a **SHA-256 of the full normalized
  request + tenant/session**, `/stats`.

## Run
```bash
pip install -r requirements.txt   # dsc, pinned by commit (gate + parse_amount)
python3 fastpath.py            # :8071
curl -s localhost:8071/optimize -d '{"text":"Obriši sve fajlove u /var/log"}'
# {"route":"block","blocked":true,"code":"catastrophic_command","reason":"...",...}
curl -s localhost:8071/optimize -d '{"text":"rm -fr /"}'
# {"route":"block","blocked":true,"code":"destructive_root_delete",...}
curl -s localhost:8071/optimize -d '{"text":"PDV 17% na neto 2400"}'
# {"route":"math_pdv","answer":"2808.00",...}
```
Tests: `python3 -m unittest discover -s tests -v`

### CLI and exit codes

```bash
python3 fastpath.py --check 'rm -fr /'   # prints JSON, exit 3
python3 fastpath.py --check 'zdravo'     # prints JSON, exit 0
```

| exit | meaning |
|------|---------|
| `0`  | request allowed/answered (may still route to `llm`) |
| `3`  | denied by the gate (`blocked:true`, with `code` + `reason`) |
| `2`  | usage error (missing `--check` argument) |

## Measured
- T1 block **0.03 ms**, T2 block **0.06–0.94 ms**, PDV **6.2 ms** cold first
  call (math is recomputed on every request, never served from the cache).
- LUMI MI250X guarded bench: false_success 19.7% raw -> **0/1,000**; 10k rerun (2026-11-04) **1/10,000 (FAIL)** — earlier 0/10,000 not reproduced; 114.4 rps @ CONC=512 (prior run).
- Related: https://github.com/gamai-io/crossnode-bench (DOI 10.5281/zenodo.23933835).

Apache-2.0.
## Tests
```bash
make test
```

## Cache safety

- The key is `dsc.cachekey.request_key` — **`v2:` + SHA-256** over the canonical
  JSON object `{"v","t","tenant","session","ctx"}`, where `t` is the full
  normalized request and `session` is the optional tenant (`sid` or `tenant` in
  the body, or `X-Tenant-ID`). Fields are JSON values, not `|`-joined
  substrings, so a delimiter in the text cannot collide with another tenant.
  Two different inputs or tenants never share an entry, and caller text is not
  stored in the key. Pre-v2 rows are unreachable (old `q:` keys): they miss
  once and age out by TTL. `cache_get` also refuses any non-v2 key.
- Deterministic math is computed **before** the cache lookup and is never
  read from it, so a stored answer cannot override `PDV ...` arithmetic
  (regression: storing `0.00` for a PDV query still returns `2808.00`).

## Security / deployment

- Default bind is `GAMA_FASTPATH_BIND=0.0.0.0` for LAN/Tailscale callers. On a public
  host, block the port at the firewall (verified on Contabo: ufw default-DROP, port 8071
  unreachable from an external node while 80/443 answer).
- `POST /store` is **loopback-only**. Remote callers must set `GAMA_FASTPATH_STORE_TOKEN`
  and send it as `X-Store-Token`; without it the endpoint answers `403`.
- Request bodies are capped by `GAMA_FASTPATH_MAX_BODY` (default 262144 bytes) and
  oversized requests get `413`, so one client cannot exhaust memory.
- The HTTP handler never echoes parser exceptions back to the caller.

## Money formats

`dsc.amount.parse_amount` (imported here, not copied) accepts BHS/EU/US thousands separators
deterministically (Decimal, half-up): `2400`, `2.400`, `2.400,00`, `1.234.567,89`, `2,400.00`
all resolve correctly. Regression tests cover these forms; the earlier regex stopped at the
first separator and returned `2.81` for `2.400,00`.

## How this is sold (and what it saves)

The gate is **free to adopt**: it is a deterministic pre-LLM step, and metering it would cost
more than it earns. What it returns, measured on our traffic (2026-11-23):

- `PDV 17% na neto 2400` → **2808.00 in 6.2 ms, 0 tokens**, versus 2.53 s and ~$0.0019 through a model.
- `rm -rf /`, `drop table`, `obrisi sve` → blocked in **0.03–0.06 ms** before any model runs.
- Every answer that never reaches the model is a call the customer does not pay for.

We charge for the harness and the audit around the gate (evidence receipts, replay), not for the
arithmetic. A buyer is shown their own intercepted-request count, not a percentage we computed
on our own workload.
