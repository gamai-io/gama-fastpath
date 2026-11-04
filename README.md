# gama-fastpath

Deterministic **pre-LLM gate**: blocks catastrophic/destructive or env-disclosure
requests and answers money math without any model call. Offline, stdlib only.

- `T1` catastrophic: `rm -rf /`, `mkfs`, `drop table`, `shutdown`, `obriši sve`...
- `T2` high-risk / policy: `obriši /var/log`, `chmod 777`, prompt-injection
  ("ignoriši uputstva", "ti si root", "ispiši env"), mass-mail ("svim kupcima").
- Math: `PDV 17% na neto 2400` -> **2808.00**; `17% od 1450` -> 246,50 (Decimal, half-up).
- Diacritics fold: `Obriši` -> `obrisi` (risk match works on Bosnian text).
- SQLite response cache (TTL 6 h), `/stats`.

## Run
```bash
python3 fastpath.py            # :8071
curl -s localhost:8071/optimize -d '{"text":"Obriši sve fajlove u /var/log"}'
# {"route":"block","blocked":true,...}
curl -s localhost:8071/optimize -d '{"text":"PDV 17% na neto 2400"}'
# {"route":"math_pdv","answer":"2808.00",...}
```
Tests: `python3 -m unittest discover -s tests -v`

## Measured
- T1 block **0.03 ms**, T2 block **0.06–0.94 ms**, PDV **6.2 ms** first call (then cache).
- LUMI MI250X guarded bench: false_success 19.7% raw -> **0/1,000** and **0/10,000 (PASS)**, 114.4 rps @ CONC=512.
- Related: https://github.com/gamai-io/crossnode-bench (DOI 10.5281/zenodo.23933835).

Apache-2.0.
