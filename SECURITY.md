# Security policy — gama-fastpath

## Reporting

E-mail **renato@gamatrade.ba** with the subject `[gama-fastpath-security]`. Please include the
version or commit, a minimal reproduction, and what an attacker gains. Do not open a
public issue for something exploitable before it is fixed.

There is no bug bounty and no guaranteed response time. Expect an acknowledgement if the
report is actionable.

## Scope

The deterministic gate is an **input filter, not a sandbox**. It parsed shell/SQL intent
and refuses recognised destructive commands, but a filter can be bypassed by something it
does not model. Do not treat "the gate allowed it" as permission to run an untrusted
command. The cache is scoped by a request hash; if you believe two requests can collide,
that is a security report.

## What this project does and does not promise

It is open-source software provided as-is. There is no warranty, no service-level
agreement and no claim that it is free of defects. Reports are read on a best-effort
basis; a fix is not guaranteed.
