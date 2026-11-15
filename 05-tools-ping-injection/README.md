# Netis NC63 — Unauthenticated OS command injection via an incomplete blacklist in the ping/traceroute tool of skk_set.cgi

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

The diagnostics handler `FUN_0040ee48` (`tools_set`) embeds the `IpAddr` request parameter into a ping or
traceroute command line that is executed with `system()`. The only protection is an incomplete blacklist of
shell metacharacters that does not reject `;`, `&&`, backticks or `$()`, so an unauthenticated attacker can
run arbitrary commands as root. Both the ping (`type=1`) and traceroute (`type=2`) branches are affected.

## Affected Product

| | |
|---|---|
| Vendor | Netis |
| Product | NC63 |
| Firmware | V3.0.0.3327 (version string reported by the device: `Netis(NC63)-V3.0.0.3327`) |
| Architecture | MIPS32 little-endian, uClibc, no PIE |
| Component | `/bin/netis.cgi`, handler `FUN_0040ee48` (`tools_set`) |
| Type | OS Command Injection (CWE-78) / Incomplete Blacklist (CWE-184) |
| Authentication required | **None** |

## Root Cause

`FUN_0040ee48` builds `"ping -c 4 %s"` / `"traceroute %s"` with `IpAddr` via `sprintf()` and calls
`system()`. A short blacklist is applied beforehand, but it is incomplete: command separators and command
substitution survive it. No authentication check exists anywhere in the `skk_set` dispatch chain, and the
handler never reads `/tmp/boa_auth`.

## Proof of Concept (non-destructive)

```bash
curl -s -X POST --data-binary "tools_set=1&type=1&IpAddr=127.0.0.1;id>/tmp/o;" \
  http://<router>/cgi-bin/skk_set.cgi
```

`type=2` (traceroute) behaves identically.

### Observed result

`["SUCCESS"]` in the response, with the injected command executed as root; the output is readable through
the same endpoint family. Control test: `IpAddr=127.0.0.1` runs only ping.

## Impact

Unauthenticated remote code execution as root through a normal management function. Because the diagnostics
page is a regular feature, it is likely to be reachable through any WAN-side exposure as well.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8** (researcher self-assessment).

## Relationship to the other command-injection advisory

This is a **different handler and a different parameter** from the Wake-on-LAN / WPS-PIN injection
(`FUN_0040f0f0` / `FUN_0040e758` with `wakeup_mac` / `pin_host`). Those handlers apply no filter at all;
this one applies a filter that is incomplete. The fixes are separate: adding a filter here does not protect
the other two handlers, and validating a MAC/PIN format there does not protect this one.

## Repository files

| File | Content |
|---|---|
| `README.md` | This advisory |
| `poc/poc_find0005.sh` | Non-destructive reproduction script |

## Discovery

Discovered by Zimo-666 on 2026-10-17 via static reverse engineering with Ghidra and dynamic verification
on a rehosted device (QEMU system emulation of the vendor image). Vendor notified: pending.
