# Netis NC63 — Unauthenticated OS command injection in the Wake-on-LAN and WPS-PIN handlers of skk_set.cgi

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

The `skk_set.cgi` action handlers `FUN_0040f0f0` (wakeup_set) and `FUN_0040e758` (wps_set) build shell
command lines with `sprintf()` from the `wakeup_mac` / `pin_host` request parameters and execute them with
`system()`. Neither handler validates the parameter format nor escapes shell metacharacters, so an
unauthenticated attacker can append arbitrary commands that run as root.

## Affected Product

| | |
|---|---|
| Vendor | Netis |
| Product | NC63 |
| Firmware | V3.0.0.3327 (version string reported by the device: `Netis(NC63)-V3.0.0.3327`) |
| Architecture | MIPS32 little-endian, uClibc, no PIE |
| Component | `/bin/netis.cgi`, handlers `FUN_0040f0f0` and `FUN_0040e758` |
| Type | OS Command Injection (CWE-78) / CWE-77 |
| Authentication required | **None** |

## Root Cause

`FUN_0040f0f0` formats a Wake-on-LAN command using `wakeup_mac` and calls `system()`; `FUN_0040e758` does
the same with `pin_host` for the WPS PIN. Neither validates the value against a MAC or PIN format, and
neither escapes shell metacharacters. The dispatch chain `FUN_004138a0` → `FUN_004134c8` performs no
authentication check, and the handlers never read `/tmp/boa_auth`, so a request without any cookie reaches
the sink.

## Proof of Concept (non-destructive)

```bash
curl -s -X POST --data-binary \
  "wakeup_set=1&wakeup_mac=00:11:22:33:44:55;/bin/touch\${IFS}/tmp/pwn_wol;" \
  http://<router>/cgi-bin/skk_set.cgi
```

The same technique with `wps_set=1&pin_host=<payload>` behaves identically.

### Observed result

`["SUCCESS"]` in the response, with `/tmp/pwn_wol` created as root in the rehosted device; command output
is readable through the same endpoint family. Control test: the same request without shell metacharacters
only performs the wake-up and creates nothing.

## Impact

Unauthenticated remote code execution as root, i.e. complete device compromise. The same endpoint also
exposes the WPS handler, giving two independent injection points in one request path.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8** (researcher self-assessment).

## Relationship to the other command-injection advisory

This is a **different handler and a different parameter** from the ping/traceroute injection in
`tools_set` (`FUN_0040ee48`), and the two differ in kind: `tools_set` applies an incomplete blacklist that
this pair does not have at all. Removing the blacklist bypass does not affect these handlers, and removing
the `system()` calls here does not affect `tools_set`.

## Repository files

| File | Content |
|---|---|
| `README.md` | This advisory |
| `poc/poc_find0004.sh` | Non-destructive reproduction script |

## Discovery

Discovered by Zimo-666 on 2026-10-17 via static reverse engineering with Ghidra and dynamic verification
on a rehosted device (QEMU system emulation of the vendor image). Vendor notified: pending.
