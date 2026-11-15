# Netis NC63 — Pre-authentication stack buffer overflow with program-counter control in the generic MIB value parser of skk_set.cgi

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

The generic MIB value parser `FUN_0040f7f4` in `netis.cgi` copies attacker-controlled POST values into a
stack buffer with `strcpy()` for several MIB types, and uses width-less `sscanf("%s")` for another,
without any length validation. The saved return address is reachable from the request body, so arbitrary
non-NUL bytes — including binary data — can be written over saved control data. **Program-counter control
was verified: the CPU reported `$epc = 0x44444444`, i.e. four attacker-supplied `D` bytes.**

## Affected Product

| | |
|---|---|
| Vendor | Netis |
| Product | NC63 |
| Firmware | V3.0.0.3327 (version string reported by the device: `Netis(NC63)-V3.0.0.3327`) |
| Architecture | MIPS32 little-endian, uClibc, no PIE |
| Component | `/bin/netis.cgi`, handler `FUN_0040f7f4` |
| Type | Stack-based Buffer Overflow (CWE-121) / Out-of-bounds Write (CWE-787) |
| Authentication required | **None** |

## Root Cause

`skk_set.cgi` dispatches named actions to `FUN_0040f7f4(params, action, mib_table, pMib)`. For the
IPv4/IPv6 MIB types the function performs `strcpy(dst, value)` into a stack buffer with the value taken
verbatim from the POST body; for type `0xc` it uses width-less `sscanf("%s")`. No length or character
validation is applied. The POST body is not URL-decoded for binary bytes, so this is effectively a
write-what-where primitive into the stack. The dispatcher chain performs no authentication check and the
handler never reads `/tmp/boa_auth`.

> **Note on frame geometry.** Two figures circulate for this frame: an early static read gave a 128-byte
> buffer with the saved `$ra` 296 bytes above it; the PoC that actually produced `epc = 0x44444444` uses a
> 404-byte payload, which places the saved `$ra` at offset 400 (392 filler bytes, then saved `$s0`, saved
> `$fp`, saved `$ra`). The tested figure is the one reproduced below. The exact buffer base and size
> should be re-confirmed against the disassembly before being quoted.

## Proof of Concept (non-destructive)

```bash
curl -s -X POST --data-binary \
  "lan_ip_set=mod&lanIpAddr=<404-byte payload: 392 x 'A', 'BBBB', 'CCCC', 'DDDD'>" \
  http://<router>/cgi-bin/skk_set.cgi
```

A script that builds the payload byte-exactly is provided at
[`poc/poc_find0003_pc.py`](poc/poc_find0003_pc.py).

### Observed result

The HTTP response is empty (the process dies) and the serial console reports `SIGSEGV ... epc = 44444444`
— the instruction pointer is controlled by the four bytes that land on the saved return address. Control
test: the same request with a short value returns `["SUCCESS"]` and the CGI exits normally.

## Impact

Unauthenticated remote code execution as root. The web stack runs as root; the binaries are non-PIE and
libuClibc / libapmib are mapped at fixed addresses, so a ret2libc / ret2system chain is practical. The only
length limit is the request size.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8** (researcher self-assessment).

## Relationship to existing advisories

This is the same function reached by a different action and parameter than CVE-2026-76071
(`ipFilterList=mod` with `destHost`, a width-less `sscanf` sink). Here the action is `lan_ip_set=mod` and
the value reaches a `strcpy` sink through `lanIpAddr`. Different action, different parameter, different
copy primitive; the parser accepts both, so fixing one path does not remove the other.

## Repository files

| File | Content |
|---|---|
| `README.md` | This advisory |
| `poc/poc_find0003_pc.py` | Builds the 404-byte payload and sends it |

## Discovery

Discovered by Zimo-666 on 2026-10-17 via static reverse engineering with Ghidra and dynamic verification
on a rehosted device (QEMU system emulation of the vendor image). Vendor notified: pending.
