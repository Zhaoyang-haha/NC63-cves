# Netis NC63 (V3.0.0.3327) — Security Advisories

This repository documents four independently discovered vulnerabilities in the **Netis NC63** router
firmware **V3.0.0.3327**. All issues were found by static reverse engineering of the firmware image
together with dynamic verification on an emulated device (QEMU system emulation of the original firmware;
no physical hardware was modified). Every advisory contains a non-destructive proof of concept.

> **Status:** CVE: Not assigned (identifiers requested). Vendor notification: pending.
> Repository published for coordinated disclosure.

## Affected Product

| | |
|---|---|
| Vendor | Netis |
| Product | NC63 |
| Firmware | V3.0.0.3327 (version string reported by the device: `Netis(NC63)-V3.0.0.3327`) |
| Architecture | MIPS32 little-endian, uClibc, no PIE |
| Web server | Boa 0.94.14rc21 on TCP/80 |
| CGI dispatcher | `/bin/netis.cgi`, running as **root** |

## Advisories

| # | Advisory | CWE | CVSS 3.1 |
|---|---|---|---|
| 1 | [Unauthenticated hidden diagnostic endpoint enables telnetd and yields a root shell](01-mptoolenable-telnet-backdoor/) | `CWE-306` | 8.8 |
| 2 | [Pre-authentication stack buffer overflow with program-counter control in the generic MIB value parser of skk_set.cgi](03-http-param-parser-overflow/) | `CWE-121` | 8.8 |
| 3 | [Unauthenticated OS command injection in the Wake-on-LAN and WPS-PIN handlers of skk_set.cgi](04-wakeup-wps-command-injection/) | `CWE-78` | 8.8 |
| 4 | [Unauthenticated OS command injection via an incomplete blacklist in the ping/traceroute tool of skk_set.cgi](05-tools-ping-injection/) | `CWE-78` | 8.8 |

Directory names retain the internal finding numbers, so the paths do not match the order above.

## Common precondition — and why it is not the vulnerability

Boa forwards every request whose path ends in `.cgi` to `/bin/netis.cgi` (a 151 KB dispatcher, function
`FUN_00405244`, dispatch table at `0x00434080`) **before any authorization logic runs**. Authentication is
implemented only inside individual `login.cgi`-style handlers, via the `/tmp/boa_auth` flag.

All four advisories share that precondition, but each has its own distinct defect and sink:

- **#1** — a hidden dispatch-table entry that calls `system()` to start telnetd, checking no credential.
- **#2** — `strcpy()` / width-less `sscanf()` of a POST value into a stack buffer, reachable to saved control data.
- **#3** — `sprintf()` into a shell command with **no filtering at all** (`wakeup_mac`, `pin_host`).
- **#4** — `sprintf()` into a shell command behind an **incomplete blacklist** that omits `;` and `$()`.

Advisories #3 and #4 are separate handlers with separate argument sets, and the two differ in kind (no
filter versus an incomplete one); fixing either leaves the other exploitable.

## Related advisories for this product (not duplicated here)

| Existing CVE | Scope | Why it is not covered here |
|---|---|---|
| CVE-2024-48455 | information disclosure via `skk_get.cgi` (`mode_name`, `wl_link`) | read-only leak; no write or crash primitive |
| CVE-2024-48456 | information disclosure via the `password` argument of the password page | read-only leak; no write primitive |
| CVE-2024-48457 | information disclosure via `skk_set.cgi` / `start_wifi.sh` | different sink |
| CVE-2026-73673 | unauthenticated firmware update (`upload_fw.cgi`), no signature check | concerns authentication and signature verification of firmware images; unrelated to command construction or stack copies |
| CVE-2026-76070 | stack overflow in the Base64 **decoder** used by the login handler | different function and opposite data direction |
| CVE-2026-76071 | stack overflow via width-less `sscanf` in `ipFilterList=mod` / `destHost` | same parser function, but a different action and parameter; see advisory #2 |

None of the four advisories here concerns firmware update, Base64 decoding, or the `ipFilterList`
parameter.

## Disclosure timeline

- 2026-10-17 — vulnerabilities verified against the vendor firmware image.
- 2026-10-17 — advisory package prepared; vendor notification pending.
- CVE identifiers requested through VulDB — pending.

## Repository layout

| Path | Content |
|---|---|
| `01-mptoolenable-telnet-backdoor/` | Advisory, raw request, serial-console evidence |
| `03-http-param-parser-overflow/` | Advisory, PoC that demonstrates program-counter control |
| `04-wakeup-wps-command-injection/` | Advisory, PoC script |
| `05-tools-ping-injection/` | Advisory, PoC script |

## License

The advisory text is released under CC BY 4.0; the proof-of-concept code under the MIT license
(see [`LICENSE`](LICENSE)).

All proof-of-concept code is non-destructive and intended for authorized testing against devices you own
or are explicitly permitted to test.
