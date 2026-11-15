# VulDB Submission Sheet — Netis NC63 V3.0.0.3327

Four entries. Submit **one at a time** (fill, click Add, start a new form). Each entry has exactly the
six fields the form asks for. `Description` is plain text — the form disables markup, so paste the block
verbatim without the fence.

---

## ENTRY 1 — NC63-F1

### Vendor
```
Netis
```

### Product
```
NC63
```

### Version or Commit
```
V3.0.0.3327
```

### Vulnerability Class
```
Missing Authentication for Critical Function (CWE-306)
```

### Description
```
An authentication bypass vulnerability was discovered in Netis NC63 firmware V3.0.0.3327. The Boa web server forwards every request whose path ends in ".cgi" to the netis.cgi dispatcher without an authorization check. One of the dispatched endpoints is a hidden diagnostic handler whose name is the Base64 encoding of "mptoolenable". Requesting it starts the BusyBox telnet daemon on TCP/23 with root privileges, and the diagnostic account then provides a uid=0 shell. Root cause: The dispatch table at 0x00434080 pairs endpoint names with handlers; the entry for "bXB0b29sZW5hYmxl.cgi" points to FUN_0040e460. FUN_0040e460 never reads /tmp/boa_auth (the flag the rest of the CGI uses as its authentication state) and calls system() with the telnetd start-up command. Because boa routes every *.cgi path to netis.cgi before any authorization logic, the handler is reachable by anyone who can open TCP/80. Impact: Any host that can reach the management interface obtains full root control without credentials: persistent firmware modification, traffic interception, lateral movement. LAN vector (AV:A) is scored; if the interface is exposed to WAN, AV:N applies and the score becomes 9.8. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8). A non-destructive proof of concept and the full technical analysis are published in the advisory linked below.
```

### Advisory / Exploit / Proof-of-Concept
```
https://github.com/Zhaoyang-haha/NC63-cves/tree/main/01-mptoolenable-telnet-backdoor
```

---

## ENTRY 2 — NC63-F3

### Vendor
```
Netis
```

### Product
```
NC63
```

### Version or Commit
```
V3.0.0.3327
```

### Vulnerability Class
```
Stack-based Buffer Overflow (CWE-121)
```

### Description
```
A stack-based buffer overflow vulnerability was discovered in Netis NC63 firmware V3.0.0.3327. The generic MIB value parser FUN_0040f7f4 copies attacker-controlled POST values into a stack buffer with strcpy() for several MIB types, and uses width-less sscanf("%s") for another type, without any length validation. The saved return address is reachable from the request body, so a 404-byte value controls it. The instruction pointer was set to 0x44444444 (four attacker-supplied "D" bytes) in our test. Root cause: skk_set.cgi dispatches named actions to FUN_0040f7f4(params, action, mib_table, pMib). For the IPv4/IPv6 MIB types the function performs strcpy(dst, value) into a stack buffer with the value taken verbatim from the POST body; for type 0xc it uses width-less sscanf("%s"). No length or character validation is applied, and the POST body is not URL-decoded for binary bytes, so the write content is fully attacker-controlled. The dispatcher chain performs no authentication check and the handler never reads /tmp/boa_auth. Impact: Unauthenticated remote code execution as root. The web stack runs as root; the binaries are non-PIE and libuClibc/libapmib are mapped at fixed addresses, so a ret2libc/ret2system chain is practical. The only length limit is the request size. This is a different action and parameter from CVE-2026-76071 (ipFilterList=mod / destHost, a width-less sscanf sink): here the action is lan_ip_set=mod and the value reaches a strcpy sink through lanIpAddr. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8). A non-destructive proof of concept and the full technical analysis are published in the advisory linked below.
```

### Advisory / Exploit / Proof-of-Concept
```
https://github.com/Zhaoyang-haha/NC63-cves/tree/main/03-http-param-parser-overflow
```

---

## ENTRY 3 — NC63-F4

### Vendor
```
Netis
```

### Product
```
NC63
```

### Version or Commit
```
V3.0.0.3327
```

### Vulnerability Class
```
OS Command Injection (CWE-78)
```

### Description
```
An OS command injection vulnerability was discovered in Netis NC63 firmware V3.0.0.3327. The Wake-on-LAN handler FUN_0040f0f0 and the WPS-PIN handler FUN_0040e758 build shell command lines with sprintf() from the wakeup_mac / pin_host request parameters and execute them with system(). Neither handler validates the parameter format nor escapes shell metacharacters, so an unauthenticated attacker can append arbitrary commands that run as root. Root cause: FUN_0040f0f0 formats a WoL command using wakeup_mac and calls system(); FUN_0040e758 does the same with pin_host for the WPS PIN. The dispatch chain FUN_004138a0 -> FUN_004134c8 performs no authentication check and the handlers do not read /tmp/boa_auth, so a request without any cookie reaches the sink. Impact: Unauthenticated remote code execution as root, i.e. complete device compromise. The same endpoint also exposes the WPS handler, giving two independent injection points. These handlers apply no input filter at all, unlike the diagnostics handler in a separate advisory, so fixing one does not fix the others. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8). A non-destructive proof of concept and the full technical analysis are published in the advisory linked below.
```

### Advisory / Exploit / Proof-of-Concept
```
https://github.com/Zhaoyang-haha/NC63-cves/tree/main/04-wakeup-wps-command-injection
```

---

## ENTRY 4 — NC63-F5

### Vendor
```
Netis
```

### Product
```
NC63
```

### Version or Commit
```
V3.0.0.3327
```

### Vulnerability Class
```
OS Command Injection (CWE-78)
```

### Description
```
An OS command injection vulnerability was discovered in Netis NC63 firmware V3.0.0.3327. The diagnostics handler FUN_0040ee48 embeds the IpAddr request parameter into a ping or traceroute command line that is executed with system(). The only protection is an incomplete blacklist of shell metacharacters that does not reject ";", "&&", backticks or $(), so an unauthenticated attacker can run arbitrary commands as root. Both the ping (type=1) and traceroute (type=2) branches are affected. Root cause: FUN_0040ee48 builds "ping -c 4 %s" / "traceroute %s" with IpAddr via sprintf and calls system(). A small blacklist is applied beforehand, but it is incomplete: command separators and command substitution survive it. No authentication check exists in the skk_set dispatch chain, and the handler never reads /tmp/boa_auth. Impact: Unauthenticated remote code execution as root through a normal management function. Because the diagnostics page is a regular feature, it is likely reachable through any WAN-side exposure as well. This is a different handler and parameter from the Wake-on-LAN / WPS-PIN advisory, and it is guarded by a filter that those handlers do not have, so fixing one does not fix the others. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8). A non-destructive proof of concept and the full technical analysis are published in the advisory linked below.
```

### Advisory / Exploit / Proof-of-Concept
```
https://github.com/Zhaoyang-haha/NC63-cves/tree/main/05-tools-ping-injection
```

---

## Checkboxes

| Box | When to tick |
|---|---|
| `Request a CVE for this new vulnerability` | Tick on all four |
| Prerequisite (1) — **Vendor contacted beforehand** | Tick **only after** the vendor e-mail has been sent and the sent page captured |
| Prerequisite (2) — no CVE assigned yet | Satisfied |
| Prerequisite (3) — not submitted to another CNA | Satisfied |

---

## Before submitting

1. **Confirm `V3.0.0.3327` is still the latest firmware** on the vendor support page. If a newer build
   exists, write `through V3.0.0.3327` — the wording the existing CVE-2026-76070 / 76071 records use.
2. **Verify the two figures in Entry 1's root cause.** Internal notes give conflicting counts for the
   dispatch table (16 entries / index 6 versus 10 endpoints / index 5). The description above refers to the
   entry by endpoint name so it holds either way, but the correct figures should be confirmed in Ghidra
   before anything cites an index.
3. **Verify Entry 2's frame geometry.** The tested PoC uses a 404-byte payload (saved `$ra` at offset 400);
   an earlier static read gave a 128-byte buffer with `$ra` at 296. The description quotes only the tested
   payload length.
4. **Keep the descriptions above in sync with the repository.** Each advisory's `README.md` carries the
   same technical facts; a reviewer may compare them.
