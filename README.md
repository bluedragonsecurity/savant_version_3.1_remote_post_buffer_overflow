# CVE Request: Savant Web Server 3.1 — Denial of Service via HTTP POST Buffer Overflow

![rce](rce.png)

## Summary

Buffer overflow in Savant Web Server 3.1 allows remote unauthenticated attackers to
crash the server (denial of service) via a crafted HTTP POST request with an oversized
URI and body. The overflow overwrites EIP and EBP, causing an unhandled exception.
Existing CVEs for Savant (CVE-2002-1120 and CVE-2005-0338) cover the GET-method
overflow only. This vulnerability uses the POST method which hits a different code path.

---

## MITRE Form Fields

**Request Type:** Report Vulnerability / Request CVE ID

**Vulnerability Type:** Buffer Overflow (CWE-121: Stack-based Buffer Overflow)

**Vendor:** Savant Software (savant.sourceforge.net — abandoned/unmaintained)

**Product:** Savant Web Server

**Version:** 3.1

**Attack Type:** Remote, unauthenticated

**Impact:**
- Code Execution: potentially (EIP is fully controlled), but exploit only demonstrates DoS
- Denial of Service: yes
- Information Disclosure: no

**Affected Component:** HTTP POST request handler (port 80, default)

---

## Vulnerability Details

Savant Web Server 3.1 does not properly validate the length of the URI or body in
incoming HTTP POST requests. By sending a POST with a URI of 257 bytes (253 bytes
of padding + 4 bytes that land directly on EIP) followed by a body of 554 bytes, the
server crashes due to a stack-based buffer overflow.

The crash analysis in OllyDbg confirms full control over EIP and EBP:

```
EIP: 42424242   ("BBBB" — bytes at URI offset 253-256)
EBP: 41414141   ("AAAA" — from the URI padding)
```

This is a different code path from the GET-method overflow documented in CVE-2002-1120.
The GET-method exploits (EDB-781, EDB-1184, EDB-10434, EDB-18401, Metasploit module
exploit/windows/http/savant_31_overflow) all target the GET request handler. This POST
vulnerability is in a separate handler.

### Trigger

The PoC sends a single malformed POST request:

```
POST /<253 x 'A' + 4 x 'B'>\r\n\r\n<554 x 'D'>
```

The server crashes immediately upon processing. Sometimes the bug does not trigger on
the first attempt and the PoC needs to be re-sent.

### Crash analysis

Debugger output (OllyDbg attached to Savant.exe):

```
EAX: FFFFFFFF
ECX: 00002736
EDX: 00000007
ESP: 0102EA64
EBP: 41414141  <-- controlled (0x41 = 'A')
EIP: 42424242  <-- controlled (0x42 = 'B')
```

Stack dump shows the URI data ('A' bytes) and the POST method string visible in memory.
Full EIP control means this could likely be escalated to remote code execution,
but the submitted PoC demonstrates denial of service only.

---

## Timeline

- **~2013:** Vulnerability discovered
- **2026:** PoC cleaned up, requesting CVE assignment

---

## Discoverer

Antonius — Blue Dragon Security (bluedragonsec.com)
https://github.com/bluedragonsecurity

---

## References

- Exploit source code and PoC screenshots: https://github.com/bluedragonsecurity
- Savant Web Server project: https://savant.sourceforge.net/
- Related (GET-method, different code path): CVE-2002-1120, CVE-2005-0338
- Metasploit module (GET only): exploit/windows/http/savant_31_overflow

---

## Suggested CVE Description

Savant Web Server 3.1 contains a stack-based buffer overflow in the HTTP POST
request handler. A remote unauthenticated attacker can crash the server by sending
a POST request with an oversized URI (257+ bytes), causing EIP to be overwritten
and resulting in denial of service. This is a different vulnerability than
CVE-2002-1120 (which affects GET requests).

---

## CVSS 4.0 Estimate

- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Impact: High availability impact (server crash), no confidentiality/integrity impact demonstrated

Estimated base score: ~8.7 (High)
