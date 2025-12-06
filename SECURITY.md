# Security Policy

## Overview

Don's System Monitor is a **local-first system utility** designed to operate without cloud services, external APIs, or telemetry.  
All monitoring, logging, and communication occur **entirely on machines you control**.

Security is treated as a practical concern: the tool aims to be transparent, inspectable, and predictable rather than opaque or network-dependent.

---

## Threat model (what this project does and does not protect against)

This project is designed to be secure in the following contexts:

- Local machine monitoring
- Private LAN or trusted-network remote viewing
- Headless or unattended operation on personal or homelab systems

This project is **not** designed to protect against:

- Malicious local users with OS-level access
- Compromised operating systems
- Exposure to untrusted public networks without additional protections (VPN, firewall rules, etc.)
- Advanced active attackers performing traffic interception or binary modification

---

## Remote access security

Remote monitoring uses a **simple authenticated TCP interface**.

Key points:
- No data is transmitted unless a client successfully authenticates
- A shared password is required before any system data is sent
- No discovery, broadcasting, or auto-pairing exists
- No internet-facing services are enabled by default

### Passwords
- Remote passwords are stored only in `sysmon.config.json`
- Passwords are **never logged**
- Default placeholder passwords should be changed immediately

You are responsible for:
- Choosing a strong password
- Restricting network access using a firewall when needed
- Avoiding exposure of the service to untrusted networks

---

## Data handling

- No telemetry
- No analytics
- No crash reporting
- No automatic updates
- No external servers

Collected data includes:
- System resource metrics (CPU, RAM, disk, temperature)
- Process names and resource usage
- Locally generated diagnostic logs

All data remains on the host system unless explicitly requested by a connected viewer.

---

## Binary builds and trust

Prebuilt executables are provided for convenience only.

Recommendations:
- Prefer building from source if you require full auditability
- Verify hashes if you redistribute internally
- Treat binaries as you would any other local utility

---

## Reporting security issues

If you believe you have found a **real security vulnerability**, please report it responsibly.

Preferred method:
- Open a **private GitHub issue** (or contact the maintainer directly if possible)

Please include:
- Clear steps to reproduce
- What data or access is impacted
- Whether the issue is local-only or remotely exploitable

Do **not** publicly disclose vulnerabilities before they are reviewed.

---

## License and modification notice

This project is licensed under the **Creative Commons CC BY-ND 4.0 International** license.

Important implications:
- You are free to use and redistribute the software
- **Derivative works may not be distributed**
- Security-related modifications must not be redistributed without permission
- This policy does not restrict private, local modifications for personal use

If you believe a security fix requires redistribution or collaboration, contact the maintainer to discuss acceptable approaches.

---

## Final note

Don's System Monitor is intended to be:
- Transparent
- Understandable
- Locally controlled

Security is achieved through simplicity, limited scope, and user-controlled deployment rather than complex abstractions or hidden services.
