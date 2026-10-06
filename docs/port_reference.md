# Port Reference

Reference information about common network ports. **This is general background material. These ports were not necessarily found on the target.** Only the actual scan results in `reports/security_report.md` count as findings.

An open port is not automatically a vulnerability. Exposure ratings are preliminary indicators of how much attention a port deserves if it is reachable from untrusted networks.

## Quick Table

| Port | Service | Preliminary exposure |
|---|---|---|
| 21 | FTP | High |
| 22 | SSH | Medium |
| 23 | Telnet | High |
| 25 | SMTP | Medium |
| 53 | DNS | Medium |
| 80 | HTTP | Medium |
| 110 | POP3 | Medium |
| 139 | NetBIOS Session | High |
| 143 | IMAP | Medium |
| 443 | HTTPS | Low |
| 445 | SMB | High |
| 993 | IMAPS | Low |
| 995 | POP3S | Low |
| 3306 | MySQL | High |
| 3389 | RDP | High |
| 5432 | PostgreSQL | High |
| 8080 | HTTP alternate | Medium |
| 8443 | HTTPS alternate | Medium |

## 21/tcp - FTP

- **Function:** File Transfer Protocol: transfers files between client and server.
- **Legitimate use / benefits:** Simple, widely supported file exchange and legacy system integration.
- **Security threats:**
  - Credentials and data sent in clear text (sniffing)
  - Anonymous login left enabled
  - Brute-force attempts against accounts
  - Outdated server software with known flaws
- **Common security concerns:** Plain FTP has no encryption. Check whether anonymous access is allowed (requires authorized review).
- **Defensive recommendations:**
  - Replace with SFTP or FTPS
  - Disable anonymous login
  - Restrict access by IP / firewall
  - Keep the FTP server patched

## 22/tcp - SSH

- **Function:** Secure Shell: encrypted remote login, command execution and file transfer.
- **Legitimate use / benefits:** Secure remote administration with strong encryption and key-based authentication.
- **Security threats:**
  - Brute-force / password guessing
  - Weak or default credentials
  - Outdated SSH versions with known flaws
  - Stolen or unprotected private keys
- **Common security concerns:** Generally appropriate for administration, but should not be open to the whole internet without hardening.
- **Defensive recommendations:**
  - Use key-based authentication, disable password login
  - Disable direct root login
  - Restrict source IPs or use a VPN/bastion host
  - Use fail2ban or rate limiting
  - Patch OpenSSH

## 23/tcp - Telnet

- **Function:** Unencrypted remote terminal access.
- **Legitimate use / benefits:** Largely obsolete; occasionally used for legacy network devices.
- **Security threats:**
  - All traffic including passwords in clear text
  - Session hijacking
  - Frequent target for automated credential attacks
- **Common security concerns:** Telnet should rarely be exposed. Its presence usually indicates a legacy or unmanaged device.
- **Defensive recommendations:**
  - Disable Telnet and use SSH
  - Block port 23 at the firewall
  - Isolate legacy devices that cannot be upgraded

## 25/tcp - SMTP

- **Function:** Simple Mail Transfer Protocol: sends and relays email between servers.
- **Legitimate use / benefits:** Required for email delivery from a mail server.
- **Security threats:**
  - Open relay abused for spam
  - User enumeration
  - Phishing/spoofing via weak SPF/DKIM/DMARC
  - Cleartext mail transfer without TLS
- **Common security concerns:** A web-only server normally does not need public SMTP. Verify relay settings during authorized review.
- **Defensive recommendations:**
  - Disable open relay
  - Require STARTTLS
  - Configure SPF, DKIM and DMARC
  - Close the port if no mail service is intended

## 53/tcp - DNS

- **Function:** Domain Name System: resolves domain names to IP addresses.
- **Legitimate use / benefits:** Essential for name resolution on authoritative or recursive DNS servers.
- **Security threats:**
  - DNS amplification (DDoS reflection) via open resolvers
  - Zone transfer information leakage
  - Cache poisoning on unpatched resolvers
- **Common security concerns:** Check whether the server is an open recursive resolver or permits zone transfers (authorized review).
- **Defensive recommendations:**
  - Disable recursion for external clients
  - Restrict zone transfers (AXFR) to secondary servers
  - Patch DNS software
  - Consider DNSSEC

## 80/tcp - HTTP

- **Function:** Hypertext Transfer Protocol: serves web pages without encryption.
- **Legitimate use / benefits:** Delivers web content; commonly used to redirect visitors to HTTPS.
- **Security threats:**
  - Traffic can be read or modified in transit
  - Web application flaws (XSS, SQL injection, etc.)
  - Information leakage via server banners or default pages
  - Outdated web server software
- **Common security concerns:** Expected on a web server. Best practice is to redirect all traffic to HTTPS.
- **Defensive recommendations:**
  - Redirect HTTP to HTTPS and enable HSTS
  - Hide version banners
  - Patch web server and application
  - Use a web application firewall (WAF) where appropriate

## 110/tcp - POP3

- **Function:** Post Office Protocol v3: downloads email from a mail server.
- **Legitimate use / benefits:** Simple mailbox retrieval for legacy email clients.
- **Security threats:**
  - Clear-text credentials when TLS is not used
  - Brute-force login attempts
- **Common security concerns:** Prefer the encrypted variant (POP3S, port 995).
- **Defensive recommendations:**
  - Use POP3S (995) or enforce STARTTLS
  - Disable if not needed
  - Enforce strong passwords / MFA

## 139/tcp - NetBIOS Session

- **Function:** NetBIOS session service used by older Windows file sharing.
- **Legitimate use / benefits:** Legacy Windows network file/printer sharing.
- **Security threats:**
  - Information disclosure
  - Null-session enumeration
  - Legacy SMB flaws
- **Common security concerns:** Should not be reachable from untrusted networks.
- **Defensive recommendations:**
  - Block at the firewall
  - Disable NetBIOS over TCP/IP if unused

## 143/tcp - IMAP

- **Function:** Internet Message Access Protocol: accesses and manages email on the server.
- **Legitimate use / benefits:** Lets users sync mail across multiple devices.
- **Security threats:**
  - Clear-text credentials when TLS is not used
  - Brute-force login attempts
- **Common security concerns:** Prefer the encrypted variant (IMAPS, port 993).
- **Defensive recommendations:**
  - Use IMAPS (993) or enforce STARTTLS
  - Disable if not needed
  - Enforce strong passwords / MFA

## 443/tcp - HTTPS

- **Function:** HTTP over TLS: serves web content over an encrypted connection.
- **Legitimate use / benefits:** Confidentiality, integrity and server authentication for web traffic.
- **Security threats:**
  - Weak TLS versions or ciphers
  - Expired or misconfigured certificates
  - Web application flaws still apply (encryption does not fix them)
  - Outdated web server software
- **Common security concerns:** Expected and desirable on a website. Review TLS configuration and certificate validity.
- **Defensive recommendations:**
  - Enable only TLS 1.2/1.3
  - Keep certificates valid and renewed
  - Enable HSTS
  - Patch the web server and application

## 445/tcp - SMB

- **Function:** Server Message Block: Windows file and printer sharing.
- **Legitimate use / benefits:** File sharing inside trusted internal networks.
- **Security threats:**
  - Wormable remote code execution flaws in unpatched systems (e.g. EternalBlue / MS17-010)
  - Anonymous or weak-credential share access
  - Ransomware spread
  - Information disclosure
- **Common security concerns:** SMB should not be exposed to the internet. Exposure indicates a serious network design concern.
- **Defensive recommendations:**
  - Block 445 at the perimeter firewall
  - Disable SMBv1
  - Apply Windows security updates
  - Require authentication and disable null sessions

## 993/tcp - IMAPS

- **Function:** IMAP over TLS: encrypted email access.
- **Legitimate use / benefits:** Secure mailbox access for email clients.
- **Security threats:**
  - Brute-force login attempts
  - Weak TLS configuration
- **Common security concerns:** Appropriate on a mail server; review TLS and authentication settings.
- **Defensive recommendations:**
  - Enforce strong passwords / MFA
  - Use modern TLS only
  - Rate-limit failed logins

## 995/tcp - POP3S

- **Function:** POP3 over TLS: encrypted email retrieval.
- **Legitimate use / benefits:** Secure mailbox download for email clients.
- **Security threats:**
  - Brute-force login attempts
  - Weak TLS configuration
- **Common security concerns:** Appropriate on a mail server; review TLS and authentication settings.
- **Defensive recommendations:**
  - Enforce strong passwords / MFA
  - Use modern TLS only
  - Rate-limit failed logins

## 3306/tcp - MySQL

- **Function:** MySQL/MariaDB database server.
- **Legitimate use / benefits:** Stores application data for websites and services.
- **Security threats:**
  - Brute-force or default credentials
  - Direct data exposure if accounts are weak
  - Unpatched database server flaws
- **Common security concerns:** Databases should normally listen only on localhost or a private network, not the internet.
- **Defensive recommendations:**
  - Bind to 127.0.0.1 or an internal interface
  - Firewall the port
  - Use least-privilege accounts and strong passwords
  - Patch the database server

## 3389/tcp - RDP

- **Function:** Remote Desktop Protocol: graphical remote access to Windows systems.
- **Legitimate use / benefits:** Convenient remote administration of Windows machines.
- **Security threats:**
  - Brute-force attacks
  - Credential theft
  - Past critical flaws (e.g. BlueKeep)
  - A common entry point for ransomware
- **Common security concerns:** RDP should not be directly exposed to the internet.
- **Defensive recommendations:**
  - Place behind a VPN or gateway
  - Enable Network Level Authentication (NLA)
  - Enforce MFA and account lockout
  - Restrict by IP and patch regularly

## 5432/tcp - PostgreSQL

- **Function:** PostgreSQL database server.
- **Legitimate use / benefits:** Stores application data for websites and services.
- **Security threats:**
  - Brute-force or default credentials
  - Overly permissive pg_hba.conf rules
  - Unpatched database server flaws
- **Common security concerns:** Databases should normally listen only on localhost or a private network.
- **Defensive recommendations:**
  - Limit listen_addresses and pg_hba.conf rules
  - Firewall the port
  - Use strong passwords and least privilege
  - Patch PostgreSQL

## 8080/tcp - HTTP alternate

- **Function:** Alternate HTTP port, often used for proxies, application servers or admin panels.
- **Legitimate use / benefits:** Runs a second web service or a development/application server beside the main site.
- **Security threats:**
  - Forgotten test or admin interfaces
  - Default credentials on management consoles
  - Unencrypted traffic
  - Unpatched application servers (e.g. Tomcat, Jenkins)
- **Common security concerns:** Identify exactly what is running here; non-standard web ports are often unintended exposure.
- **Defensive recommendations:**
  - Close the port if not needed
  - Require authentication and HTTPS
  - Restrict to internal networks
  - Patch the application server

## 8443/tcp - HTTPS alternate

- **Function:** Alternate HTTPS port, often used for admin consoles and application servers.
- **Legitimate use / benefits:** Encrypted access to a secondary web service or management interface.
- **Security threats:**
  - Exposed admin panels
  - Default credentials
  - Weak TLS configuration
  - Unpatched application servers
- **Common security concerns:** Identify what is running here and whether it needs to be public.
- **Defensive recommendations:**
  - Restrict admin interfaces to internal networks/VPN
  - Use strong authentication
  - Patch the application