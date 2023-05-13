---
layout: post
title: Kerberoasting
category: Red Teaming
---

**Table of Contents**

* TOC
{:toc}


# Overview

Kerberoasting is a technique used by attackers to request a service ticket (TGS) to access a specific service then take that ticket offline for cracking. If a valid TGT is presented to the KDC to access this service, a valid TGS is sent back to the client. This means in order to use this technique, we MUST be a valid user within a network/domain.

Why this attack is so effective is that when the KDC responds back with the TGS, the ticket is encrypted with the password of the service account used to run the service requesting to be accessed.

Here is a diagram from [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/b4af186e-b2ff-43f9-b18e-eedb366abf13) that shows a basic overview of the Kerberos protocol.

![kerberos_diagram.png](/images/Red_Teaming/kerberos_diagram.PNG)


Kerberoasting takes place in Steps 3 and 4 within that diagram where the client sends a ```KRB_TGS_REQ``` to the KDC. Then the KDC returns the ```KRB_TGS_REP```


# Enumeration

Once we have established a foothold within an Active Directory environment, we can begin the enumeration process of targeting user accounts with the ```servicePrincipalName``` attribute filled in. Usually if a user object in Active Directory has that attribute filled in, that means the account is being used to run a specific service.

Instead of using different tools to enumerate for these accounts, a simple PowerShell command should give us what we need.

```powershell
Get-ADUser -filter {servicePrincipalName -like "*"} -Properties * | Select Name, servicePrincipalName, kerberosEncryptionType
```

Running this within my AD lab, we find a few accounts that we can kerberoast.

![kerberoast_enumeration.png](/images/Red_Teaming/kerberoast_enumeration.PNG)

We can also see that one account uses RC4 encryption. If we find an account using RC4, we can target this account and have a better chance at cracking the ticket we get from kerberoasting since RC4 is a weaker encryption type comapred to AES 128/256.


# Exploitation

Now that we have found some accounts we can target, lets start roastin'!

There plenty of tools out there like [Get-UserSPNs](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) and [Rubeus](https://github.com/GhostPack/Rubeus#kerberoast) but I am just going to use Rubeus for this article.


I have Rubeus downloaded onto my Domain Controller (MARVEL-DC) and will use the [kerberoast method](https://specterops.gitbook.io/ghostpack/rubeus/roasting#kerberoast) to requst a TGS.

- Note: You DON'T need to be a privileged user in a domain OR have access to a Domain Controller to perform this attack. This can simply be done as a standard user within a network.

```powershell
.\Rubeus kerberoast /user:svc_condeleg /nowrap
```

![kerberoast_svc_condeleg.png](/images/Red_Teaming/kerberoast_svc_condeleg.PNG)

Nice! We got what we needed. Now we take the hash portion of the output offline and can crack it using JtR/Hashcat to get the service account's password.

We can also see this service account uses RC4 encryption so cracking this ticket might be a little easier.

# Ways to Defend Against Kerberoasting

Unfortunately, there really isn't a way to "prevent" this attack within an environment since this is how the Kerberos protocol works though are some dections that might help in the event your network might be under attack.

1. Setting detections up against a fake service accout in your environment (This idea was greatly explained by Sean Metcalf on his [blog](https://adsecurity.org/?p=3513))

2. Monitoring for RC4 downgrades of service ticket responeses.
    - If an service account is configured to use AES 128/256 level encryption but it is noticed that a RC4 ticket was sent, this might be something to look into

3. Monitor accounts that still use RC4 encryption in your environment.
    - Accounts that use RC4 encryption are prime targets for attackers since its easier to crack those tickets so be weary of when these accounts are in use.