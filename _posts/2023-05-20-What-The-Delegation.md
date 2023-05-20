---
layout: post
title:  "What the Delegation?"
category: Active Directory
---

In this article, we are going to take a look at the delegation extension within the Kerberos protocol for Active Directory. We will also dive into how to enumerate for accounts with this setting configured, how to exploit these accounts, and possible preventions against delegation, specifically unconstrained delegation.

- Note I: If you want to read something from someone with more knowledge than me, I recommend checking out this article - [Wagging The Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)

- Note II: The marvelous harmj0y has quite a few articles about delegation on his blog - [s4u2pwnage](https://blog.harmj0y.net/activedirectory/s4u2pwnage/)

**If anything here is stated incorrectly or you have any questions, please reach out to me and let me know!**

**Table of Contents**
* TOC
{:toc}

## Overview

To start, there are three different types of delegation when dealing with Kerberos:

1. Unconstrained Delegation
2. Constrained Delegation
3. Resource-Based Constrained Delegation


## Unconstrained Delegation

Unconstrained delegation allows an application to access separate resources with the credentials of another user or computer. **Any other account**. As an attacker, these accounts with unconstrained delegation enabled can make for great targets for escalating privileges.


Here is a capture from [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94) (Also in **References** ) for the basic workflow of authentication -

![ms-sfu-uncondeleg.PNG](/images/Active_Directroy/Delegation/ms-sfu-uncondeleg.PNG)

Each step of the process is walked through [here](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/1fb9caca-449f-4183-8f7a-1a5fc7e7290a) but what is key about this process is highlighted in step 8; "**To fulfill the user's request, Service 1 needs Service 2 to perform some action on behalf of the user. Service 1 uses the forwarded TGT of the user and sends that in a KRB_TGS_REQ to the KDC, asking for a ticket for Service 2 in the name of the user**.

What this means is that the inital TGT for the user is saved on Service 1 into the machine's memory! This allows us to extract this TGT to impersonate the user who has accessed Service 1.

So if a privileged user has logged into a machine allowed for unconstrained delegation, we can extract their TGT and impersonate this user.

### What To Look For

For an account to be used for unconstrained delegation, the computer/account must have the "**Trust this user/computer for delegation to any service (Kerberos only)**" setting turned on.

![uncon_deleg.png](/images/Active_Directroy/Delegation/uncon_deleg.PNG)

We can also use PowerShell (with the Active Directory module) to search for users/computers that have unconstrained delegation enabled.

```powershell
get-aduser -filter {TrustedForDelegation -eq $true} -properties * | select Name, servicePrincipalName
```

### Exploiting 

If a user logons onto a machine that we have already compromised and the machine is configured for unconstrained delegation, that user's credentials (TGT) is saved into memory. We can use tools such as [mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#list) to export the tickets that have been cached and use them to escalate privileges or move laterally.


## Constrained Delegation

The next type of delegation is constrained delegation. This extension limits a service's ability to delegate a user's credentials onto another service. Previously, we saw in the unconstrained delegation section that we only had to select an option to enabled delegation for an account. For constrained delegation, there is another step where we can select what services the "primary service" can use the client's credentials to authenticate with.

Lets take a look in Active Directory Users and Computers.
![con_deleg.png](/images/Active_Directroy/Delegation/con_deleg.PNG)



Here I created an account named "svc-condeleg" (hmm... I wonder what it is used for?) and under the delegation tab, we can see the account is configured for constrained delegation because the "**Trust this user for delegation to specified services only**. This means the "svc-condeleg" account's credentials can be delegated to those specifc services only. Unlike before where the account's TGT could be delegated to ANY service. Woo! Way more secure!.

There is also another set of options we have to choose from:
- "Use Kerberos only"
- "Use any protocol"

In order to utilize the S4U protocol, we have to select the second option. Once we dive into the exploitation section, we will take a look into why "Use Kerberos only" does not work.

But this isn't the only thing we need to check for the account. If we go check out the attribute editor section for the account, we need to look at two key attributes.
- msDS-AllowedToDelegateTo
- userAccountControl

Under the ```msDS-AllowedToDelegateTo``` attribute, we can find the list of SPNS the account can delegate to.

![con_deleg_msds.png](/images/Active_Directroy/Delegation/con_deleg_msds.PNG)

And in ```userAccountControl```, we can see the flag for ```TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION``` is set.

![con_deleg_uac.png](/images/Active_Directroy/Delegation/con_deleg_uac.PNG)


These attributes being set also dives into the **S4U** extensions which we will look at below.

Alright, so it looks like we have found the perfect target to exploit constrained delegation, lets dive into that next.

### Exploiting Constrained Delegation

I am going to follow along the [Rubeus docs for constrained delegation abuse](https://specterops.gitbook.io/ghostpack/rubeus/constrained-delegation-abuse) for this section but there are plenty of resources on how to do this online.

For my environment, I have a domain controller and a domain-joined workstation.
- MARVEL-DC.marvel.local
- marvel-ws1.marvel.local

I will be logged into the workstation as the service account, "svc_condeleg" and go through on how we can access the domain controller from there. Also note I have disabled Defender for my lab to demonstrate this attack.
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94
First, we can see I am logged in as "svc-condeleg" on marvel-WS1 and I cannot access the domain controller.
![ws1-condeleg](/images/Active_Directroy/Delegation/marvel-ws1-condeleg.PNG)

**Note**: Just to start "fresh" I ran ```klist purge``` in my powershell session

Using Rubeus, I generated the rc4 hash for account (it is assumed we already have compromised the account's credentials). Then with the hash, we can perform the operation to get onto the domain controller.

Now, we can generate a TGS to use in order to impersonate a privilegd user in the domain (like a Domain Admin).
![tgs_rubeus](/images/Active_Directroy/Delegation/tgs_rubeus.PNG)

Sorry for the cutoff but we can get the TGS using this command referenced in the guide or below:
```powershell
.\Rubeus.exe s4u /user:svc_condeleg /rc4:<hash> /impersonateuser:mknight
```
* The mknight account is a domain admin for my lab. Can you tell I like marvel yet? But don't worry, its still DC > .


Next we can use the TGS to access one of the SPNs current set for our account to be delegated to on the domain controller.
```powershell
.\Rubeus.exe s4u /ticket:<tgt data> /tgs:<tgs data> /msdsspn:cifs/marvel-dc.marvel.local /ptt
```

After this, we can see the TGS we need to access the cifs service on the domain controller was loaded into our PS session!
![tgs_DA_cifs_rubeus](/images/Active_Directroy/Delegation/tgs_rubeus_cifs_success.PNG)

Now lets see if we can access the domain controller.
![dc_access](/images/Active_Directroy/Delegation/rubeus_s4u_success_dc.PNG)

Nice! We are in!

![dc_proof](/images/Active_Directroy/Delegation/dc_proof_CD.PNG)


#### Use Kerberos Only

Earlier in this section, I mentioned how if the object has the "Use Kerberos Only" option selected, we won't be able to perform the same technique done above. Lets take a look and see what happens when an account is configured this way.

In the image below, we see the svc-condeleg account is configured to "Use Kerberos only". Now lets go back to the workstation and see what happens.

![condeleg_kerb_only](/images/Active_Directroy/Delegation/condeleg_kerb_only.PNG)


We can perform the same commands above to generate the TGT and TGS for the svc-condeleg account but once we try to use that TGS as the mknight account (Domain Admin), we are thrown an error.

![kdc_badoption](/images/Active_Directroy/Delegation/kdc_bad_option.PNG)

Well, why is that?

If we inject the TGS into memory, and run ```klist```, we will find that the ticket does not hav the ```FORWARDABLE``` flag set.

![tgs_not_fwdable](/images/Active_Directroy/Delegation/tgs_not_fwdable.PNG)

Now reading throw [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94) , Section 1.3.2 mentions how S4UProxy requires the forwardable flag be set and if not, the request will fail. This will then return the ```KDC_BADOPTION``` we saw from Rubeus.


When we dive into the S4U section of this post, I will be referencing most of the images shown here because constrained delegation relies heavily on the S4U extension but we won't worry about that right now.



## S4U2Self and S4U2Proxy

Before we talk about the final type of delegation, Resource Based Constrained Delegation, I wanted to give the rundown about S4U2Self and S4U2Proxy since I have been referencing it a TON.

So, what is the difference?


To pretty much state what is written in MS-SFU (Referenced below), what makes these extensions unique is that the **client name**, **realm**, and **authorization data** are of the **user**, not the service making the TGS request. This is different than what is written in RFC 4120 which states that the service ticket request will contain the paramters earlier but of the **service**, not the user.  

S4U2Self allows a service (Service 1) to obtain a TGS to itself on behalf of the user. This essntially lets the user authenticate to the service using Kerberos even if the original method of authentication was done with a different protocol.

S4U2Proxy gets invoked once the requesting user wants to access another service (Service 2) but in order for this be completed, Service 1 needs a valid TGS (to access Service 1 from the client) in order for the user to obtain a TGS to access Service 2.



In this diagram, we can see that Service 2 allows Service 1 to access it's resources on the behalf of the client using the TGS of the user. There are two conditions that needs to be met in order for Service 1 to access Service 2 (Step 5 under Figure 2)

1. **Service 1 must have a valid TGT from the KDC**
2. **Service 1 has a valid TGS for the user to access Service 1 with the ```FORWARDABLE``` flag set**

As we have seen above, if the TGS is missing the ```FORWARDABLE``` flag, the process fails.


![s4u_diagram.png](/images/Active_Directroy/Delegation/s4u_diagram.PNG)

Figure 2 from [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)





## Resource Based Constrained Delegation

### Overview

The final type of delegation, resource-based constrained delegation (rbcd), allows the service requesting to be accessed to control what other services are allowed to delegate to itself. This essentially flips the flow of trust for when Service 1 authenticates to Service 2. Instead of allowing Service 1 delegation capabilities to Service 2, Service 2 is configured to trust Service 1 for delegation.


### What To Look For

When enumerating for Resource Based Constrained Delegation, we are looking for users/computers with the ```PrincipalsAllowedToDelegateToAccount``` attribute filled in.

Or we look for the ```msDS-AllowedToActOnBehalfOfOtherIdentity``` attribute to be filled in.


In our lab, we can see this user account ```svc-rbcd``` has delegation permissions with the Domain Controller.

```powershell
Get-ADUser svc-rbcd -Properties * | Select-Object Name, PrincipalsAllowedToDelegateToAccount
```

![rbcd-enum.png](/images/Active_Directroy/Delegation/rbcd-enum.PNG)


Great! We can assume we have compromised this service account and exploit this misconfiguration to access the Domain Controller.


### Exploitation

Using Rubeus, we generate the neccesary TGS to access the file system on the Domain Controller.

```powershell
.\Rubeus.exe s4u /user:svc-rbcd /rc4:<hash> /domain:marvel.local /msdsspn:cifs/marvel-dc.marvel.local /impersonateuser:mknight /ptt
```

Once we have this ticket in memory, we can then access the folders on the domain controller. Or we can use ```ldap/marvel-dc.marvel.local``` as the ```msdsspn``` flag and try to DC Sync (Which I didn't know until reading HarmJ0y's article above. Pretty cool!)

![rbcd-success.png](/images/Active_Directroy/Delegation/rbcd-success.PNG)



## References
- [Microsoft article about Constrained Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Wagging The Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [Microsoft Technical Document - MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [SpecterOps Article for Rubeus and Delegation](https://specterops.gitbook.io/ghostpack/rubeus/constrained-delegation-abuse)
- One of many resources online to use as a guide - [IRedTeam](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#trial-and-error)