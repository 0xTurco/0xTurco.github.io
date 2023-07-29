---
layout: post
title:  "Kerberos Delegation Attacks - From a Defenders Perspective"
category: Active Directory
---

**Table of Contents**
* TOC
{:toc}

## Intro

I previously did a brief article about [attacking kerberos delegation](https://0xturco.github.io/active%20directory/2023/05/20/What-The-Delegation.html) but after sometime, I decided to come back do a quick writeup about how defenders can detect and try to mitigate this vector.


## Identifying Objects with Delegation Enabled

In order to prevent and detect these type of attacks, defenders should know what computers and accounts in their environment have this settings enabled. Without knowing where these configurations exist, security engineers and the SOC can leave themselves susceptible to this attack.

## Limiting Privileged Account Access

If a computer / server needs to have unconstrained delegation enabled within an environment, an organization should monitor and limit users with privileged accounts from accessing these devices. Limiting this will help prevent the chance of an attacker abusing this misconfiguration and extracting privileged credentials.

## Protected Users Group

The [Protected Users Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) can be utilized to contain a privileged account's credentials from being used across a network. Along with many other preventive and secure measures, the group also prevents accounts and computers from being able to be delegated.

## Conclusion

I know this is a short blog but these are some of the measures I can think of and have helped implement which has lead to increasing the security in my organization's environment. Hopefully this helps with securing your network and maybe leads to some new ideas.

~ 0xTurco