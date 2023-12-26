---
layout: post
title:  "HackTheBox Sherlocks - OpTinselTrace-5"
category: DFIR
---

# Scenario

You'll notice a lot of our critical server infrastructure was recently transferred from the domain of our MSSP - Forela.local over to Northpole.local. We actually managed to purchase some second hand servers from the MSSP who have confirmed they are as secure as Christmas is! It seems not as we believe christmas is doomed and the attackers seemed to have the stealth of a clattering sleigh bell, or they didn’t want to hide at all!!!!!! We have found nasty notes from the Grinch on all of our TinkerTech workstations and servers! Christmas seems doomed. Please help us recover from whoever committed this naughty attack!

# Questions

**Q1. Which CVE did the Threat Actor (TA) initially exploit to gain access to DC01?**

CVE-2020-1472

[MITRE ATT&CK Technique - T1210](https://attack.mitre.org/techniques/T1210/)


![q1-1.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q1-1.PNG)

We can see a logon attempt using NTLM auth instead of kerberos from the attacker's IP address

[ZeroLogon Reference](https://www.kroll.com/en/insights/publications/cyber/cve-2020-1472-zerologon-exploit-detection-cheat-sheet)

After successful exploitation, the attacker logged in using the Administrator account.

[MITRE ATT&CK Technique - T1068](https://attack.mitre.org/techniques/T1068/)

![q1-2.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q1-2.PNG)

We can also see in the System logs that the Domain Controller was using NTLM auth and "failed to authenticate" at the same time of this attack

![q1-3.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q1-3.PNG)


**Q2. What time did the TA initially exploit the CVE? (UTC)**

2023-12-13 09:24:23

![q2-1.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q2-1.PNG)

**Q3. What is the name of the executable related to the unusual service installed on the system around the time of the CVE exploitation?**

hAvbdksT.exe

From the system logs, we can see this service was installed after exploitation. The name of the service is "vulnerable_to_zerologon"

![q3-1.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q3-1.PNG)

**Q4. What date & time was the unusual service start?**

Continuing a search through the system logs, we can find the "vulnerable_to_zerologon" service was started at 2023-12-13 09:24:24 (UTC)

![q4-1.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q4-1.PNG)


**Q5. What was the TA's IP address within our internal network?**

Using Eric Zimmermann's EVTXCmd tool, we can parse all the windows event logs and input all the data into a csv.

```powershell
.\EvtxeCmd\EvtxECmd.exe -d "C:\Users\turco\Documents\HTB-Sherlocks\optinsel5\optinseltrace5\DC01.northpole.local-KAPE\DC01.northpole.local-KAPE\uploads\auto\C%3A\Windows\System32\winevt\Logs" --csv "C:\Users\turco\Documents\HTB-Sherlocks\optinsel5\optinseltrace5" --csvf "evtxcmd-out.csv" --sd "11/30/2023"
```

Then using TimelineExplorer, we can view the data.

Applying the filter where the username is not empty and other random windows accounts, we can see RDP connections made from the ip address 192[.]168[.]68[.]200

![q5.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q5.PNG)

**Q6. Please list all user accounts the TA utilised during their access. (Ascending order)**

Administrator, Bytesparkle

The user logged into the Domain Controller using the Administrator account after exploiting the ZeroLogon vulnerability and the Bytesparkle account was previously compromised.

**Q7. What was the name of the scheduled task created by the TA?**

svc_vnc

[MITRE ATT&CK Technique T1053.005](https://attack.mitre.org/techniques/T1053/005/)

Viewing the event logs, we can see two schedule tasks that are created and the unusual one being the "svc_vnc" task

![q7.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q7.PNG)


**Q8. Santa's memory is a little bad recently! He tends to write a lot of stuff down, but all our critical files have been encrypted! Which creature is Santa's new sleigh design planning to use?**

Unicorn

We are initially given the encrypted files and need to find a way to decrypt the files - [MITRE ATT&CK Technique T1486](https://attack.mitre.org/techniques/T1486/)

My first instinct was to run strings against the files and see if there was anything interesting.

Looking at the "splunk_svc[.]dll", we can see the note that is left for Santa along with the list of files most likely encrypted, a string "EncryptingC4Fun!", and the encryption algo (XOR)

![q8-1.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q8-1.PNG)

So we can try to decrypt the files using the key "EncryptingC4Fun!" with xor.

![q8-2.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q8-2.PNG)

Yup! It worked as we can see the PDF file header in the lower section. Now lets download this PDF and take a look.

Here is the first page:

![q8-3.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q8-3.PNG)

Scrolling down to the third page, we can see the creature used for Santa's new sleigh

![q8-4.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q8-4.PNG)

**Q9. Please confirm the process ID of the process that encrypted our files.**

5828

First, we can use our output from EVTXCmd and search for similar file types, xmax. The result pointed to one log, Microsoft-Windows-UAC-FileVirtualization/Operational

![q9-1.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q9-1.PNG)

Viewing this log, we can find there is only one process being ran - 5828

![q9-2.png](/images/HTB/Sherlocks/OpTinsel-Trace-5/q9-2.PNG)
