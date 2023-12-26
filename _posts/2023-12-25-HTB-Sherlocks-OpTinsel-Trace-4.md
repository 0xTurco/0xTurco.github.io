---
layout: post
title:  "HackTheBox Sherlocks - OpTinselTrace-4"
category: DFIR
---


# Scenario

Printers are important in Santa’s workshops, but we haven’t really tried to secure them! The Grinch and his team of elite hackers may try and use this against us! Please investigate using the packet capture provided! The printer server IP Address is 192.168.68.128


# Questions

**Q1. The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?**

IP Address - ```172[.]17[.]79[.]133```

[MITRE ATT&CK Technique T1018](https://attack.mitre.org/techniques/T1018/)

We can see traffic from this IP hitting the Print Server on several different ports

![q1.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q1.PNG)



**Q2. Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?**

Port 9100

From the attacker's IP, we can see traffic hitting this IP from the attacker

[MITRE ATT&CK Technique T1071](https://attack.mitre.org/techniques/T1071/)

![q2.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q2.PNG)



**Q3. What is the full name of printer running on the server?**

Printer Name - NorthPole HP LaserJet 4200n

[MITRE ATT&CK Tecnique T1082](https://attack.mitre.org/techniques/T1082/)

Once a connection is established, we can see the server name

![q3.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q3.PNG)

**Q4. Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?**

Name - Douglas Price

[MITRE ATT&CK Technique T1083](https://attack.mitre.org/techniques/T1083/)

![q4.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q4.PNG)

**Q5. The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?**

```
The addressed employee is confirmed to be working with grinch and team. According to Clause 69 , This calls for an immediate expulsion
```
[MITRE ATT&CK Technique T1005](https://attack.mitre.org/techniques/T1005/)

![q5-2.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q5-2.PNG)


![q5-1.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q5-1.png)

**Q6. What was the name of the scheduled print job?**

Print Job Name - MerryChristmas+BonusAnnouncment

![q6.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q6.PNG)

**Q7. Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?**

File Path  - ```/Administration/securitykeys/ssh_systems/id_rsa```

![q7-1.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q7-1.PNG)

![q7-2.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q7-2.PNG)



**Q8. What is size of this file in bytes?**

File Size - 1914

See Q7 for size

**Q9 .What was the hostname of the other compromised critical server?**

Server Name - christmas.gifts

In the backup ssh key message, we can see the server name

```
#This is a backup key for christmas.gifts server. Bytesparkle recommended me this since in christmas days everything gets mixed up in all the chaos and we can lose our access keys to the server just like we did back in 2022 christmas.
```

[MITRE ATT&CK Technique T1098.004](https://attack.mitre.org/techniques/T1098/004/)

**Q10. When did the Grinch attempt to delete a file from the printer? (UTC)**

2023-12-08 12:18:14

![q10.png](/images/HTB/Sherlocks/OpTinsel-Trace-4/q10.PNG)
