---
layout: post
title:  "TryHackMe - Investigating with Splunk"
category: DFIR
---


**Q1. How many events were collected and ingested in the index **main**?**

```text
index=main
```

returns

12,256 Logs

![[q1.PNG]](/images/THM/investigating-with-splunk/q1.PNG)


**Q2. On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?**

We can use [Windows Event ID 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720) to find the newly created account.

```text
index=main host=server EventID=4720
```

![[q2.PNG]](/images/THM/investigating-with-splunk/q2.PNG)


**Q3. On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?**

```text
index=main host=server EventID=13 A1berto
```

[Windows Event ID 13](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)is an event generated from Sysmon when the registry is modified


![[q3.PNG]](/images/THM/investigating-with-splunk/q3.PNG)


**Q4. Examine the logs and identify the user that the adversary was trying to impersonate.**

Looking at the user list in the logs, we see there is an account called "Alberto"


**Q5. What is the command used to add a backdoor user from a remote computer?**

```powershell
"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
```

Searching through logs with "A1berto", we come across this command for adding the account into the network


**Q6. How many times was the login attempt from the backdoor user observed during the investigation?**

Looking through the logs, we cannot see any logon attempts from the new accounts.

**Q7. What is the name of the infected host on which suspicious Powershell commands were executed?**

```
index=main A1berto powershell.exe
```

We can find a powershell command executing a base64 encoded string on the account James.Browne

![[q7.PNG]](/images/THM/investigating-with-splunk/q7.PNG)



**Q8. PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?**

A previous article I have read by Mandiant reminded me of event IDs related to PowerShell

[Mandiant Article](https://www.mandiant.com/resources/blog/greater-visibility)

Now we search again with just powershell in the search bar

```text
index=main powershell
```

Then we can see the event ID "4103" in the event ID list which is also referenced in the Mandiant article

![[q8.PNG]](/images/THM/investigating-with-splunk/q8.PNG)


**Q9. An encoded Powershell script from the infected host initiated a web request. What is the full URL?**

We can grab the encoded powershell and throw it into CyberChef for decoding

![[q9-1.PNG]](/images/THM/investigating-with-splunk/q9-1.PNG)

Then we can decode the base64 string which seems to be the URL from the larger base64 encoded string which returns and IP of ```hxxp[://]10[.]10[.]10[.]5``` and that means our URL is ```hxxp[://]10[.]10[.]10[.]5/news[.]php```

