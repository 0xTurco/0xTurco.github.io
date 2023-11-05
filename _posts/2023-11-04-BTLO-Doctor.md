---
layout: post
title:  "Blue Team Labs Online - Doctor"
category: DFIR
---

# Scenario

One of our web application servers has been compromised and the incident response team has isolated the machine. You’ve been provided with remote access; investigate the system and figure out the attacker’s actions.



**Q1. What is the name of the malicious process? Provide the full path of the binary**

For listing processes, we can run the linux command:

```bash
ps -aux
```
and get a list back of all running processes.

Searching through this list, we find an unfamiliar program being ran by "/bin/sh" called appleaday. And if we run:

```bash
locate appleaday
```

We get the path of "**/usr/bin/appleaday**"

![q1.png](/images/BTLO-Labs/IR/Doctor/q1.PNG)

**Q2. What is the port that the malicious process listens on?**

Grabbing the listening ports using "**netstat**", we can see a few interesting ports. I went through this list and 445 was the correct port being used. 

![q2.png](/images/BTLO-Labs/IR/Doctor/q2.PNG)

**Q3. Provide the full URL from which the malware was downloaded to the system**

```text
hxxp[://]18[.]132[.]210[.]238:6565/appleaday
```

Going to the "/var/log" directory, I ran:

```bash
grep "appleaday" -iR .
```

to find any instance of that string and we find the URL in **./audit/audit.log.3**

![q3.png](/images/BTLO-Labs/IR/Doctor/q3.PNG)



**Q4. There was another file downloaded from the same server. Provide the full URL**

Doing something similar to Q3, we change the string to the URL of the attacker's server and find the other program downloaded:

```bash
hxxp[://]18[.]132[.]210[.]238:4646:LinEnum[.]sh
```

![q4.png](/images/BTLO-Labs/IR/Doctor/q4.PNG)


**Q5. What is the port running on the system that was used as the entry point, and what was the type of vulnerability exploited?**

Since we know we are working on a web server and the server could be apache, some ports could be **80,443,8080, or 8443** - 80 is the answer after trying these.

Looking through the logs, the attacker was running sqlmap against the server and trying to exploit an SQLi vulnerability.

![q5.png](/images/BTLO-Labs/IR/Doctor/q5.PNG)


**Q6. What is the name of the file that had the vulnerability? Provide the full system path**

The attacker was using the file "**/prod/old/searcher.php**" but we need the full path on the system.

![q6.png](/images/BTLO-Labs/IR/Doctor/q6.PNG)

```bash
/var/www/html/prod/old/searcher.php
```

**Q7. What is the name of the file created and what is the first command executed by the attacker?**

Once the attacker had control with the SQLi vulnerability, another file was created call "**cc.php**" for the attacker to establish a remote connection

Then the initial command ran was "**whoami**"

![q7.png](/images/BTLO-Labs/IR/Doctor/q7.PNG)

**Q8. The attacker obtained a reverse shell, what was the language used to create the reverse shell and what is the lowest port used?**

We can see reading the logs that python was used for the reverse shell and the only two ports used for the connections were **4444** and **4433**.

![q8.png](/images/BTLO-Labs/IR/Doctor/q8.PNG)