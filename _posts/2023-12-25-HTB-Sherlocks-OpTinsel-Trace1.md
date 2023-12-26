---
layout: post
title:  "HackTheBox Sherlocks - OpTinselTrace-1"
category: DFIR
---


# Scenario

An elf named "Elfin" has been acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. Santa's network of intelligence elves has told Santa that the Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! Santa is very busy with his naughty and nice list, so he’s put you in charge of figuring this one out. Please audit Elfin’s workstation and email communications.


# Questions

**Q1. What is the name of the email client that Elfin is using?**

In order to find what mailclient was used, we can analyze the provided prefetch files using PECmd by Eric Zimmerman. 

```powershell
.\PECmd.exe -f C:\Users\turco\Documents\HTB-Sherlocks\optinseltrace1\elfidence_collection\TriageData\C\Windows\prefetch\MAILCLIENT.EXE-3B077E7D.pf > C:\Users\turco\Documents\HTB-Sherlocks\optinseltrace1\mailclient-3B077E7D-PF.txt
```

Analyzing the output, we can find an executable called mailclient.exe located within the ```Program Files (x86)\\EM Client``` folder.


**Q2. What is the email the threat is using?**

```
definitelynotthegrinch[@]gmail[.]com
```

After searching through the user's local folders, we can find where the eM Client stores its files from a user's mailbox - ```C:\\Users\\turco\\Documents\\HTB-Sherlocks\\optinseltrace1\\elfidence_collection\\TriageData\\C\\users\\Elfin\\Appdata\\Roaming\\eM Client\\Local Folders```

The file(s) that seemed interesting were the mail_data files and the largest being mail_data.dat-wal.

Opening this, we can see email subject, to, from, etc data.

![q2.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q2.PNG)


 
**Q3. When does the threat actor reach out to Elfin?**

27/11/2023 17:27:26

Searching through the same file from Q2, we can find the first time the attacker reached out to Elfin.

```html
<div>------ Original Message ------</div>
<div>From "Grinch Grincher" &lt;<a href="mailto:definitelynotthegrinch@gmail.com">definitelynotthegrinch@gmail.com</a>&gt;</div>
<div>To <a href="mailto:elfinbestelfxmas4eva@gmail.com">elfinbestelfxmas4eva@gmail.com</a></div>
<div>Date 27/11/2023 17:27:26</div>
<div>Subject Hi there x</div></div><div><br /></div>
<div id="x2bae29fd0178450"><blockquote cite="CAKoKexGojcDK_vpQyeGAyFt3HLXxMmXfoYPyZZ=urf3c5ZyaPw@mail.gmail.com" type="cite" class="cite2">
<div dir="ltr">hiiiiii<div><br /></div><div>I know this is quite forward, but I noticed you going into the North pole HQ the other day and I thought you looked very cool,</div><div><br /></div><div>tell me a bit about yourself??Â </div><div><br /></div><div dir="ltr" class="gmail_signature" data-smartmail="gmail_signature"><div dir="ltr">Yours truly,<br /><br /><div>Wendy Elflower</div></div></div></div>
</blockquote></div>
</body></html>
```


**Q4. What is the name of Elfins boss?**

elfuttin bigelf

Going farther down in the mail file, we can see emails sent between Elfin and their boss.

![q4.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q4.PNG)



**Q5. What is the title of the email in which Elfin first mentions his access to Santas special files?**


Re: work

We can see Elfin mentions having access to Santa's binaries within this email thread


**Q6. The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?**

wendy elflower, 2023-11-28 10:00:21

![q6.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q6.PNG)

Scrolling down more, we can see the email sent by Elfin mentioning that Wendy's name was grinch briefly

**Q7. What is the name of the bar that Elfin offers to meet the threat actor at?**

![q7.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q7.PNG)

SnowGlobe Bar


**Q8. When does Elfin offer to send the secret files to the actor?**

28 Nov 2023 16:53:48


**Q9. What is the search string for the first suspicious google search from Elfin? (Format: string)**

"how to get around work security"



**Q10. What is the name of the author who wrote the article from the CIA field manual?**

Joost Minnaar

![q10.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q10.PNG)


**Q11. What is the name of Santas secret file that Elfin sent to the actor?**

santa_deliveries.zip

We can locate the file within Elfin's system - ```\\C\\users\\Elfin\\Appdata\\Roaming\\top-secret```

**Q12. According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?**

2023-11-28 17:01:29

First, we can analyze the $MFT record using MFTECmd from Eric Zimmermann.

```
.\MFTECmd.exe -f "C:\Users\turco\Documents\HTB-Sherlocks\optinseltrace1\elfidence_collection\TriageData\C\$MFT" --csvf "C:\Users\turco\Documents\HTB-Sherlocks\optinseltrace1\optinsel1.csv" --csv "C:\Users\turco\Documents\HTB-Sherlocks\optinseltrace1"
```

Then with this csv that is generated, we can use EZViewer and Notepad++ to find the correct time.

In EZViewer, we can locate the santa_deliveries.zip file and get the created time.

![q12.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q12.PNG)

Then using npp, we can get the exact second mark

**Q13. What is the full directory name that Elfin stored the file in?**


Answer: ```C:\\users\\Elfin\\Appdata\\Roaming\\top-secret```


**Q14. Which country is Elfin trying to flee to after he exfiltrates the file?**

Greece

From the browser history, Elfin is looking for flights to Greece

![q14.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q14.PNG)


**Q15. What is the email address of the apology letter the user (elfin) wrote out but didn’t send?**

In order to read the user's email data, we can import their eM Client data into ours and reload the eM Client application to view the Drafts folder.

![q15.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q15.PNG)

Email: ```santa.claus[@]gmail[.]com```

**Q16. The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?**

If we go back to our provided files, we were given some key registry hives, SYSTEM SAM and SECURITY. We can use secretsdump from impacket to dump the credentials from these hives. 

![q16-1.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q16-1.PNG)

Hash for Elfin:

```text
Elfin:1001:aad3b435b51404eeaad3b435b51404ee:529848fe56902d9595be4a608f9fbe89::
```

Now we can take the NT portion of this output and crack it or use an online tool like crackstation.

![q16-2.png](/images/HTB/Sherlocks/OpTinsel-Trace-1/q16-2.PNG)

```text
Elfin : Santaknowskungfu
```