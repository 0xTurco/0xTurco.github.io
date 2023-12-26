---
layout: post
title:  "HackTheBox Sherlocks - OpTinselTrace-3"
category: DFIR
---

# Scenario

Oh no! Our IT admin is a bit of a cotton-headed ninny-muggins, ByteSparkle left his VPN configuration file in our fancy private S3 location! The nasty attackers may have gained access to our internal network. We think they compromised one of our TinkerTech workstations. Our security team has managed to grab you a memory dump - please analyse it and answer the questions! Santa is waiting…


# Questions

Files generated from volatility for analysis can be found [here](https://github.com/0xTurco/Files-From-Challenges/tree/main/HTB-Sherlocks/OpTinsel-Trace-3) on my github.

**Q1. What is the name of the file that is likely copied from the shared folder (including the file extension)?**

To find files with volatility, we can run

```bash
python3 /home/turco/Tools/volatility3/vol.py -f ./santaclaus.bin windows.filescan.FileScan > files.txt
```

Then we can analyze this output.

Right off the bat, we can see a zip file within the ```C:\\Users\\santaclaus\\Desktop``` folder

present_for_santa[.]zip

Now in order to retrieve the file, we can take the address of the file and feed it into volatility.

```bash
python3 /home/turco/Tools/volatility3/vol.py -f ./santaclaus.bin windows.dumpfiles.DumpFiles --virtaddr 0xa48df8fb42a0
```

![q1.png](/images/HTB/Sherlocks/OpTinsel-Trace-3/q1.PNG)


**Q2. What is the file name used to trigger the attack (including the file extension)?**

click_for_present[.]lnk

We can see the file from the output in Q1

**Q3. What is the name of the file executed by click_for_present.lnk (including the file extension)?**

present[.]vbs

We can see the file from the output in Q1

**Q4. What is the name of the program used by the vbs script to execute the next stage?**

Instead of viewing the vbs, we can view the LNK file and see ```powershell.exe``` is being called


**Q5. What is the name of the function used for the powershell script obfuscation?**

Going into VirusTotal for the VBS, we can view the decode VBS script and see that powershell is called followed by the function "WrapPresent"


![q5.png](/images/HTB/Sherlocks/OpTinsel-Trace-3/q5.PNG)

See Q6 for VT Submission

**Q6. What is the URL that the next stage was downloaded from?**


URL - ```hxxp[://]77[.]74[.]198[.]52/destroy_christmas/evil_present[.]jpg```


We can submit the VBS to virus total and get info about the script

[VT Submission for VBS File](https://www.virustotal.com/gui/file/78ba1ea3ac992391010f23b346eedee69c383bc3fd2d3a125ede6cba3ce77243/behavior)

**Q7. What is the IP and port that the executable downloaded the shellcode from (IP:Port)?**


IP Address and Port - ```77[.]74[.]198[.]52:445```

We can upload the binary into VT and get more details about the malware

[VT Submission for the binary](https://www.virustotal.com/gui/file/31ef280a565a53f1432a1292f3d3850066c0ae8af18a4824e59ac6be3aa6ea9c/behavior)

**Q8. What is the process ID of the remote process that the shellcode was injected into?**

PID - 724

Within the present[.]exe we downloaded from the filedump, we can run strings against the file and discover an ip address - 77[.]74[.]198[.]52

Then running a netscan against the memory dump, we can find this ip address associated with that PID

![q8.png](/images/HTB/Sherlocks/OpTinsel-Trace-3/q8.PNG)


**Q9. After the attacker established a Command & Control connection, what command did they use to clear all event logs?**


Retrieving the regular windows powershell log file from volatility using the virtaddr from the filescan, we can use windows event viewer to review the log file

```bash
python3 /home/turco/Tools/volatility3/vol.py -f ./santaclaus.bin windows.dumpfiles.DumpFiles --virtaddr 0xa48dfefe6e50
```


Then analyzing the log file, we can find the command used to clear the logs

![q9.png](/images/HTB/Sherlocks/OpTinsel-Trace-3/q9.PNG)

```powershell
Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }
```

[MITRE Technique T1070.001](https://attack.mitre.org/techniques/T1070/001/)

**Q10. What is the full path of the folder that was excluded from defender?**

With volatility, we can retrieve the Defender logs and see if there are any exclusions added

```bash
python3 /home/turco/Tools/volatility3/vol.py -f ./santaclaus.bin windows.dumpfiles.DumpFiles --virtaddr 0xa48e00183de0
```

The virtual address is found from the filescan ran previously.

Then in a windows machine, we can open the evtx file and observe the logs.

![q10.png](/images/HTB/Sherlocks/OpTinsel-Trace-3/q10.PNG)

```C:\\Users\\Public```

**Q11. What is the original name of the file that was ingressed to the victim?**

From the same Powershell log, we can see another program be used for dumping the lsass process.

![q11.png](/images/HTB/Sherlocks/OpTinsel-Trace-3/q11.PNG)

This looks like the sysinternals tool ProcDump.

We can verify by finding the file "PresentForNaughtyChild.exe" within our filescan and dumping the file with volatility.

Then, we can open the executable on our windows machine and confirm the details of the binary.

![q11-2.png](/images/HTB/Sherlocks/OpTinsel-Trace-3/q11-2.PNG)

Yup! It is procdump!

Answer: procdump.exe


**Q12. What is the name of the process targeted by procdump.exe?**

From Q11, we can see the lsass.exe process was the target of the attacker

[MITRE Technique T1003.001](https://attack.mitre.org/techniques/T1003/001/)


