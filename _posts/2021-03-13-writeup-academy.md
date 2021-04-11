---
titile: academy Machine 
author: Software User
date: 2021-03-13 16:31:00 +0800
category: hackthebox
tags: [htb-machines,htb,academy,htb,composer,audit log]
--- 

---

![Desktop View]({{ "/assets/img/htb-machines/academy/1.png" | relative_url }})

---

<strong><span style="color:#06bf04">Introduction</span></strong>


Academy is easy level machine released on 07 November 2020 on HacTheBox and created by [egre55](https://www.hackthebox.eu/home/users/profile/1190) and [mrb3n](https://www.hackthebox.eu/home/users/profile/2984)


<span style="color:#06bf04">The blog is for educational purposes only.</span>

--- 

<strong ><span style="color:#06bf04">Enumeration</span></strong>

<strong><span style="color:#06bf04">IP-: 10.10.10.215</span></strong>

As always, I added IP In hosts file.

Lets start with Port Scanning

---

# Nmap

<p><code class="language-plaintext highlighter-rouge">softwareuser@parrot:~ sudo nmap -sC -sS -sV -T4 -A -oN nmap/intial_scan academy.htb </code></p>

![Desktop View]({{ "/assets/img/htb-machines/academy/2.png" | relative_url }})

<strong>-sC for default scripts</strong><br>
<strong>-sV for Version detection</strong><br>
<strong>-sS for SYN scan </strong><br>
<strong>-T4 for speeding up Scan</strong><br>
<strong>-A  for Advanced and Aggressive features</strong><br> 
<strong>-oN for Output</strong><br>

---

<strong>lnmap is just my alias to print only open ports from result file</strong>


```markdown
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

# Web Page

On home page we can see. A Login and Register button

![Desktop View]({{ "/assets/img/htb-machines/academy/3.png" | relative_url }})

Let's register 

![Desktop View]({{ "/assets/img/htb-machines/academy/4.png" | relative_url }})

Let’s Login with the username and password that we used to register

![Desktop View]({{ "/assets/img/htb-machines/academy/5.png" | relative_url }})


And I got successfully logged in 

![Desktop View]({{ "/assets/img/htb-machines/academy/5.png" | relative_url }})

Now we can see some modules. but nothing more I found on this page. so after some time, I decided to intercept the request of register.php request through burp suite also I'll run gobuster.

![Desktop View]({{ "/assets/img/htb-machines/academy/6.png" | relative_url }})
register.php

![Desktop View]({{ "/assets/img/htb-machines/academy/4.png" | relative_url }})

intercepting the request

![Desktop View]({{ "/assets/img/htb-machines/academy/7.png" | relative_url }})

So in the request, I found an interesting parameter roleid=0. Probably roleid is used here is to decide the privileges of a user or role of a user. we can change this roleid=0 to another integer and then we can that we have got some other account or we are still that normal user. also, I started  gobuster

the request

```
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 46
Origin: http://academy.htb
Connection: close
Referer: http://academy.htb/register.php
Cookie: PHPSESSID=q1nn1qd514akhbcvn68rnvghcs
Upgrade-Insecure-Requests: 1

uid=software&password=123&confirm=123&roleid=0
```

o after changing with other numbers like 10,9,8...........1 I thought a higher number will give us admin but when I changed it to 1. 

Request
![Desktop View]({{ "/assets/img/htb-machines/academy/8.png" | relative_url }})
```
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 46
Origin: http://academy.htb
Connection: close
Referer: http://academy.htb/register.php
Cookie: PHPSESSID=q1nn1qd514akhbcvn68rnvghcs
Upgrade-Insecure-Requests: 1

uid=software&password=123&confirm=123&roleid=1
```
and I tried logging in as an administrator account. because in gobuster i got admin.php 

![Desktop View]({{ "/assets/img/htb-machines/academy/9.png" | relative_url }})
i got successfully logged in as admin 

![Desktop View]({{ "/assets/img/htb-machines/academy/10.png" | relative_url }})

# Admin Account

![Desktop View]({{ "/assets/img/htb-machines/academy/11.png" | relative_url }})

we have got a subdomain here ```dev-staging-01.academy.htb```let's add this subdomain in the hosts' file.

# dev-staging-01.academy.htb 

Let's visit `dev-staging-01.academy.htb` and thats an laravel app 


![Desktop View]({{ "/assets/img/htb-machines/academy/12.png" | relative_url }})

we have got an APP_KEY `dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=`

![Desktop View]({{ "/assets/img/htb-machines/academy/13.png" | relative_url }})

i started googling about this app-key and started looking for exploit

![Desktop View]({{ "/assets/img/htb-machines/academy/14.png" | relative_url }})

so there is a msf module to get a shell by using app key. MSF [Module](https://www.rapid7.com/db/modules/exploit/unix/http/laravel_token_unserialize_exec/)

and we got shell as www-data 

![Desktop View]({{ "/assets/img/htb-machines/academy/15.png" | relative_url }})

# www-data shell 

I need to enumerate now and after enumerating some directories I found a password in the hidden file .`env`

![Desktop View]({{ "/assets/img/htb-machines/academy/16.png" | relative_url }})

password `mySup3rP4s5w0rd!!` 

<!-- these four users has shell  -->

<!-- ![Desktop View]({{ "/assets/img/htb-machines/academy/17.png" | relative_url }}) -->

# cry0l1t3  shell 

`cry0l1t3 :` `mySup3rP4s5w0rd!!`

so i tried these all user one by one so  i this password is valid for user cry0l1t3 and i got user 

![Desktop View]({{ "/assets/img/htb-machines/academy/18.png" | relative_url }})

user cry0l1t3 can't run sudo.
so i ll run [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)

![Desktop View]({{ "/assets/img/htb-machines/academy/19.png" | relative_url }})

So, i got a password for user `mrb3n`

![Desktop View]({{ "/assets/img/htb-machines/academy/20.png" | relative_url }})

`mrb3n:``mrb3n_Ac@d3my!`

# mrb3n shell 

![Desktop View]({{ "/assets/img/htb-machines/academy/21.png" | relative_url}})

so mrb3n is allowed to run sudo 

![Desktop View]({{ "/assets/img/htb-machines/academy/22.png" | relative_url }})
composer Privilege escalation

# Root 

check here about [composer](https://gtfobins.github.io/gtfobins/composer/)
![Desktop View]({{ "/assets/img/htb-machines/academy/23.png" | relative_url }})

run this to get root shell 
```bash
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
sudo composer --working-dir=$TF run-script x
```
i got root.txt 

![Desktop View]({{ "/assets/img/htb-machines/academy/24.png" | relative_url }})
Thank you for reading my blog if you have any suggestions feel free to contact me on [twitter](https://twitter.com/softwareuser_).


