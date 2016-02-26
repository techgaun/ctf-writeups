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

And, the md5 hash was found to be hash of `pinkfloydrocks`. Cool, this looked like its going good so far.
