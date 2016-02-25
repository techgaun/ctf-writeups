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
