# The WebSec CTF

[WebSec CTF](http://websec.tech/challenges) is a CTF organized by group from Nepal. Though I am severely lacking time, I'm going to document whenever I can work on it.

## Web

### Super Secure Login
- Just guess the common user/password for admin users. I got it in two tries(which is bad).

### Empty Page
- You can view the source code or just do `F12` to open your browser's console where you'll see your flag.

### Someone know what i have
- After viewing the source code, I found a text `Ne0`. All I had to do was set my user agent to that string and I got the flag.

## Cryptography

### I am a prisoner
- `base64 -d <<< "d2VsY29tZV90b19wd25nYW1l"`

### Rome that is all I have to say
- March 15 gives away the shift we need which is 15.

### DJ Khaled
- Use the key `DJKHALED` and run vigenere cipher decoding to get your flag.

### I love riding rails.
- This one was a [rail fence cipher](https://en.wikipedia.org/wiki/Rail_fence_cipher) with the rails of 5 and offset 2. The deciphered text was `Dear love, I will miss you but you can never be together. You will find someone better than me.`

## Forensics

### Hidden Message
- The png image had to be just processed by [online steganography tool](http://manytools.org/hacker-tools/steganography-encode-text-into-image/go)

### Cr4ck3rs exfiltrated their team before we got there.
- Run an exif analysis.
```
exif laptop.jpg
```

### What's my name?
- Yet another robots.txt stuff. The file you get `security.zip` is just an ascii text file

### Packet sniffer are great,lets warm up
- Load it on wireshark and check the `tcp.stream eq 24`. Its a form submission and you can see the flag.

### How much do you know about the image ?
- Open up the image in text editor. You will see something fishy because there's a base64 encoded stuff in the image on 7th line.

### CSI raided our server
- Another classic wav + text combined to hide text in wave file. You can use [one of the stegano decoders](https://futureboy.us/stegano/decinput.html) to decode it.

## Miscellaneous

### Gem #1
- Another robots.txt stuff but on the websec.tech site itself.

### Gem #2
- WebSec is powered by Mellivora and the javascript file seems to be modified. There's comment that will work as an answer.

Later on, I joined the team to write the challenges for the CTF. I did solve some of the other challenges which I unfortunately didn't document. The CTF is already finished now but it was fun to play and later on write some of the challenges.
