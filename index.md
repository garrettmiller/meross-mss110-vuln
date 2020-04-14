## Meross MSS110 Vulnerability

The [Meross MSS110](https://www.amazon.com/meross-MSS110-Control-Occupies-ETL-Complied/dp/B074K3NFZQ) is a popular "smart plug" device currently available from Amazon, and the subject of a recent promotion (only $10!)

![alt text](plug.jpg "Meross MSS110")

Having an [inherent](https://nvd.nist.gov/vuln/detail/CVE-2016-5081) [distrust](https://nvd.nist.gov/vuln/detail/CVE-2016-5650) of [Internet-of-Things](https://en.wikipedia.org/wiki/Mirai_(malware)) devices, before I get to really trusting this thing I wanted to poke at it a bit.  I began by setting it up on a throwaway segment of my WLAN, and plugging my Christmas tree into it.  I then ran nmap against it:

```
Starting Nmap 7.60 ( https://nmap.org ) at 2018-01-13 23:56 EST
NSE: Loaded 146 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 23:56
Completed NSE at 23:56, 0.00s elapsed
Initiating Ping Scan at 23:56
Scanning 192.168.1.51 [4 ports]
Completed Ping Scan at 23:56, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:56
Completed Parallel DNS resolution of 1 host. at 23:56, 0.00s elapsed
Initiating SYN Stealth Scan at 23:56
Scanning Meross_Smart_Plug (192.168.1.51) [1000 ports]
Discovered open port 23/tcp on 192.168.1.51
Discovered open port 80/tcp on 192.168.1.51
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
[repeated output truncated]
adjust_timeouts2: packet supposedly had rtt of 13024986 microseconds.  Ignoring time.
Completed SYN Stealth Scan at 23:57, 28.29s elapsed (1000 total ports)
Initiating Service scan at 23:57
Scanning 2 services on Meross_Smart_Plug (192.168.1.51)
Completed Service scan at 23:57, 16.01s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against Meross_Smart_Plug (192.168.1.51)
WARNING: RST from 192.168.1.51 port 23 -- is this port really open?
Retrying OS detection (try #2) against Meross_Smart_Plug (192.168.1.51)
Initiating Traceroute at 00:00
Completed Traceroute at 00:00, 0.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 00:00
Completed Parallel DNS resolution of 2 hosts. at 00:00, 0.01s elapsed
NSE: Script scanning 192.168.1.51.
Initiating NSE at 00:00
Completed NSE at 00:00, 39.77s elapsed
Nmap scan report for Meross_Smart_Plug (192.168.1.51)
Host is up (0.15s latency).
Not shown: 997 closed ports
PORT    STATE    SERVICE VERSION
23/tcp  open     telnet?
| fingerprint-strings: 
|   GenericLines, NULL: 
|_    Login as:
80/tcp  open     http?
|_http-title: Site doesn't have a title (text/html; charset=).
514/tcp filtered shell
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port23-TCP:V=7.60%I=7%D=1/13%Time=5A5AE33A%P=x86_64-pc-linux-gnu%r(NULL
SF:,9,"Login\x20as:")%r(GenericLines,9,"Login\x20as:");
Aggressive OS guesses: Actiontec MI424WR-GEN3I WAP (99%), DD-WRT v24-sp2 (Linux 2.4.37) (98%), Linux 3.2 (98%), Microsoft Windows XP SP3 or Windows 7 or Windows Server 2012 (96%), Linux 4.4 (96%), Microsoft Windows XP SP3 (96%), BlueArc Titan 2100 NAS device (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   0.03 ms 192.168.11.2
2   0.02 ms Meross_Smart_Plug (192.168.1.51)

NSE: Script Post-scanning.
Initiating NSE at 00:01
Completed NSE at 00:01, 0.00s elapsed
Initiating NSE at 00:01
Completed NSE at 00:01, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 245.67 seconds
           Raw packets sent: 1330 (63.010KB) | Rcvd: 1288 (52.143KB)
```

Interestingly, as soon as I did this, my Christmas tree began turning itself on and off intermittently.  I'm not sure how that's related, but it's worth noting. *(I later learned that this is because nmap is crashing the device)* 

Seeing that port 80 was open, I also ran a Nikto scan against the webserver:

```
root@kali:~# nikto -host 192.168.1.51
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.51
+ Target Hostname:    192.168.1.51
+ Target Port:        80
+ Start Time:         2018-01-14 00:15:18 (GMT-5)
---------------------------------------------------------------------------
+ Server: HTTPD
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /postnuke/modules.php?op=modload&name=Web_Links&file=index&req=viewlinkdetails&lid=666&ttitle=Mocosoft Utilities\"%3<script>alert('Vulnerable')</script>: Postnuke Phoenix 0.7.2.3 is vulnerable to Cross Site Scripting (XSS). http://www.cert.org/advisories/CA-2000-02.html.
+ OSVDB-3093: /do_map: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /do_subscribe: This might be interesting... has been seen in web logs from an unknown scanner.
+ 7549 requests: 14 error(s) and 6 item(s) reported on remote host
+ End Time:           2018-01-14 00:23:50 (GMT-5) (512 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

This also caused the lights to freak out.  (As mentioned above, I eventually learned that this is also because Nikto is crashing the device, dumping its crash state to screen before the telnet connection closes):

```
Except 2: TLBL
    z0=00000000 at=fffffffe v0=0000002e v1=00000000
    a0=00000000 a1=8019d5d0 a2=80438215 a3=00000020
    t0=8019d55f t1=80438213 t2=8019d550 t3=00000025
    t4=80256c08 t5=0000005a t6=a069b144 t7=a069b144
    s0=00000000 s1=0000002f s2=0000002f s3=8019d5b8
    s4=80438210 s5=8019d4e0 s6=8019d4f4 s7=80220d88
    t8=ffffffea t9=00000004 k0=80220e0a k1=0000077e
    gp=8021e250 sp=802209d0 fp=8019d504 ra=80014b94
    pc=80191f9c sr=1000e403 cause=00000008, badva=00000000

00000000: 9C 1F 19 80 D0 09 22 80  80 08 22 80 94 4B 01 80  |......"..."..K..|
00000010: B8 2F 1E 80 E0 D4 19 80  F4 D4 19 80 88 0D 22 80  |./............".|
00000020: 04 D5 19 80 3C 59 19 80  94 4B 01 80 00 00 25 80  |....<Y...K....%.|
00000030: E9 45 36 00 00 00 00 00  08 00 34 3E 80 D4 5D 80  |.E6.......4>..].|
00000040: 14 00 00 00 BC 5F F4 4A  04 00 00 00 00 00 00 00  |....._.J........|
00000050: 01 00 00 00 78 DA 3D 80  BC D4 5D 80 00 00 00 00  |....x.=...].....|
[output truncated]
000001D0: E4 09 22 80Connection closed by foreign host.
```

I took a packet capture of a communications session between the mobile app and the device.  Things look fairly normal here, communicating with an Amazon AWS host over what looks like TLS based on the presence of `0x17 0x03 0x03` at the [beginning](https://tools.ietf.org/html/draft-agl-tls-snapstart-00) of every TCP data segment:

I decided to do a bit of open-source research to see if I could find a copy of the binary firmware for the device.  I wasn’t lucky enough to find this online, but I did find an .apk of the app for the device on the manufacturer's website.  Out of curiosity, I loaded this into an online decompiler and started to poke around.  Wait, what’s in this “assets” folder?

![alt text](firmware.png "Decompiler")

What luck - the APK actually contains a copy of what looks like the firmware binary, presumably to facilitate firmware upgrades!

Let’s run a `file` and `binwalk` on this to see what we’re dealing with:

```
root@kali:~/Desktop# file mss110-us-v1-rc0118.bin 
mss110-us-v1-rc0118.bin: u-boot legacy uImage, zxrouter, Linux/MIPS, Standalone Program (Not compressed), 733628 bytes, Sat Jan  6 08:46:07 2018, Load Address: 0x80500000, Entry Point: 0x80500000, Header CRC: 0xC2D49870, Data CRC: 0x51CE1F0F

root@kali:~/Desktop# binwalk mss110-us-v1-rc0118.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0xC2D49870, created: 2018-01-06 08:46:07, image size: 733628 bytes, Data Address: 0x80500000, Entry Point: 0x80500000, data CRC: 0x51CE1F0F, OS: Linux, CPU: MIPS, image type: Standalone Program, compression type: none, image name: "zxrouter"
9344          0x2480          LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 2154072 bytes

```

It looks like a U-boot image, along with some lzma-compressed data at a specific offset.  Let’s carve that out using `dd` and see what we can find, and then decompress it using xzcat:

```
root@kali:~# dd if=mss110-us-v1-rc0118.bin bs=1 skip=9344 of=lzma.tar.lzma
```

We can then poke through strings to see what we might find:

```
root@kali:~# xzcat lzma.tar.lzma | strings | less
```

No obvious passwords in here, but there's definitely some RSA keys, clues to how the device works, and other interesting nuggets:

```
%s UserId:%d Key:%s
%s Username:%s Password:%s
IOT server Connecting...
Error(%d) connecting failed
connecting failed increase count
smart.meross.com
iot.meross.com
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA3PDOOsoOVMONFsD/yV08pDmdXFLpropH73In6HA7lIzJn0Qh
DJxIwhbAHBqSu12XHzZeQCWm20ggyX2OacWapqxTYzpHzsEq2iwjusuwXpt2tvgR
EoyEdsFSw7WaNwlOqV6AqFtyws9inK+lyRNvu/AfmRpebGenqR/OcJ6n5FBIjdBH
[truncated]
#PROFILE
#VER_2_1
SYS_USERS=admin
SYS_USERS1=user
SYS_ADMPASS=
SYS_ADMPASS1=
```

Wait, what's that last part?  `SYS_USERS=admin`.  Let’s go back and try and connect via telnet.  The telnet listener doesn’t respond to the typical line endings, so we need to adjust our client to send proper ones (via [Microsoft](https://support.microsoft.com/en-us/help/322846/telnet-client-does-not-send-crlf-when-expected))

1.	Start the Telnet Client.
2.	Open a Telnet session to a Telnet server.
3.	Press CTRL+] to switch to command mode.
4.	Type set crlf.
5.	Press ENTER to return to session mode.

Taking a random stab at a password, I tried "admin", *blank*.  Boom, it dumps me to a shell.  Maybe I should have tried that to begin with:

```
root@kali:~# telnet 192.168.1.51
Trying 192.168.1.51...
Connected to 192.168.1.51.
Escape character is '^]'.
Login as:^]
telnet> set crlf
Will send carriage returns as telnet <CR><LF>.
^MInvalid User Name
Login as:admin^MPassword:^M
CFG>ls^Mget         set         del         prof 
```

Upon an initial look, it doesn't appear to be a full Bash shell, but it definitely exposes some inner workings of the system as well as some type of debug filesystem.

There's risks here though - a tool located at `Meross/wifi` will dump the ESSID, WPA2 passphrase, and BSSID of the network it's currently associated with.  This isn't a huge issue since we're presumably connected to the LAN as well, but in case this device is internet-exposed or didn't follow its configured 802.11 security settings, this could be a fairly severe risk.

![alt text](settings.png "Meross/wifi")

There's also what appears to be part of a web-based admin interface exposed (`admin.htm`), though this doesn't appear to be documented anywhere.  Changing a password here does appear to change the Telnet password, though it would be nice if Meross advertised this functionality if it worked fully, allowing users to change the password to their device (or enable/disable Telnet).

### UPDATE as of 4/28/2018, firmware version 1.1.24

The telnet behavior described above was current as of firmware version 1.1.18, but appears to have been disabled in 1.1.24.  However, the `admin.htm` administrative interface is still exposed and unauthenticated as of 1.1.24.

### Future work:
* Explore exposed shell, filesystem
* Carve, reverse engineer binaries
* Explore HTTP server further

### Tests Passed:
* Test behavior when presented with Wi-Fi network that doesn't match stored security settings

Unlike another [device I've looked at](https://nvd.nist.gov/vuln/detail/CVE-2016-5650), the MSS110 appears to only connect to networks matching the WPA2 security settings of networks it knows.  Other devices show this "fail open" behavior, which is incredibly dangerous when combined with a hardcoded root password.

Interestingly enough, my [ecobee 4](https://www.ecobee.com/) doesn't do well at this - it will connect to a network with matching ESSID, but mismatched security settings.  This resulted in the issuance of CVE-2018-6402:

```“Ecobee Ecobee4 4.2.0.171 devices can be forced to deauthenticate and connect to an unencrypted Wi-Fi network with the same SSID, even if the device settings specify use of encryption such as WPA2, as long as the competing network has a stronger signal. An attacker must be able to set up a nearby SSID, similar to an "Evil Twin" attack.”```
