# pgp-com
- Tags: crypto, misc
- Points: 451
- Solves: 24

## Challenge
> You know how PGP works, right? 

We get an archive with one file: `pgp-communication.txt`
In this file we find a short message:
>We use PGP for secure communication to all participating teams and the
>organization. You know how PGP works, right?
> 
>Here are relevant keys and messages, your password is "changemeNOW" without
>quotes.

together with a `PGP PRIVATE KEY BLOCK`, a `PGP PUBLIC KEY BLOCK` and three `PGP MESSAGE` blocks.

## Solution

Split the input file into 5 files: `publickey.txt`, `privatekey.txt`, `message1.txt`, `message2.txt`, `message3.txt`.

First we use GnuPG to import the public and private keys. To not pollute our global key database, we specify a custom `GNUPGHOME`:

```
GNUPGHOME=/tmp/pgp-com gpg --import publickey.txt
GNUPGHOME=/tmp/pgp-com gpg --import privatekey.txt
```

Now we take a look at what we got:

```
GNUPGHOME=/tmp/pgp-com gpg --list-keys
pub   rsa4096 2019-04-02 [SCEA]      3E5FC53F2B3D0B92057DE7701437E68F5024FDC0
uid           [ unknown] Midnight Sun CTF Admin <admin@midnightsunctf.se>
pub   rsa4096 2019-04-02 [SCEA]      6AEEDDD07760D2B83482553BEBA63E4B442DB992
uid           [ unknown] Midnight Sun CTF Participating teams <teams@midnightsunctf.se>
pub   rsa4096 2019-04-02 [SCEA]      6CF8DEB045D8200275DE16A3BB0EAF2215849295
uid           [ unknown] Midnight Sun CTF Devteam maillist <devs@midnightsunctf.se>
```

```
GNUPGHOME=/tmp/pgp-com gpg --list-secret-keys
sec   rsa4096 2019-04-02 [SCEA]
      6AEEDDD07760D2B83482553BEBA63E4B442DB992
uid           [ unknown] Midnight Sun CTF Participating teams <teams@midnightsunctf.se>

```

Public keys for three emails, private key only for one email.
Using the private key, we can decrpyt messages 1 and 3. The private key is encrypted, so gpg prompts for a password on decrypt. Luckily the message in the file gave us the password: `changemeNOW`. For Message 2 we get `decryption failed: No secret key`, since it is only send to devs and admin.

```
GNUPGHOME=/tmp/pgp-com gpg --decrypt message1.txt
Hi,
This is a message just to say hello and welcome you all to the competition.
We are now introducing our own implementation of the super secure PGP messaging format.
We will use it for all important communication during the CTF.
Best regards,
CTF Admin

GNUPGHOME=/tmp/pgp-com gpg --decrypt message3.txt
We have received some indications that our PGP implementation has problems with randomness.
The dev team is currently working on fixing the issue.
We will not use this system for further messages until it has been fixed.
Your key pairs were not generatad by this system, and they should be safe even for future use.
```

After first looking around the packets a bit, to see if there is anything hidden in them (eg. with `gpg --list-packets --verbose message1.txt`) and not finding anything, we notice the hint in the messages:

They say the key pairs are safe, so no problem there. But there is an issue with randomness in their PGP implementation. Looking up how pgp works, you see that messages are encrypted with a symmetric cipher. The key is randomly generated for each message, and encrypted with the public keys of the recipients. The referenced 'problem with randomness' is therefore probably a weakness in these symmetric keys.

They can easily be dumped with
```
GNUPGHOME=/tmp/pgp-com gpg --show-session-key < message1.txt
...
session key: '9:0000000000000000000000000000000000000000000000000000000000001336'
...

GNUPGHOME=/tmp/pgp-com gpg --show-session-key < message3.txt
...
session key: '9:0000000000000000000000000000000000000000000000000000000000001338'
...
```

We guess that message2 has a key of `1337` and get the flag:
```
GNUPGHOME=/tmp/pgp-com gpg --override-session-key 9:0000000000000000000000000000000000000000000000000000000000001337 < message2.txt
...
From: Midnight Sun CTF Admin <admin@midnightsunctf.se>
To: Midnight Sun CTF Devteam maillist <devs@midnightsunctf.se>
Subject: 
Date: 2019-04-02 17:27:07

Hi,

How could you implement a system with such bad session key generation!?

Please remeber that midnight{sequential_session_is_bad_session} in the future...

Best regards,
CTF Admin

```