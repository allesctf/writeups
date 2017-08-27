# Rev250 - Secure Messenger 

**Description:** Messengers are more secure nowadays. But what if they logging too much?

Ok it gets more interesting, only 7 teams solved this one. We had given an APK and two log files of the application, one logfile of Alice and one logfile of Bob. They basically looked like this:

```
  alice/session/est/base/0624fb0d82deaa7ca92f9e2b72d48b4c07011c46dad736f6d3c7f220cda1d32b
alice/session/est
alice/session/ephemeral/shared/001f29a3fd9bbf63e788fb6f39570b32ca6fa518b681b1ccaa8df0f0835b8f1d
alice/session/est/base/0624fb0d82deaa7ca92f9e2b72d48b4c07011c46dad736f6d3c7f220cda1d32b
alice/session/ephemeral/shared/d5bb4b7f1ad9f4a20f2c9f8fb0f63a00cabffa81165b10fe4e171d8e405eb37d
alice/session/est/base/0624fb0d82deaa7ca92f9e2b72d48b4c07011c46dad736f6d3c7f220cda1d32b
alice/session/ephemeral/shared/f5f7943a624467724c155ed41573d5ba1f0032fcfe2676b6ed66b8f772646f07
alice/session/ephemeral/prekey/requested/public/[2094329238 : 77a759a63c9abc1f51be05cc971f7e5fa09949cda7062451ee55bdd05540a44c]
alice/session/ephemeral/prekey/requested/private/6074af859b089f844e01c7c1c35a1ad174ea39dd39c0ce73981a57e3d20a6a70
alice/msg/rcv/bob/enc/6312d8951609e19c54ca2f3db86b6961 -> [1]
alice/session/est/base/0624fb0d82deaa7ca92f9e2b72d48b4c07011c46dad736f6d3c7f220cda1d32b
alice/session/ephemeral/prekey/requested/public/[1869677971 : e6eed22b5f5fa59de8d8e0b736bfd572f2d49952ccff07b2aaeefb7271141d77]
alice/session/ephemeral/prekey/requested/private/68783b882f3463a512b11a6bab3bfb87aeeef749357d4bfa8b6a656857d0b873
alice/msg/rcv/bob/enc/eee70b4f327fe0a2faa9944c360210ab -> [2] 
[...]
```

We can see that some information is leaked, like a private and public key and some "shared" key.

Anyways, start Android decompiling as always: Get the jar via dex2jar and extract the apk with apktool as well. Dex2Jar isn't reliable at all and we have to use the smali code later to figure out invalid Java code. I also ran the apk trough [DeGuard](http://apk-deguard.com/) to resolve some of the obfuscated class names (the tool's not very good at it, but sometimes you get an idea what the class might be).

Anyway, hands on the decompiled sources! They are acctually pretty confusing, so I did some renaming at first. The 3 main classes are:
 * Participant => Acts as one person in the encrypted conversation and holds its own public/private keypair. Also stores the encrypted session to other participants
 * EncryptedSession => Encrypts and decrypts messages with a participant using a agreement on Curve25519 and AES with SHA256HMAC
 * ECKey => An encrypted message with some public key, private key and seed value

Lets trace the log file calls and assume the client's view is "Alice" (it acctually is! :D). "session/est/base/" is logged when a new EncryptedSession to a participant you havn't talked to yet is established. The value logged is the Curve25519 Agreement based on the public key of "Bob" and our own private key of "Alice". This agreement is used for all encryption later on, so it remains the same (and shows up quite often in the log).

"ephemeral/shared/" is used when a message encryption from Alice to Bob happens. Its again an agreement via Curve25519 and public/private key. But this time a new keypair for this message is generated, lets call it KP_MSG. In the encrypt function another keypair is generated, lets call this KP_ENC. The agreement is performed on the public key KP_MSG and private key KP_ENC, this agreement is logged again. KP_MSG is logged as well (requested/public/ and requested/private).

The last logtype is "msg/rcv/" which logs the message ID. 

Man so, many key pairs and agreements. And some of the keys are leaked, but the leakage of all the public/private keys is actually a false flag.

Lets take a close look to the encryption function:
```
public ECKey encryptData(StringStorage paramStringStorage, PublicKeyStorage paramPublicKeyStorage)
  {
    Curve25519 curve25519Obj = Curve25519.get("best");
    Curve25519KeyPair localCurve25519KeyPair = curve25519Obj.generateKeyPair();
    byte[] agreement = ((Curve25519)curve25519Obj).calculateAgreement(paramPublicKeyStorage.getMSGPubKey(), localCurve25519KeyPair.getPrivateKey());
    Logger.add(participant1.username + "/session/ephemeral/shared/", arrayOfByte);
    shiftCounter += 1L;
    byte[] keyBytes = sha256Hmac(getIVShifted(shiftCounter), "WhisperSystems".getBytes(), 16);
    byte[] ivBytes = sha256Hmac(agreement, "WhisperSystems".getBytes(), 16);
    Cipher localCipher = getCipherInstance();
    localCipher.init(1, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(ivBytes));
    return new ECKey(localCipher.doFinal(paramStringStorage.getStoredValue().getBytes()), shiftCounter, paramPublicKeyStorage.getSeed(), localCurve25519KeyPair.getPublicKey());
  }
```
So, we aim for a AES decrypt. What we need is:
 * IV
 * Key
 * Encrypted data (obviously, but its in the log of Bob)
 * MODE and Padding Method (given by AES/CBC/PKCS5Padding)

The Key is build via:
```
shiftCounter += 1L;
byte[] keyBytes = sha256Hmac(getIVShifted(shiftCounter), "WhisperSystems".getBytes(), 16);
```
The getIVShifted() performs some XOR and ROR Operations with the first agreement that this conversation had. Keep that in mind! But besides that pretty easy, isn't it? The IV is a little bit more complicated:
```
byte[] agreement = ((Curve25519)curve25519Obj).calculateAgreement(paramPublicKeyStorage.getMSGPubKey(), localCurve25519KeyPair.getPrivateKey());
byte[] ivBytes = sha256Hmac(agreement, "WhisperSystems".getBytes(), 16);
```
So the iv calculates from the agreement between KP_MSG and KP_ENC. We don't have those key pairs :( But what we do have is the log of the agreement after "/session/ephemeral/shared/" . So all we need for a AES decrypt is:
 * First agreement ever in this conversation (logged in session/est/base/)
 * Agreement of the current message (logged in ephemeral/shared/)
 * Number of the current message = shiftCounter (logged in the log of Bob)

And we got all those information! So i wrote a Java program that performs the decryption. It wasn't as simple as it sounds, since the sha256Hmac-Function wasn't decompiled properly. It seems that dex2jar doesn't like abstract classes with inherited classes, maybe it was some kind of additional obfuscation. Anyway, here are the decrypted messages from Alice to Bob:
```
Hello, bobby :)
What du U think about new messenger`s protocol?..
Wha..?
Dant warry, I am the one who checked it. It is safe for our deal.
So take it --- h4ck1t{X}
X=1_b3tT3r_w1Ll_b3_u5iNg_AX0L0TL```
```

The Java Source is attached, together with my "cleaned" decompiled sources .

Flag: h4ck1t{1_b3tT3r_w1Ll_b3_u5iNg_AX0L0TL}


  

