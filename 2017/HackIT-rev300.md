# Rev300 - APIServer

**Description:** Client can access the API server. Try to login as an admin who is used to use the same passwords everywhere.

Another APK, but harder (= native code :D). Only 4 teams in total solved this task! It looks like a simple API where you can register users and retrieve information about the API. All the messages are send via POST and signed with a signature. So far so good, lets take a sniff with Wireshark:

**Register**
```
POST /api/register HTTP/1.1
Content-Type: text/plain; charset=utf-8
Content-Length: 102
Host: 195.88.243.197:8060
[...]
sig_body=f8c13266314f9f7f989e3b49d0be30eac0969f24d9a0d9698a965a7efaca1a69.name%3Duser%26&sig_version=4

HTTP/1.1 200 OK
[...}
Server: H4CK1TServer/v2017.08

personal_key=h4ck1t48bb6e862e54f2a795ffc4e541caed4d
```
**Info**
```
POST /api/info HTTP/1.1
[...]
sig_body=b3a8db7e1ec33b1802d02610db62878c9c7337efac479e1e461ec896f6d43d2a.personal_key%3Dh4ck1t48bb6e862e54f2a795ffc4e541caed4d%26&sig_version=4

HTTP/1.1 200 OK
[...]
Server: H4CK1TServer/v2017.08

1) method=register, params=[name : 'your name'] = personal_key
2) method=info, params=[personal_key : 'your registration key' = TEXT]
3) method=login_admin, params=[hex_password : 'My password in HEX. Im stupid admin and use a SINGLE password everywhere :)']
```
The Android app only implements register and info. We get a big hint here: the admin uses the same password everywhere!

Lets dive into reversing: The Java client has a function "buildPostArgs()" which iterates all the post parameters, concats and signs them:
```
// buildPostArgs()
    // str1 holds all the post args in one string
    byte[] arrayOfByte = MainActivity.signature(str1.getBytes());
    try
    {
      Object[] arrayOfObject = new Object[2];
      arrayOfObject[0] = new String(Hex.encodeHex(arrayOfByte));
      arrayOfObject[1] = URLEncoder.encode(str1, "UTF-8");
      String str3 = String.format("%s.%s", arrayOfObject);
      str2 = str3;
      return String.format("sig_body=%s&sig_version=4", new Object[] { str2 });
    }x
```
The "signature" function is implemented via JNI, so we load the [libsignatures.so]() in IDA.
```
  v3 = a1;
  v4 = a3;
  operator new[](0x20u);
  v5 = (*(int (__fastcall **)(int, int))(*(_DWORD *)v3 + 684))(v3, v4);
  v6 = v5;
  if ( (signed int)v5 <= -1 )
    v5 = -1;
  v7 = operator new[](v5);
  (*(void (__fastcall **)(int, int, _DWORD, unsigned int))(*(_DWORD *)v3 + 800))(v3, v4, 0, v6);
  v8 = sub_4660();
  v9 = v8;
  *(_DWORD *)v8 = 'kc4h';
  *(_WORD *)(v8 + 4) = 't1';
  v10 = (*(int (__fastcall **)(int, int))(*(_DWORD *)v3 + 684))(v3, v4);
  sub_485C(v7, v10, v9, 40);
  v11 = (*(int (__fastcall **)(int, signed int))(*(_DWORD *)v3 + 704))(v3, 32);
  (*(void (__fastcall **)(int, int, _DWORD, signed int))(*(_DWORD *)v3 + 832))(v3, v11, 0, 32);
  return v11;
```
Quite confusing, isn't it? Lets clean this mess up:
```
  v3 = a1;
  v4 = a3;
  operator new[](0x20u);
  length = strlen(javastring)
  argumentString =  new char[](length);
  v8 = copyJNIStringToCString(javastring)
  
  // Wierd function we know nothing about !
  v9 = sub_4660();
  
  v10 = v9; // Signature bytes ? 
  *(_DWORD *)v9 = 'kc4h'; // FIll the first chars with h4ck1t
  *(_WORD *)(v9 + 4) = 't1';
  
  // No idea
  v11 = (*(int (__fastcall **)(int, int))(*(_DWORD *)v3 + 684))(v3, v4);
  
  // Actual signing
  sub_485C(argumentString, v11, v10, 40);
  
  // Copy native bytes to Java Byte Array, etc...
  v12 = (*(int (__fastcall **)(int, signed int))(*(_DWORD *)v3 + 704))(v3, 32);
  (*(void (__fastcall **)(int, int, _DWORD, signed int))(*(_DWORD *)v3 + 832))(v3, v12, 0, 32);
  return v12;
```
A little bit better, but still no idea how the signature is produced. IDA comes with a great Android GDB server and I even rooted my phone for this challenge. After some tracing around in the library you pretty fast get lost. There are basicly two signing functions that are applied to certain memory regions with static input data and offsets. 

So what about this wierd sub_4660 function ? It takes no argument, altough it computes something... And it applies some XOR to a static memory string! And its used by the signature function!! Lets image a signing function as sign(inputBuffer, outputBuffer, key) , then v9 = v10 matches the key ! And the key starts with h4ck1t! It was a plain guess, but it was worth a try. So i dumped the memory of v9 after it was decrypted and stored it as hex string:

```
6834636B31741E301EE91B1CEC1EEFEE1CE919F436F4E9E925EF261BE8ED1B29F4ED1E1C191F1B1B
```

Next I sent it in as hex string to login_admin. But the request was refused (of course) since we had no signature for this certain post parameters. Replacing the input of the signature-function via the IDA debugger didn't work, so i simply patched the smali code to sign this certain message for me:
```
 const-string v1, "name"
 iget-object v2, p0, Lanative/hackit2017/com/apiclient/Api$1;->val$name:Ljava/lang/String;

.line 18
invoke-virtual {v0, v1, v2}, Lanative/hackit2017/com/apiclient/Client;->addPost(Ljava/lang/String;Ljava/lang/String;)Lanative/hackit2017/com/apiclient/Client;
```
PATCHED TO:
```
const-string v1, "hex_password"
const-string v2, "6834636B31741E301EE91B1CEC1EEFEE1CE919F436F4E9E925EF261BE8ED1B29F4ED1E1C191F1B1B"

.line 18
invoke-virtual {v0, v1, v2}, Lanative/hackit2017/com/apiclient/Client;->addPost(Ljava/lang/String;Ljava/lang/String;)Lanative/hackit2017/com/apiclient/Client;
```
So the next time i triggered "register" on the installed and modified app, the post message was signed. Without any big hope I send it via curl and had a good laugh when it was right at the first try!
```
user@ubuntu:~/Schreibtisch/ITCTF/lab1$ curl -X POST http://195.88.243.197:8060/api/login_admin --data "sig_body=45cb847e3bafe29b044276b2c23532162c690516ea1e7e3398accb525ba41082.hex_password%3D6834636B31741E301EE91B1CEC1EEFEE1CE919F436F4E9E925EF261BE8ED1B29F4ED1E1C191F1B1B%26&sig_version=4"
flag=h4ck1t{wH3n_u_trY_t0_h1d3_smTh_b3_r34dY_f0r_d1sc10sur3}
```

Flag: h4ck1t{wH3n_u_trY_t0_h1d3_smTh_b3_r34dY_f0r_d1sc10sur3}

