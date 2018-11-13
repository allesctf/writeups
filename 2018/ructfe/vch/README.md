# vch (Reversing)

## Introduction
This was the only challenge I worked on during the 9 hour CTF playtime. One hour before the finish I finally noticed the vulnerability and a very bad script to solve the challenge was written. It didn't give many points, but still: Solved!

## VulnBox Analysis
We notice a three docker container running:
1. MongoDB
2. Vulnerable App
3. Vulnerable App Builder
```txt
CONTAINER ID        IMAGE                      COMMAND                  CREATED             STATUS                          PORTS                        NAMES
60c5ed1b67ea        mongo                      "docker-entrypoint.s…"   3 minutes ago       Up 3 minutes                    27017/tcp                    vch_mongo_1_1003a9745283
361721bff1ec        microsoft/dotnet:2.1-sdk   "dotnet run -c Relea…"   3 minutes ago       Up 3 minutes                    127.0.0.1:19999->19999/tcp   vch_vch_1_dc70a160731c
e9e3ca4ebabb        microsoft/dotnet:2.1-sdk   "dotnet build -c Rel…"   3 days ago          Restarting (0) 25 seconds ago                                vch_vch_run_1_375a4ea1c627
```

The running nginx only forwarded the docker port 19999 to 9999.

MongoDB was the data storage for the app, *vulnerable app* the website with ASP host and *vulnerable app builder* restarted itself every minute or so. This way the newest source was build, but not deployed until you restarted the vulnerable app container.

## Sourcecode Analysis
The source code to the app was given, so we had an easy time analyzing the app without the use of reversing. There were 3 dotnet core applications, two libraries and one ASP.NET core website that ran itself once started. 

1. NTPTools
2. Vch.Core
3. VchAPI

Lets start with the API: It connects to the MongoDB at startup and hosts an REST interface "BoardController.cs" via dependency injection. The launchSettings.json reveals the API endpoint:
```json
{
  "$schema": "http://json.schemastore.org/launchsettings.json",
  "profiles": {
    "api": {
      "commandName": "Project",
      "launchBrowser": true,
      "launchUrl": "api/board/messages",
      "applicationUrl": "http://localhost:19999"
    }
  }
}
```
We got several endpoints:
* [GET] /messages : Read all posted messages
* [POST] /message/post/{userId} : Post message for the user {userId}
* [GET] /messages/{userId} : Read messages from the user {userId}
* [POST] /user : Register a user

While the messages endpoint only returns objects of "PublicMessage" (with some fields redacted), the messages/{userId} endpoint returns the full message structure including the user data and flag.
The POST message endpoint simply adds a message. The POST /user endpoint registers a new user provided as json structure. This created user could be used to post new messages. Basically only a user UUID is generated and returned.

From our packet logger we could see that the flagbot "Supervisor 1.0.0" created a user every two minutes and posted a message afterwards. During user registration the "TrackingCode" field of the user is set where the flag is stored.

## Fixing
The exploit idea is obvious: We need to obtain the flagbots user ID and retrieve the flag messages. Lets check out the UUID generation (located in the library Vch.Core):

The constructor initializes the "lastComputedHash" byte array trough an Guid, although only 6 bytes are used:
```csharp
public class UUIDProvider : IUUIDProvider
{
    public UUIDProvider(ITimeProvider timeProvider)
    {
        this.timeProvider = timeProvider;
        shaProvider = new SHA512Managed();

        lastComputedHash = new byte[8];
        Array.Copy(Guid.NewGuid().ToByteArray(), lastComputedHash, 6);
    }
```
The code to generate the UUID is:
1. Retrieve current timestamp (64 bit) via NTP Server
2. Retrieve "lastComputedHash" (64 bit) and update lastComputedHash
3. XOR them
4. Return the UUID as 64 bit integer
```csharp
public async Task<UInt64> GetUUID(UserMeta meta)
{
    var timestamp = await timeProvider.GetTimestamp(meta.VaultTimeSource.Endpoint());
    var secure = GetNextSecureRandomBytes();

    var timeBits = new BitArray(timestamp.ToBytes());
    var rndBites = new BitArray(secure);

    byte[] result = new byte[8];
    timeBits.Xor(rndBites).CopyTo(result, 0);

    return BitConverter.ToUInt64(result);
}
```
GetNextSecureRandomBytes() is super simple. Basically sha512()
1. Generate SHA512 Hash of the lastComputedHash (6 byte input)
2. Copy the first 6 byte of the hashed result to lastComputedHash 
3. Return lastComputedHash
```csharp
private byte[] GetNextSecureRandomBytes()
{
    var hash = shaProvider.ComputeHash(lastComputedHash);
    Array.Copy(hash, lastComputedHash, 6);
    return lastComputedHash.ToArray();
}
```
So basically: new = sha512(old)[0:6]
Ony might think: "Only 6 bytes were copied to the 8 byte buffer, that is the flaw!". But no, this fix wouldn't protect against the attack described later. My first and final fix was not pretty, but worked: I xored "result" and "lastComputedHash" with two static buffers. Since there would be only automated exploits this was enough :D

## The Exploit
My first thoughts were about an exploit that would gain RCE. This would explain the docker container. But since Newtonsoft.Json was used as JSON Library (which is pretty secure unless you force it not to) Object Injection was impossible. And since a direct databinding was used SQL injection was not an option as well.

The registration of the flag bot looked a little bit odd, there was an IP and port included in the registration:
```json
{"LastName": "1.0.0", "TrackingCode": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "FirstName": "Supervisor", "VaultTimeSource": {"IPAddres": "10.10.10.10", "Port": "123"}}
```
The NTP Server used to retrieve the time was included in the user structure! This way we can provide our own timestamps, basically turning the above XOR into a leak of the current "lastComputedHash". When 0x00 is provided as time, the calculation of the new user ID reduces to:
```json
lastComputedHash ^ 0x00 = lastComputedHash
```
Ok thats a way to leak the hash (and all the following hashes!).

Lets talk a little bit about NTP:
```txt
The 64-bit timestamps used by NTP consist of a 32-bit part for seconds and a 32-bit part for fractional second, giving a time scale that rolls over every 232 seconds (136 years) and a theoretical resolution of 2−32 seconds (233 picoseconds). NTP uses an epoch of January 1, 1900 so the first rollover will be on February 7, 2036.
```
The 32 bit part for seconds could be brute forced, since a new flag is generated each 120 seconds. But the fraction part makes it (AFAIK) impossible to guess the last generated userId. In the packet capture I saw some teams brute forcing our userIds, so maybe there is still a way...

Anyways, since we can't guess old userIds we have to think about something different. We could actually generate arbitrary ID, using a 64 bit timestamp we provide and a secret we know!
```txt
lastHash ^ timestamp = uuidToGenerate
=> timestamp = uuidToGenerate ^ lastHash
```
But seems worthless at first. But when I studied the REST endpoints for the 99th time I saw the method:
```csharp
[HttpPost("message/post/{userId}")]
public async Task<ActionResult<Message>> PostMessageAsync(string userId)
{
    try
    {
        var user = userStorage.FindUser(userId);
        if (user == null)
            return NotFound();

        var text = await ParseContent<string>();
        return messageStorage.AddOrUpdateMessage(MessageId.From(await uuidProvider.GetUUID(user.Meta)), user, text).ToActionResult();
    }
```
The method says **AddOrUpdateMessage**! So what happens when we provide a message ID of a message that not our user generated, but the flagbot ? 
```csharp
public Message AddOrUpdateMessage(MessageId id, UserInfo userInfo, string text)
{
    return messages.AddOrUpdate(id, messageId =>
    {
        var message = Message.Create(text, userInfo, messageId);
        messagesCollection.InsertOneAsync(message).Wait();
        return message;
    },
    (messageId, message) =>
    {
        message.Text = text;
        var update = Builders<Message>.Update.Set(oldMessage => oldMessage.Text, text);
        messagesCollection.UpdateOneAsync(oldMessage => oldMessage.MessageId.Equals(messageId), update).Wait();
        return message;
    });
}
```
Only the message text gets updated and the whole message is returned. Including all fields, including the user info and including the flag!

We only got to know which message from the Flagbot was. Luckily the bot used ~10 different messages only, so those messages could be easily identified.

So the exploit script was:
1. Host a NTP Server that sends the timestamp 0x00
2. Create a user at the target server and set our NTP server as endpoint (POST /user). Store userID as createdUserId
3. Leak currentHash trough createdUserId
4. Query messages of the enemy server (GET /messages)
5. Search last message of the flag bot and grab the messageId
6. Calculate timestamp for this messageId
7. Host another NTP server, returning the calulcated timestamp
8. Post Message (POST /message/{createdUserId})
9. Retrieve Flag

Its quite a flow for only one flag, but the automation reached around 4 seconds per flag.

Im curious if there were other flaws in the application that I didn't notice...

Anyway, fun challenge! And very, very, very messy script attached.

