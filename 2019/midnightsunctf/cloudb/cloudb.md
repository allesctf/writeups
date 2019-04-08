---
tags: ["web"]
author: "LinHe"
---
# Challenge
> These guys made a DB in the cloud. Hope it's not a rain cloud...  
> Service: [http://cloudb-01.play.midnightsunctf.se](http://cloudb-01.play.midnightsunctf.se)

When visiting the website, we can click on "Demo" to create a new account. There is also an admin login.  
We first checked if we could perform SQL injections, but that didn't work.

# Solution
When creating a new account, a request is made to `http://cloudb-01.play.midnightsunctf.se/userinfo/<email>/info.json`.  
The result is a JSON file, containing the intersting key `admin` which is set to `false`.  
Obviously, the goal is to change this to `true`.  

# Becoming admin
After creating an account (or logging in), we are given the option to edit our account. The interesting part here is that we can upload a new profile picture.  
When uploading the picture, a request is made to `http://cloudb-01.play.midnightsunctf.se/signature` with to parameters: acl and hmac.  
The response is an Amazon S3 POST policy and a signature. The policy and signature are then used to upload the picture to an S3 bucket.  
The policy looks like this:
```JavaScript
{
    'expiration': '2019-04-08T17:06:05.000Z',
    'conditions': [
      ['content-length-range', 1, 10000],
      {'bucket': 'cloudb-profilepics'},
      {'acl': 'public-read'},
      ['starts-with', '$key', 'profilepics/']
    ]
}
```

It looks like the acl parameter is directly inserted into the JSON.  
When changing the acl parameter, the hmac becomes invalid so we needed to find out how to create our own hmac's.  
We found the relevant code in the website's JavaScript:
```JavaScript
app = {
  hmac: function(b, e) {
    return CryptoJS.HmacSHA256(b+e, this.secret+"").toString(CryptoJS.enc.Hex)
  },
  secret: {secret: "cl0udb_Pr0d_Do_NOT_d1sclose"},
  // ...
}
```
To create the correct hmac for our acl, we had to call app.hmac(acl_data, "").  
When implementing this in Python, I first only got wrong hmacs.  
This is because I used `cl0udb_Pr0d_Do_NOT_d1sclose` as key.  
However, after looking at the JavaScript code again, I noticed that they use `app.secret+""` as the key.  
Because of the way how JavaScript works, this results in `[object Object]` being the key...  

Now that we were able to create correct hmacs, we tried to change acl to `'}`, which resulted in the JSON looking like this:
```JavaScript
{
    'expiration': '2019-04-08T17:06:05.000Z',
    'conditions': [
      ['content-length-range', 1, 10000],
      {'bucket': ''}'},
      {'acl': 'public-read'},
      ['starts-with', '$key', 'profilepics/']
    ]
}
```
We now knew that the acl parameter is directly inserted into the JSON without any checks.  
The Plan now was to change the conditions so that we could write anywhere on the bucket, not just to profilepics.  
This wasn't easy as we needed to get rid of the `starts-with` condition and Amazon only allowed the keys `expiration` and `conditions` and creating a second `conditions` key would cause Amazon to ignore the first one.  
After some time we found out that if there were two keys, one named `conditions` and the other one named `Conditions` (notice the capital 'C'), Amazon would ignore the `Conditions` key and only use the `conditions` key.  
We tried to upload our updated user JSON file to `userinfo/<email>/info.json`, then went to the admin page, logged in and ... we still got `You are not admin!` Something obviously didn't work.  
After downloading our info.json from `http://cloudb-01.play.midnightsunctf.se/userinfo/<email>/info.json`, we noticed that it still had admin set to `false`.  
We then created a new account and then tried to download it's info.json directly from the S3 bucket. However, it wasn't there.  
Then we noticed that the name of the bucket was `cloudb-profilepics`. After a few tries we found out that there is another bucket named `cloudb-users` which had a users directory. We found out that the `info.json` for each user was stored in `users/<email>/info.json`.  
We now had to change the JSON policy to allow us to write into the `cloudb-users` bucket. To do this, we used `public-read-write'}],'conditions': [['starts-with', '$bucket', ''],['starts-with', '$key', ''],{'acl': 'public-read-write'}],'Conditions': [{'acl': 'public-read-write` as acl, resulting in the following policy:
```JavaScript
{
  'expiration': '2019-04-08T17:45:19.000Z',
  'conditions': [
    ['content-length-range', 1, 10000],
    {'bucket': 'cloudb-profilepics'},
    {'acl': 'public-read-write'}
  ],
  'conditions': [
    ['starts-with', '$bucket', ''],
    ['starts-with', '$key', ''],
    {'acl': 'public-read-write'}
  ],
  'Conditions': [
    {'acl': 'public-read-write'},
    ['starts-with', '$key', 'profilepics/']
  ]
}
```
Amzon would use the second `conditions` key which allows us to write to any file in any bucket that the signer has access to.  
Additionally, the `Conditions` key would be ignored.  
This allowed us to upload a new info.json with `admin` set to `true`.  
After logging in as admin, we got the flag: `midnight{n3x7_t1m3_w3ll_d0_1t_Cl0udl3sslY}`

See exploit.py for the full exploit.
