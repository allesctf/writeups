# Does Linux Dream of Windows?

Flag1: Solves: 7, Score: 163  
Flag2: Solves: 1, Score: 400

> Tux is dreaming of Windows.
[http://dream.chal.ctf.westerns.tokyo](http://dream.chal.ctf.westerns.tokyo)

The server is running a `ASP.NET` website on `ubuntu` using `Apache 2`. To get the first flag we have to get the content of `upload.aspx`, `upload.aspx.cs` and `Web.config`. Apache checks for the file extension when doing a request. If it is in a special list, the requests gets forwarded to `ASP.NET`. Otherwise the server responds with the raw content. We tried several thing, the website allows a user to upload files, but all extensions that would be interpreted by `ASP.NET` are blacklisted. Later a hint got released: `Hint2 (2020-09-19 20:00:00 UTC): Did you try "Back To Top" from upload.aspx? What's happening?` We did what the hint suggests and noticed that the url ends with `INDEX.HTM`. We have known of some weird behavior when using unicode and character case conversion, but we never thought it would work, just tried, because nothing had worked. It worked. There are some unicode characters that get when converted to upper/lower case "normal" ASCII. For example the german `ß` when converted to upper-case becomes `SS`. We found a writeup on google with a list of other characters like that, but lost the link to it. Those are the URLs we used.

```
http://dream.chal.ctf.westerns.tokyo/upload.a%C5%BFpx
http://dream.chal.ctf.westerns.tokyo/upload.a%C5%BFpx.c%C5%BF
http://dream.chal.ctf.westerns.tokyo/Web.con%EF%AC%81g
```

## Flag1

```
TWCTF{f29941def1f24f2c1e15ba36390e1302a61614bfc698267bc4a13485d6ae}
```