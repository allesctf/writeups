## urlcheck v1

This task was a flask app that allows requesting URLs if:
- `urlparse(url).netloc` is an IPv4 address (regex match)
- the IP is not a local IP, based on a series of tests for local address ranges

The app also includes an endpoint that returns the flag if it's requested from 127.0.0.1.

Notably, the URL is parsed two times:
- by `urllib.parse.urlparse` for the regex check
- and `requests` (which is using `urllib3.util.parse_url` internally) for the requests

We tried exploiting the difference between these URL parsers but couldn't get the URLs to pass the regex check.

We googled a bit and found a page that talked about URL parsers and blocklist bypasses. This bypass works:

`0177.0.0.1`

It's matched by the regex (`^\d+\.\d+\.\d+\.\d+$`) and the check function parses it to `[177, 0, 0, 1]`, which is allowed.
When passed to the operating system though (`getaddrinfo`, ..), the leading zero marks the first octet as octal (with 0o177 == 127), and requests localhost.

This doesn't feel like it's the intended solution though as it does not depend on the two Python URL parsers in use.

## urlcheck v2

Similar setup to urlcheck v1, but:
- IP is not checked by regex anymore
- IP whitelist based on `ipaddress.ip_address(x).is_global`
- FQDN is resolved using `socket.gethostbyname` before checking IP address
- requests.get if IP is allowed

Setup looks a lot like we'll need to exploit parser differences (`requests` vs `gethostbyname`), but:
- name is resolved by gethostbyname and requests (=> twice!)
- we tried dns rebinding (https://lock.cmpxchg8b.com/rebinder.html is nice)
- it worked
- probably not the intended solution though