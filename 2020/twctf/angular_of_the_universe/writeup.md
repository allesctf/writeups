# Angular of the Universe
Category: Web

Flag1: Solves: 39, Score: 139  
Flag2: Solves: 34, Score: 149

> You know, everything has the angular.
A bread, you, me and even the universe.
Do you know the answer?

[http://universe.chal.ctf.westerns.tokyo](http://universe.chal.ctf.westerns.tokyo)


## Solution
There are two flags in this challenge, and I lost all files to it.. Except the python server on nix1.. RIP


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