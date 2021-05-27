#!/bin/sh
while [ ! -f /var/lib/certidude/server-secrets/self_cert.pem ]; do
    sleep 1
done
exec nginx -g "daemon off; error_log /dev/stdout info;"
