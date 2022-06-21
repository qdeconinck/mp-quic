#!/bin/sh

docker run --name squid -d -p 3128:3128 -v $PWD/passwords:/etc/squid/passwords -v $PWD/squid.conf:/etc/squid/squid.conf -v $PWD/logs:/var/log/squid datadog/squid

# export http_proxy="http://admin:changeme@127.0.0.1:10500"
# export https_proxy=$http_proxy