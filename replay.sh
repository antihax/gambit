#!/bin/bash
if [[ -z "$1" ]] 
then
    echo "missing hash"
else
    ip=`dig @resolver4.opendns.com myip.opendns.com +short`
    wget -O - -q https://iam.antihax.net/file/antihax-pass/raw/$1 | nc $ip 55
fi
