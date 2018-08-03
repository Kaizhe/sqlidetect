#!/bin/bash

# This is the script to run the SQLi Detector container on localhost and listen on docker0 interface

docker rm -f sqli || true 

docker run -it --rm --net=host --cap-add=NET_ADMIN --name sqli kaizheh/sqlidetect
