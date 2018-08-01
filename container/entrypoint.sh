#!/bin/bash

set -e

RET=$(ifconfig | grep docker0 | wc -l)
while [ $RET -eq 0 ]
do
	sleep 1
	RET=$(ifconfig | grep docker0 | wc -l)
done

#tshark -i docker0 -Y "mysql.command==3" -T fields -e mysql.query
/sqlidetect
