#!/bin/bash

sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/tracing_on'
pgrep -f CassandraDaemon
sudo pkill -TERM -f CassandraDaemon
#echo "waiting 5 seconds before force-killing"
#sleep 5
#sudo pkill -9 -f CassandraDaemon

exit 0
