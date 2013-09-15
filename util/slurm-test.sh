#!/bin/sh

BIN=/usr/local/squid/sbin/squid
CONFIG=/etc/squid/slurm.conf
LOG=/var/log/squid/slurm.log

echo "Shutting Down Squid"
$BIN -f $CONFIG -k shutdown
$BIN -f $CONFIG -k shutdown
$BIN -f $CONFIG -k shutdown

echo "Clearing Logs"
echo '' > $LOG

echo "Starting Squid"
$BIN -f $CONFIG

echo "Review Logs"
tail -f $LOG

