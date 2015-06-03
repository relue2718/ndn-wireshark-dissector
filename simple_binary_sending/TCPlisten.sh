#!/bin/sh
#usage: ./TCPlisten.sh port_number

if [ -z "$1" ];then
  echo "Usage: ./TCPlisten.sh port_number"
  exit
fi
if [ $# -ne 1 ];then
  echo "Only support 1 port!"
  exit
fi

echo Waiting for messages……

nc -l $1

echo See you!
