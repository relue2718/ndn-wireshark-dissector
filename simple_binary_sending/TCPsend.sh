#!/bin/sh
#usage: ./TCPsend.sh file_name

if [ -z "$1" ];then
  echo "Usage: ./TCPsend.sh file_name port_number"
  exit
fi
if [ $# -ne 2 ];then
  echo "Need both file name and port number!"
  exit
fi

echo Sending binary data……

data=`od -x $1`
dd if=$1 bs=1000 count=1  > /dev/tcp/127.0.0.1/$2

echo End
