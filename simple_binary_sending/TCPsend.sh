#!/bin/sh
#usage: ./TCPsend.sh port_number file_name length

#if [ -z "$1" ];then
#  echo "Usage: ./TCPsend.sh file_name port_number"
#  exit
#fi
#if [ $# -ne 2 ];then
#  echo "Need both file name and port number!"
#  exit
#fi

echo Sending binary data……

dd if=$2 bs=$3 count=1  > /dev/tcp/127.0.0.1/$1

echo End

