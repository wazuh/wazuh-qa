#!/bin/bash

dist=$1

if [ "$dist" == "ubuntu" ]; then
  if [ ! "$(dpkg -l | grep -E "prelink.*")" ]; then
    apt-get update
    apt-get install -y prelink
  fi
else
  if [ ! "$(rpm -qa | grep -E "prelink.*")" ]; then
    yum -y install prelink
  fi
fi
