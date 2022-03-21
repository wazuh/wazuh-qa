#!/bin/bash
# Check if ip package is installed and get the manager IP
rpm -qa | grep -E "iproute.*" || yum -y install iproute
ip=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
# Check if nfs-utils is installed
rpm -qa | grep -E "nfs-utils.*" || yum -y install nfs-utils

service nfs restart
if [ $? -ne 0 ]; then
    service nfs-server restart
fi

mkdir /media/nfs-folder
mkdir /nfs-mount-point
echo "/media/nfs-folder     $ip*(rw,sync,no_root_squash)" > /etc/exports
exportfs -a

service nfs restart
if [ $? -ne 0 ]; then
    service nfs-server restart
fi

mount -o hard,nolock "$ip":/media/nfs-folder /nfs-mount-point/
