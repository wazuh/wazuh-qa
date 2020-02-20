#!/bin/bash
# Check if ip package is installed and get the manager IP
apt-get update
dpkg -l | grep -E "iproute.*" || apt-get install -y iproute2
ip=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
# Check if nfs-utils is installed
dpkg -l | grep -E "nfs-common.*" || apt-get install -y nfs-common
dpkg -l | grep -E "nfs-kernel-server.*" || apt-get install -y nfs-kernel-server
service nfs-kernel-server restart
mkdir /media/nfs-folder
mkdir /nfs-mount-point
echo "/media/nfs-folder     $ip*(rw,sync,no_root_squash)" > /etc/exports
exportfs -a
service nfs-kernel-server restart
mount -o hard,nolock "$ip":/media/nfs-folder /nfs-mount-point/
