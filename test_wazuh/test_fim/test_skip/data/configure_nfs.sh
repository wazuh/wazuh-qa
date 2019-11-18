#!/bin/bash
# Check if ip package is installed and get the manager IP
$1 | grep -E "iproute.*" || $2 iproute
ip=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
# Check if nfs-utils is installed
$1 | grep -E "nfs-utils.*" || $2 nfs-utils
service nfs restart
mkdir /media/nfs-folder
mkdir /nfs-mount-point
# If we are on a FreeBSD distribution, configure NFS differently
if [ "$3" = "true" ]
then
  echo 'nfs_client_enable="YES"' >> /etc/rc.conf
  echo 'nfs_client_flags="-n 4"' >> /etc/rc.conf
  nfsiod -n 4
  mount -v "$ip":/media/nfs-folder /nfs-mount-point/
else
  echo "/media/nfs-folder     $ip*(rw,sync,no_root_squash)" > /etc/exports
  exportfs -a
  mount -o hard,nolock "$ip":/media/nfs-folder /nfs-mount-point/
fi
