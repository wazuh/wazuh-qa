#!/bin/bash
rpm -qa | grep -E "nfs-utils.*" || yum -y install nfs-utils
service nfs restart
mkdir /media/nfs-folder
mkdir /nfs-mount-point
echo "/media/nfs-folder     172.19.0.100*(rw,sync,no_root_squash)" > /etc/exports
exportfs -a
