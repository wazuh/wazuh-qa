#!/bin/bash

umount -f -l /nfs-mount-point
service nfs-kernel-server restart
rm -rf /nfs-mount-point
