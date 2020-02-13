#!/bin/bash

umount -f -l /nfs-mount-point
service nfs-kernel-server restart
rmdir /nfs-mount-point
