#!/bin/bash

umount -f -l /nfs-mount-point
service nfs restart
rmdir /nfs-mount-point
