#!/bin/bash

umount -f -l /nfs-mount-point
service nfs restart
rm -rf /nfs-mount-point
