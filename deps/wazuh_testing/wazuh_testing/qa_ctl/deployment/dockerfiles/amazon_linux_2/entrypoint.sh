#!/bin/bash

/usr/bin/ssh-keygen -A  # Generate the ssh keys
/usr/sbin/sshd

tail -f /dev/null
