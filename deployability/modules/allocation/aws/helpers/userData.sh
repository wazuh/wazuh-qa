#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

# Default values
DIST_NAME="Linux"
DIST_VER="0"
DIST_SUBVER="0"
SSH_PORT="2200"


if [ -r "/etc/os-release" ]; then
    . /etc/os-release
    DIST_NAME=$ID
    DIST_VER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
    if [ "X$DIST_VER" = "X" ]; then
        DIST_VER="0"
    fi
    if [ "$DIST_NAME" = "amzn" ] && [ "$DIST_VER" == "2018" ]; then
        DIST_VER="1"
    fi
    DIST_SUBVER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')
    if [ "X$DIST_SUBVER" = "X" ]; then
        DIST_SUBVER="0"
    fi
fi

if [ ! -r "/etc/os-release" ] || [ "$DIST_NAME" = "centos" ]; then
    # CentOS
    if [ -r "/etc/centos-release" ]; then
        DIST_NAME="centos"
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/centos-release`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.*([0-9]{0,2}).*/\1/p' /etc/centos-release`

    # Fedora
    elif [ -r "/etc/fedora-release" ]; then
        DIST_NAME="fedora"
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2}) .*/\1/p' /etc/fedora-release`

    # RedHat
    elif [ -r "/etc/redhat-release" ]; then
        if grep -q "CentOS" /etc/redhat-release; then
            DIST_NAME="centos"
        else
            DIST_NAME="rhel"
        fi
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/redhat-release`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.*([0-9]{0,2}).*/\1/p' /etc/redhat-release`

    # Ubuntu
    elif [ -r "/etc/lsb-release" ]; then
        . /etc/lsb-release
        DIST_NAME="ubuntu"
        DIST_VER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*([0-9][0-9])\.[0-9][0-9].*/\1/p')
        DIST_SUBVER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*[0-9][0-9]\.([0-9][0-9]).*/\1/p')

    # Gentoo
    elif [ -r "/etc/gentoo-release" ]; then
        DIST_NAME="gentoo"
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.[0-9]{1,2}.*/\1/p' /etc/gentoo-release`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.([0-9]{1,2}).*/\1/p' /etc/gentoo-release`

    # SuSE
    elif [ -r "/etc/SuSE-release" ]; then
        DIST_NAME="suse"
        DIST_VER=`sed -rn 's/.*VERSION = ([0-9]{1,2}).*/\1/p' /etc/SuSE-release`
        DIST_SUBVER=`sed -rn 's/.*PATCHLEVEL = ([0-9]{1,2}).*/\1/p' /etc/SuSE-release`
        if [ "$DIST_SUBVER" = "" ]; then #openSuse
            DIST_SUBVER=`sed -rn 's/.*VERSION = ([0-9]{1,2})\.([0-9]{1,2}).*/\1/p' /etc/SuSE-release`
        fi

    # Arch
    elif [ -r "/etc/arch-release" ]; then
        DIST_NAME="arch"
        DIST_VER=$(uname -r | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
        DIST_SUBVER=$(uname -r | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')

    # Debian
    elif [ -r "/etc/debian_version" ]; then
        DIST_NAME="debian"
        DIST_VER=`sed -rn 's/[^0-9]*([0-9]+).*/\1/p' /etc/debian_version`
        DIST_SUBVER=`sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p' /etc/debian_version`

    # Slackware
    elif [ -r "/etc/slackware-version" ]; then
        DIST_NAME="slackware"
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.[0-9].*/\1/p' /etc/slackware-version`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.([0-9]).*/\1/p' /etc/slackware-version`

    # Darwin
    elif [ "$(uname)" = "Darwin" ]; then
        DIST_NAME="darwin"
        DIST_VER=$(uname -r | sed -En 's/[^0-9]*([0-9]+).*/\1/p')
        DIST_SUBVER=$(uname -r | sed -En 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')

    # Solaris / SunOS
    elif [ "$(uname)" = "SunOS" ]; then
        DIST_NAME="sunos"
        DIST_VER=$(uname -r | cut -d\. -f1)
        DIST_SUBVER=$(uname -r | cut -d\. -f2)

    # HP-UX
    elif [ "$(uname)" = "HP-UX" ]; then
        DIST_NAME="HP-UX"
        DIST_VER=$(uname -r | cut -d\. -f2)
        DIST_SUBVER=$(uname -r | cut -d\. -f3)

    # AIX
    elif [ "$(uname)" = "AIX" ]; then
        DIST_NAME="AIX"
        DIST_VER=$(oslevel | cut -d\. -f1)
        DIST_SUBVER=$(oslevel | cut -d\. -f2)

    # BSD
    elif [ "X$(uname)" = "XOpenBSD" -o "X$(uname)" = "XNetBSD" -o "X$(uname)" = "XFreeBSD" -o "X$(uname)" = "XDragonFly" ]; then
        DIST_NAME="bsd"
        DIST_VER=$(uname -r | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
        DIST_SUBVER=$(uname -r | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')

    elif [ "X$(uname)" = "XLinux" ]; then
        DIST_NAME="Linux"

    fi
    if [ "X$DIST_SUBVER" = "X" ]; then
        DIST_SUBVER="0"
    fi
fi

if [ "$DIST_NAME" = "amzn" ] || [ "$DIST_NAME" = "sles" ] \
    || [ "$DIST_NAME" = "opensuse-leap" ]; then
    sudo sed -i "s/#Port\s22/Port ${SSH_PORT}/" /etc/ssh/sshd_config
    sudo systemctl restart sshd.service
fi

if [ "$DIST_NAME" = "rhel" ] || [ "$DIST_NAME" = "centos" ] || [ "$DIST_NAME" = "rocky" ] \
    || [ "$DIST_NAME" = "fedora" ] || [ "$DIST_NAME" = "almalinux" ]; then
    sudo sed -i "s/#Port\s22/Port ${SSH_PORT}/" /etc/ssh/sshd_config
    if [ "$DIST_NAME" = "centos" ] && [ "$DIST_VER" != "7" ]; then
        sudo yum -y install policycoreutils-python-utils
    else
        sudo yum -y install policycoreutils-python-utils
    fi
    sudo semanage port -a -t ssh_port_t -p tcp ${SSH_PORT}
    sudo systemctl restart sshd.service
    if sudo firewall-cmd --state 2>/dev/null | grep -q -w "running"; then
        sudo firewall-cmd --permanent --zone=public --add-port=${SSH_PORT}/tcp
        sudo firewall-cmd --reload
    fi
fi

if [ "$DIST_NAME" = "ol" ]; then
    yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
    systemctl status amazon-ssm-agent
    sed -i "s/#Port\s22/Port ${SSH_PORT}/" /etc/ssh/sshd_config
    yum -y install policycoreutils-python-utils
    semanage port -a -t ssh_port_t -p tcp ${SSH_PORT}
    sleep 60
    systemctl restart sshd.service
    firewall-offline-cmd --add-port=${SSH_PORT}/tcp
    firewall-cmd --reload
fi

if [ "$DIST_NAME" = "ubuntu" ] || [ "$DIST_NAME" = "debian" ]; then
    perl -pi -e "s/^#?Port 22$/Port ${SSH_PORT}/" /etc/ssh/sshd_config
    if [ "$DIST_VER" = "24" ]; then
        perl -pi -e "s/^#?ListenStream=22$/ListenStream=${SSH_PORT}/" /etc/systemd/system/sockets.target.wants/ssh.socket
        systemctl daemon-reload
        systemctl restart sshd || systemctl restart ssh
    else
        service sshd restart || service ssh restart
    fi
fi

if [ "$DIST_NAME" = "darwin" ]; then
    sed -i '' "s/ 22\/tcp/ ${SSH_PORT}\/tcp/" /etc/services
    sed -i '' "s/ 22\/udp/ ${SSH_PORT}\/tcp/" /etc/services
    launchctl unload /System/Library/LaunchDaemons/ssh.plist
    launchctl load -w /System/Library/LaunchDaemons/ssh.plist
fi
