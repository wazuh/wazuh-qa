#!/bin/bash

sysctl fs.suid_dumpable=0
sysctl kernel.randomize_va_space=2
sysctl net.ipv4.conf.all.accept_redirects=0
sysctl net.ipv4.conf.all.accept_source_route=0
sysctl net.ipv4.conf.all.log_martians=1
sysctl net.ipv4.conf.all.rp_filter=1
sysctl net.ipv4.conf.all.secure_redirects=0
sysctl net.ipv4.conf.all.send_redirects=0
sysctl net.ipv4.conf.default.accept_redirects=0
sysctl net.ipv4.conf.default.accept_source_route=0
sysctl net.ipv4.conf.default.log_martians=1
sysctl net.ipv4.conf.default.rp_filter=1
sysctl net.ipv4.conf.default.secure_redirects=0
sysctl net.ipv4.conf.default.send_redirects=0
sysctl net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl net.ipv4.tcp_syncookies=1
sysctl net.ipv4.ip_forward=0
sysctl net.ipv4.tcp_syncookies=1

echo "fs.suid_dumpable=0" >> /etc/sysctl.conf
echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects =    0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians=1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter =1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians= 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
echo "Protocol 2" >> /etc/ssh/sshd_config

