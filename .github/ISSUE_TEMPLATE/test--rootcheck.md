---
name: 'Test: Rootcheck'
about: Test suite for Rootcheck
title: ''
labels: ''
assignees: ''

---

# Testing: Rootcheck

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Rootkit

### CentOS 7

- [ ] Check running processes
  - To **hide a process** in order to trigger rootcheck, we are using [Diamorphine rootkit](https://github.com/wazuh/Diamorphine/)
  - Install process is simple and its included on Diamorphine github.

   - *Maybe the makefile is not able to find the right kernel path to compile diamorphine against it. It can be fixed using this sentence:*
      - RPM:
`sudo yum install "kernel-devel-uname-r == $(uname -r)"`
      - DEB:
`apt-get install linux-headers-$(uname -r)`

   - Then, **we can hide process using signaling** `kill -31 <PID>`. To unhide process just enter the same sentence again. It has to **generate an alert** if rootcheck is working properly.


- [ ] Check hidden ports

- [ ] Check unusual files and permissions
   - Check this feature by **creating a hidden file** on "bin", "sbin", "usr/bin",
"usr/sbin", "dev", "lib"..:

		`cd /bin ; touch .hidden ; mkdir hiddenFiles ; touch .hidden2`


- [ ] Check hidden files using system calls
  - To test the module that performs system calls we install  [**Reptile rootkit**](https://github.com/f0rb1dd3n/Reptile); The installation itself triggers alerts.
- [ ] Scan the /dev directory
   - **Creating files** to trigger rootcheck:

		`cd /dev ; touch .hidden ; mkdir hiddenFiles ; touch .hidden2`
- [ ] Scan network interfaces
    - **Enabling promiscous mode** on some interface is enough to trigger rootcheck

		 `ip link set [interface] promisc on`
- [ ] Rootkit checks (rootkit_files.txt, rootkit_trojans.txt, win_malware_rcl.txt

  - **Creating a file** named as some that appears on rootkit data base.

     `cd /bin ; touch .t0rn ; mkdir rootkitFiles ; cd rootkitFiles ; touch .shit`

### Ubuntu 16

- [ ] Check running processes
- [ ] Check hidden ports
- [ ] Check unusual files and permissions
- [ ] Check hidden files using system calls
- [ ] Scan the /dev directory
- [ ] Scan network interfaces
- [ ] Rootkit checks (rootkit_files.txt, rootkit_trojans.txt, win_malware_rcl.txt


## Policy Monitoring

### Windows 10

- [ ] Check Windows audit
- [ ] Check Windows malware
- [ ] Check Windows application

### CentOS 5
- [ ] Check Unix audit, system_audit_rcl.txt, system_audit_ssh.txt, cis_rhel5_linux_rcl.txt
  - Disabling every rootcheck module except unixaudit is useful to make alerts more readable.
	`<check_unixaudit>yes</check_unixaudit>`

   - Including desired audit files(CentOS5 on this example):
```
    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/system_audit_ssh.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_rhel5_linux_rcl.txt</system_audit>
```

### CentOS 6
- [ ] Check Unix audit, system_audit_rcl.txt, system_audit_ssh.txt, cis_rhel6_linux_rcl.txt
- [ ] Check Unix audit , cis_rhel_linux_rcl.txt

### CentOS 7
- [ ] Check Unix audit, system_audit_rcl.txt, system_audit_ssh.txt, cis_rhel7_linux_rcl.txt
- [ ] Check Unix audit , cis_rhel_linux_rcl.txt

### Ubuntu 16
- [ ] Check Unix audit, system_audit_rcl.txt, system_audit_ssh.txt, cis_debian_linux_rcl.txt

### Suse 11

- [ ] Check Unix audit, system_audit_rcl.txt, system_audit_ssh.txt, cis_sles11_linux_rcl.txt

### Suse 12

- [ ] Check Unix audit, system_audit_rcl.txt, system_audit_ssh.txt, cis_sles12_linux_rcl.txt
