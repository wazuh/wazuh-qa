---
name: 'Test: File integrity monitoring'
about: Test suite for file integrity monitoring.
title: ''
labels: ''
assignees: ''

---

# Test file integrity monitoring

## Linux

Compile with flag DEBUGAD=1:
>`make TARGET=[server|agent] DEBUG=1 DEBUGAD=1 -j8`

With the flag DEBUGAD we can see the content of the databases information in the agent.
We had two structures:

|structure|key|data|
|----|----|----|
|red&black tree|path|fim_entry_data|
|inode/dev hash table|inode:device|path|

```c
typedef struct fim_entry_data {
    // Checksum attributes
    unsigned int size;
    char * perm;
    char * attributes;
    char * uid;
    char * gid;
    char * user_name;
    char * group_name;
    unsigned int mtime;
    unsigned long int inode;
    os_md5 hash_md5;
    os_sha1 hash_sha1;
    os_sha256 hash_sha256;
    // Options
    fim_event_mode mode;
    time_t last_event;
    const char * entry_type;
    unsigned long int dev;
    unsigned int scanned;
    int options;
    os_sha1 checksum;
} fim_entry_data;
```

Configure in local_internal_options.conf:
>`syscheck.debug=2`

During the test, check `ossec.log` looking for debug, error or warning messages that may be unnecessarily repetitive or useless.

### FIM start:
- [ ] FIM should not report any alerts until the first scan has finished and generated a base line.
- [ ] After the first scan, FIM should synchronize the database with the manager's. The number of entries in both databases must be the same and with the same elements.
    `wdb 002 "select count(*) from fim_entry" "count(*)": 3372`
    `DEBUG: (6335):Fim entries: 3372`
- [ ] Check disable option, set to no, shouldn't show any message about performing scans.
- [ ] Check that if the number of inodes is different from the number of entries, then, the sum of all paths in the inode table is equal to the number of entries.
    `DEBUG: (6336): Fim inode entries: 3342, path count: 3372`
    `DEBUG: (6335): Fim entries: 3372`

### Configure file and directory in scheduled mode.
```xml
<directories>/test, /testfile/file</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] File alerts added.
- [ ] Modified file alerts.
- [ ] Deleted file alerts.
```xml
<directories check_all="no" check_size="yes">/testsize</directories>
<directories check_all="no" check_perm="yes">/testperm</directories>
<directories check_all="no" check_owner="yes">/testowner</directories>
<directories check_all="no" check_group="yes">/testgroup</directories>
<directories check_all="no" check_mtime="yes">/testmtime</directories>
<directories check_all="no" check_inode="yes">/testinode</directories>
<directories check_all="no" check_md5sum="yes">/testmd5sum</directories>
<directories check_all="no" check_sha1sum="yes">/testsha1sum</directories>
<directories check_all="no" check_sha256sum="yes">/testsha256sum</directories>
<directories check_all="no" check_attrs="yes">/testattrs</directories>
<directories check_all="yes" report_changes="yes">/testseechanges</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] Check option check_size for file and directory (added, modified and deleted alerts).
- [ ] Check option check_perm for file and directory (added, modified and deleted alerts).
- [ ] Check option check_owner for file and directory (added, modified and deleted alerts).
- [ ] Check option check_group for file and directory (added, modified and deleted alerts).
- [ ] Check option check_mtime for file and directory (added, modified and deleted alerts).
- [ ] Check option check_inode for file and directory (added, modified and deleted alerts).
- [ ] Check option check_md5sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha1sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha256sum for file and directory (added, modified and deleted alerts).
- [ ] Check option report_changes for file and directory (added, modified and deleted alerts).

### Configure file and directory in real-time mode.
```xml
<directories realtime="yes">/testrealtime, /testrealtimefile/file</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] File alerts added.
- [ ] Modified file alerts.
- [ ] Deleted file alerts.
```xml
<directories check_all="no" realtime="yes" check_size="yes">/testsize</directories>
<directories check_all="no" realtime="yes" check_perm="yes">/testperm</directories>
<directories check_all="no" realtime="yes" check_owner="yes">/testowner</directories>
<directories check_all="no" realtime="yes" check_group="yes">/testgroup</directories>
<directories check_all="no" realtime="yes" check_mtime="yes">/testmtime</directories>
<directories check_all="no" realtime="yes" check_inode="yes">/testinode</directories>
<directories check_all="no" realtime="yes" check_md5sum="yes">/testmd5sum</directories>
<directories check_all="no" realtime="yes" check_sha1sum="yes">/testsha1sum</directories>
<directories check_all="no" realtime="yes" check_sha256sum="yes">/testsha256sum</directories>
<directories check_all="no" realtime="yes" check_attrs="yes">/testattrs</directories>
<directories check_all="yes" realtime="yes" report_changes="yes">/testseechanges</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] Check option check_size for file and directory (added, modified and deleted alerts):
- [ ] Check option check_perm for file and directory (added, modified and deleted alerts):
- [ ] Check option check_owner for file and directory (added, modified and deleted alerts):
- [ ] Check option check_group for file and directory (added, modified and deleted alerts):
- [ ] Check option check_mtime for file and directory (added, modified and deleted alerts):
- [ ] Check option check_inode for file and directory (added, modified and deleted alerts):
- [ ] Check option check_md5sum for file and directory (added, modified and deleted alerts):
- [ ] Check option check_sha1sum for file and directory (added, modified and deleted alerts):
- [ ] Check option check_sha256sum for file and directory (added, modified and deleted alerts):
- [ ] Check option report_changes for file and directory (added, modified and deleted alerts):

### Configure file and directory in whodata mode.
```xml
<directories whodata="yes">/testwhodata, /testwhodatafile/file</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] File alerts added.
- [ ] Modified file alerts.
- [ ] Deleted file alerts.
```xml
<directories check_all="no" whodata="yes" check_size="yes">/testsize, /testfilesize/file</directories>
<directories check_all="no" whodata="yes" check_perm="yes">/testperm, /testpermfile/file</directories>
<directories check_all="no" whodata="yes" check_owner="yes">/testowner, /testownerfile/file</directories>
<directories check_all="no" whodata="yes" check_group="yes">/testgroup, /testgroupfile/file</directories>
<directories check_all="no" whodata="yes" check_mtime="yes">/testmtime, /testmtimefile/file</directories>
<directories check_all="no" whodata="yes" check_inode="yes">/testinode, /testinodefile/file</directories>
<directories check_all="no" whodata="yes" check_md5sum="yes">/testmd5sum, /testmd5sumfile/file</directories>
<directories check_all="no" whodata="yes" check_sha1sum="yes">/testsha1sum, /testsha1sumfile/file</directories>
<directories check_all="no" whodata="yes" check_sha256sum="yes">/testsha256sum, /testsha256sumfile/file</directories>
<directories check_all="no" whodata="yes" check_attrs="yes">/testattrs, /testattrsfile/file</directories>
<directories check_all="yes" whodata="yes" report_changes="yes">/testseechanges, /testseechangesfile/file</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] Check option check_size for file and directory (added, modified and deleted alerts).
- [ ] Check option check_perm for file and directory (added, modified and deleted alerts).
- [ ] Check option check_owner for file and directory (added, modified and deleted alerts).
- [ ] Check option check_group for file and directory (added, modified and deleted alerts).
- [ ] Check option check_mtime for file and directory (added, modified and deleted alerts).
- [ ] Check option check_inode for file and directory (added, modified and deleted alerts).
- [ ] Check option check_md5sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha1sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha256sum for file and directory (added, modified and deleted alerts).
- [ ] Check option report_changes for file and directory (added, modified and deleted alerts).
- [ ] Check that modification of the file pointed by the monitored link dont generate any alert.
- [ ] Check audit rules added (auditctl -l).
- [ ] Check audit rules removed (auditctl -l).
- [ ] Remove audit rule manually and check if the rule is reloaded. (Auto-reload each 30 seconds).
- [ ] Remove rules 5 times and check if whodata stops and realtime is started. (Check alert).
- [ ] Remove monitored folder and check if the rule is removed and re-add the folder. The rule must be re-added.
- [ ] Add blocking rule in audit and check whodata logs and alert. (auditctl -a never,task).
- [ ] Restart auditd. Check whodata connection retries.
- [ ] Stop auditd. Move to realtime.
- [ ] Check if whodata changes to realtime if auditd is disabled while wazuh is running.
- [ ] Check that `realtime` works if `whodata` is used in the configuration without auditd installed.
- [ ] Check that `realtime` works if `whodata` is used in the configuration with auditd disabled.

### Monitor links through a configured folder (the link itself).
- [ ] Check that the attributes of a link monitored through a configured folder are the attributes of the link itself (not the attributes of the file/folder that is pointed by the link).
- [ ] Check syscheck alert for adding a link to a file/folder.
- [ ] Check syscheck doesn't generate alerts if the pointed file is modified or if content is added to the pointed folder.
- [ ] Check syscheck generate modify alerts if the link changes the path where it points.
- [ ] Check syscheck doesn't generate alerts if the pointed file/folder is deleted.
- [ ] Check syscheck doesn't generate alerts if the pointed file/folder is restored (re-create the previous deleted file/folder.
- [ ] Check syscheck alert for deleting a link to a file/folder.

### Configure for monitoring a symbolic link in directories stanza.
Check links:
- [ ] Check syscheck add alerts in a monitored link that points to a folder.
- [ ] Check syscheck modify alerts in a monitored link that points to a folder.
- [ ] Check syscheck delete alerts in a monitored link that points to a folder.
- [ ] Check syscheck doesn't generate any alerts when changing the destination of the link to another folder.
- [ ] Check that, before symlink_checker passes the alerts are generated in the former folder (and not in the new one).
- [ ] Check that, after symlink_checker passes the alerts are generated in the new pointed folder (and not in the former one).
- [ ] Check syscheck delete alerts if the pointed folder is deleted (by the next scan) wether symlink_checker has been performed or not.
- [ ] Restore the previously deleted folder, check that no alerts are generated in the next scan (symlink_checker is not performed).
- [ ] Check that alerts are generated for that folder once symlink_checker is performed (next scan).
- [ ] Delete the monitored link, check that alerts are generated in the next scan (symlink_checker is not performed).
- [ ] Check that no alerts are generated for the previously pointed folder once symlink_checker is performed (next scan).
- [ ] Re-create the previously deleted link (monitored), no alerts should be generated in the pointed folder in the next scan (symlink_checker is not performed).
- [ ] Check that the folder generates alerts again once symlink_checker is performed (in the next scan).
- [ ] Change the destination of a monitored link to an already monitored folder. The alerts generated should remain the same as before making this operation (before symlink_checker is performed).
- [ ] Once symlink_checker is performed, check that no alerts are generated from the previously pointed folder and that the already monitored folder still generating alerts with its former options.
- [ ] Restore the link to point to the previous folder and wait for symlink_checker to be performed. Alerts should be generated in both folders as they were before.
- [ ] Change the destination of a link (that points to a folder) to a file. Modify both (before symlink_checker). Alerts should be generated from the folder and not from the file.
- [ ] Modify both again and check that this time alerts are generated from the file and not the folder.
- [ ] Perform the same operation but backward: change the destination of a monitored link from a file to a folder.

### Check ignore and restrict options:
- [ ] Configure ignore `<ignore>file</ignore>`
- [ ] Configure ignore sregex using '^' `<ignore type="sregex">^string</ignore>`
- [ ] Configure ignore sregex using '$' `<ignore type="sregex">string$</ignore>`
- [ ] Configure ignore sregex using '|' `<ignore type="sregex">string1|string2</ignore>`
- [ ] Configure ignore sregex using '!' `<ignore type="sregex">!string</ignore>`
- [ ] Configure restrict sregex using '^' `<directories restrict=" type="sregex">^string>/test</directories>`
- [ ] Configure restrict sregex using '$' `<directories restrict=" type="sregex">string$>/test</directories>`
- [ ] Configure restrict sregex using '|' `<directories restrict=" type="sregex">string1|string2>/test</directories>`
- [ ] Configure restrict sregex using '!' `<directories restrict=" type="sregex">!string>/test</directories>`

### Specifies if syscheck should scan the mounted filesystems, `/dev`, `/sys`, `/proc` directores.
- [ ] Configure `<skip_nfs>no</skip_nfs>`
- [ ] Configure `<skip_dev>no</skip_dev>`
- [ ] Configure `<skip_sys>no</skip_sys>`
- [ ] Configure `<skip_proc>no</skip_proc>`

### Check process priority and max_eps (performance) options:
- [ ] Configure `process_priority` option with different values and check the configured priority is set (with `top` or `htop` in Linux).
- [ ] Configure `max_eps` option.

### Centralized configuration and on-demand configuration
- [ ] Check that `<directories>` in `syscheck` configuration block are overwritten by a configuration specified in the centralized configuration (`agent.conf`) including entries with a trailing slash in a single comma-separated stanza.
- [ ] Check the `syscheck` on-demand configuration (agent configured with `agent.conf` file).

### Updates
- [ ] Check for false positives when an old manager is updated.
- [ ] Check for false positives when an old agent is updated.

### Others
- [ ] Configure the `/var/ossec` folder to be monitored `<directories>/var/ossec</directories>`
- [ ] Check nodiff option `<nodiff>/test/file</nodiff>`
- [ ] Check that back up files (created by `report_changes` option) are deleted wether the agent is restarted or a monitored file (with `report_changes`) is deleted.
- [ ] Check if ignore files and folders using tag <ignore> and restrict option (string or sregex) in both options.
- [ ] Check if delete content in `/var/ossec/queue/diff` when deleting any tag <directories report_changes="yes">
- [ ] Check if delete content in `/var/ossec/queue/diff` when report_changes option passed yes to no.
- [ ] Check that duplicate entries are ignored. Include entries with a trailing slash in a single comma-separated stanza.
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for moving a folder with a file in it
- [ ] Check syscheck alert for renaming a file
- [ ] Check that the add file alert does not contain modification information. To do this, create a file with content in the folder being monitored, delete it and add a new file with the name of the deleted file
- [ ] Check syscheck alert for renaming a folder
- [ ] Check syscheck alert for deleting a folder
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check syscheck alert for nested monitoring with <tags> option


## Windows

Compile with flag DEBUGAD=1:
>`make TARGET=[server|agent] DEBUG=1 DEBUGAD=1 -j8`

With the flag DEBUGAD we can see the content of the databases information in the agent.
We had two structures:

|structure|key|data|
|----|----|----|
|red&black tree|path|fim_entry_data|
|inode/dev hash table|inode:device|path|

```c
typedef struct fim_entry_data {
    // Checksum attributes
    unsigned int size;
    char * perm;
    char * attributes;
    char * uid;
    char * gid;
    char * user_name;
    char * group_name;
    unsigned int mtime;
    unsigned long int inode;
    os_md5 hash_md5;
    os_sha1 hash_sha1;
    os_sha256 hash_sha256;
    // Options
    fim_event_mode mode;
    time_t last_event;
    const char * entry_type;
    unsigned long int dev;
    unsigned int scanned;
    int options;
    os_sha1 checksum;
} fim_entry_data;
```

Configure in local_internal_options.conf:
>`syscheck.debug=2`

During the test, check `ossec.log` looking for debug, error or warning messages that may be unnecessarily repetitive or useless.

### FIM start:
- [ ] FIM should not report any alerts until the first scan has finished and generated a base line.
- [ ] After the first scan, FIM should synchronize the database with the manager's. The number of entries in both databases must be the same and with the same elements.
    `wdb 002 "select count(*) from fim_entry" "count(*)": 3372`
    `DEBUG: (6335):Fim entries: 3372`
- [ ] Check disable option, set to no, shouldn't show any message about performing scans.
- [ ] Check that if the number of inodes is different from the number of entries, then, the sum of all paths in the inode table is equal to the number of entries.
    `DEBUG: (6336): Fim inode entries: 3342, path count: 3372`
    `DEBUG: (6335): Fim entries: 3372`

### Configure file and directory in scheduled mode.
```xml
<directories>/test, /testfile/file</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] File alerts added.
- [ ] Modified file alerts.
- [ ] Deleted file alerts.
```xml
<directories check_all="no" check_size="yes">/testsize</directories>
<directories check_all="no" check_perm="yes">/testperm</directories>
<directories check_all="no" check_owner="yes">/testowner</directories>
<directories check_all="no" check_group="yes">/testgroup</directories>
<directories check_all="no" check_mtime="yes">/testmtime</directories>
<directories check_all="no" check_inode="yes">/testinode</directories>
<directories check_all="no" check_md5sum="yes">/testmd5sum</directories>
<directories check_all="no" check_sha1sum="yes">/testsha1sum</directories>
<directories check_all="no" check_sha256sum="yes">/testsha256sum</directories>
<directories check_all="no" check_attrs="yes">/testattrs</directories>
<directories check_all="yes" report_changes="yes">/testseechanges</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] Check option check_size for file and directory (added, modified and deleted alerts).
- [ ] Check option check_perm for file and directory (added, modified and deleted alerts).
- [ ] Check option check_owner for file and directory (added, modified and deleted alerts).
- [ ] Check option check_group for file and directory (added and deleted alerts).
- [ ] Check option check_mtime for file and directory (added, modified and deleted alerts).
- [ ] Check option check_inode for file and directory (added and deleted alerts).
- [ ] Check option check_md5sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha1sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha256sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_attrs for file and directory (added, modified and deleted alerts).
- [ ] Check option report_changes for file and directory (added, modified and deleted alerts).

### Configure file and directory in real-time mode.
```xml
<directories realtime="yes">/testrealtime, /testrealtimefile/file</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] File alerts added.
- [ ] Modified file alerts.
- [ ] Deleted file alerts.
```xml
<directories check_all="no" realtime="yes" check_size="yes">/testsize</directories>
<directories check_all="no" realtime="yes" check_perm="yes">/testperm</directories>
<directories check_all="no" realtime="yes" check_owner="yes">/testowner</directories>
<directories check_all="no" realtime="yes" check_group="yes">/testgroup</directories>
<directories check_all="no" realtime="yes" check_mtime="yes">/testmtime</directories>
<directories check_all="no" realtime="yes" check_inode="yes">/testinode</directories>
<directories check_all="no" realtime="yes" check_md5sum="yes">/testmd5sum</directories>
<directories check_all="no" realtime="yes" check_sha1sum="yes">/testsha1sum</directories>
<directories check_all="no" realtime="yes" check_sha256sum="yes">/testsha256sum</directories>
<directories check_all="no" realtime="yes" check_attrs="yes">/testattrs</directories>
<directories check_all="yes" realtime="yes" report_changes="yes">/testseechanges</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] Check option check_size for file and directory (added, modified and deleted alerts).
- [ ] Check option check_perm for file and directory (added, modified and deleted alerts).
- [ ] Check option check_owner for file and directory (added, modified and deleted alerts).
- [ ] Check option check_group for file and directory (added and deleted alerts).
- [ ] Check option check_mtime for file and directory (added, modified and deleted alerts).
- [ ] Check option check_inode for file and directory (added and deleted alerts).
- [ ] Check option check_md5sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha1sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha256sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_attrs for file and directory (added, modified and deleted alerts).
- [ ] Check option report_changes for file and directory (added, modified and deleted alerts).

### Configure file and directory in whodata mode.
```xml
<directories whodata="yes">/testwhodata, /testwhodatafile/file</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] File alerts added.
- [ ] Modified file alerts.
- [ ] Deleted file alerts.
```xml
<directories check_all="no" whodata="yes" check_size="yes">/testsize, /testfilesize/file</directories>
<directories check_all="no" whodata="yes" check_perm="yes">/testperm, /testpermfile/file</directories>
<directories check_all="no" whodata="yes" check_owner="yes">/testowner, /testownerfile/file</directories>
<directories check_all="no" whodata="yes" check_group="yes">/testgroup, /testgroupfile/file</directories>
<directories check_all="no" whodata="yes" check_mtime="yes">/testmtime, /testmtimefile/file</directories>
<directories check_all="no" whodata="yes" check_inode="yes">/testinode, /testinodefile/file</directories>
<directories check_all="no" whodata="yes" check_md5sum="yes">/testmd5sum, /testmd5sumfile/file</directories>
<directories check_all="no" whodata="yes" check_sha1sum="yes">/testsha1sum, /testsha1sumfile/file</directories>
<directories check_all="no" whodata="yes" check_sha256sum="yes">/testsha256sum, /testsha256sumfile/file</directories>
<directories check_all="no" whodata="yes" check_attrs="yes">/testattrs, /testattrsfile/file</directories>
<directories check_all="yes" whodata="yes" report_changes="yes">/testseechanges, /testseechangesfile/file</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] Check option check_size for file and directory (added, modified and deleted alerts).
- [ ] Check option check_perm for file and directory (added, modified and deleted alerts).
- [ ] Check option check_owner for file and directory (added, modified and deleted alerts).
- [ ] Check option check_group for file and directory (added and deleted alerts).
- [ ] Check option check_mtime for file and directory (added, modified and deleted alerts).
- [ ] Check option check_inode for file and directory (added and deleted alerts).
- [ ] Check option check_md5sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha1sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha256sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_attrs for file and directory (added, modified and deleted alerts).
- [ ] Check option report_changes for file and directory (added, modified and deleted alerts).
- [ ] Check that the audit policies are restored when Wazuh stops.
- [ ] Check that if an user modify a folder audit policies, making them incompatibles with Whodata, they are not restored when Wazuh stops.
- [ ] Check that if an user modify a folder audit policies, making them incompatibles with Whodata, the folder is starts to be monitored in realtime.
- [ ] Check that if a monitored folder is removed, it continues to be monitored when it reappears.
- [ ] Verify that whodata does not block files. https://github.com/wazuh/wazuh/pull/3872

### Check ignore and restrict options:
- [ ] Configure ignore `<ignore>file</ignore>`
- [ ] Configure ignore sregex using '^' `<ignore type="sregex">^string</ignore>`
- [ ] Configure ignore sregex using '$' `<ignore type="sregex">string$</ignore>`
- [ ] Configure ignore sregex using '|' `<ignore type="sregex">string1|string2</ignore>`
- [ ] Configure ignore sregex using '!' `<ignore type="sregex">!string</ignore>`
- [ ] Configure restrict sregex using '^' `<directories restrict=" type="sregex">^string>/test</directories>`
- [ ] Configure restrict sregex using '$' `<directories restrict=" type="sregex">string$>/test</directories>`
- [ ] Configure restrict sregex using '|' `<directories restrict=" type="sregex">string1|string2>/test</directories>`
- [ ] Configure restrict sregex using '!' `<directories restrict=" type="sregex">!string>/test</directories>`

### Configure directories with strange characteres
- [ ] Configure paths with backslashes `<directories>C:\test</directories>`
- [ ] Configure paths with regular slashes `<directories>C:/test</directories>`
- [ ] Configure paths with mixed regular and backslashes in it `<directories>C:\folder/test</directories>`
- [ ] Configure paths with a driver letter different from `C:`, for example `<directories>F:</directories>`

### Check <windows_registry> option

```xml
<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\batfile</windows_registry>
<windows_registry arch="both">HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION</windows_registry>
```
- [ ] Check syscheck alert for monitoring windows registry.
- [ ] Check syscheck alert for adding a registry.
- [ ] Check syscheck alert for modifying a registry.
- [ ] Check syscheck alert for delete a registry.
- [ ] Check syscheck alert with "arch" option (32, 64 and both).
- [ ] Check that no double alerts when using "arch=both" option.

### Check process priority and max_eps (performance) options:
- [ ] Configure `process_priority` option with different values and check the configured priority is set (with `top` or `htop` in Linux).
- [ ] Configure `max_eps` option.

### Centralized configuration and on-demand configuration
- [ ] Check that `<directories>` in `syscheck` configuration block are overwritten by a configuration specified in the centralized configuration (`agent.conf`) including entries with a trailing slash in a single comma-separated stanza.
- [ ] Check the `syscheck` on-demand configuration (agent configured with `agent.conf` file).

### Updates
- [ ] Check for false positives when an old manager is updated.
- [ ] Check for false positives when an old agent is updated.

### Others
- [ ] Configure the `/var/ossec` folder to be monitored `<directories>/var/ossec</directories>`
- [ ] Check nodiff option `<nodiff>/test/file</nodiff>`
- [ ] Check that back up files (created by `report_changes` option) are deleted wether the agent is restarted or a monitored file (with `report_changes`) is deleted.
- [ ] Check if ignore files and folders using tag <ignore> and restrict option (string or sregex) in both options.
- [ ] Check if delete content in `C:\Program Files (x86)\ossec-agent\queue\diff\local\c` when deleting any tag <directories report_changes="yes">
- [ ] Check if delete content in `C:\Program Files (x86)\ossec-agent\queue\diff\local\c` when report_changes option passed yes to no.
- [ ] Check that duplicate entries are ignored. Include entries with a trailing slash in a single comma-separated stanza.
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for moving a folder with a file in it
- [ ] Check syscheck alert for renaming a file
- [ ] Check that the add file alert does not contain modification information. To do this, create a file with content in the folder being monitored, delete it and add a new file with the name of the deleted file
- [ ] Check syscheck alert for renaming a folder
- [ ] Check syscheck alert for deleting a folder
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check syscheck alert for nested monitoring with <tags> option


## MacOS

Compile with flag DEBUGAD=1:
>`make TARGET=[server|agent] DEBUG=1 DEBUGAD=1 -j8`

With the flag DEBUGAD we can see the content of the databases information in the agent.
We had two structures:

|structure|key|data|
|----|----|----|
|red&black tree|path|fim_entry_data|
|inode/dev hash table|inode:device|path|

```c
typedef struct fim_entry_data {
    // Checksum attributes
    unsigned int size;
    char * perm;
    char * attributes;
    char * uid;
    char * gid;
    char * user_name;
    char * group_name;
    unsigned int mtime;
    unsigned long int inode;
    os_md5 hash_md5;
    os_sha1 hash_sha1;
    os_sha256 hash_sha256;
    // Options
    fim_event_mode mode;
    time_t last_event;
    const char * entry_type;
    unsigned long int dev;
    unsigned int scanned;
    int options;
    os_sha1 checksum;
} fim_entry_data;
```

Configure in local_internal_options.conf:
>`syscheck.debug=2`

During the test, check `ossec.log` looking for debug, error or warning messages that may be unnecessarily repetitive or useless.

### FIM start:
- [ ] FIM should not report any alerts until the first scan has finished and generated a base line.
- [ ] After the first scan, FIM should synchronize the database with the manager's. The number of entries in both databases must be the same and with the same elements.
- [ ] Check disable option, set to no, shouldn't show any message about performing scans.
    `wdb 002 "select count(*) from fim_entry" "count(*)": 3372`
    `DEBUG: (6335):Fim entries: 3372`
- [ ] Check that if the number of inodes is different from the number of entries, then, the sum of all paths in the inode table is equal to the number of entries.
    `DEBUG: (6336): Fim inode entries: 3342, path count: 3372`
    `DEBUG: (6335): Fim entries: 3372`

### Configure file and directory in scheduled mode.
```xml
<directories>/test, /testfile/file</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] File alerts added.
- [ ] Modified file alerts.
- [ ] Deleted file alerts.
```xml
<directories check_all="no" check_size="yes">/testsize</directories>
<directories check_all="no" check_perm="yes">/testperm</directories>
<directories check_all="no" check_owner="yes">/testowner</directories>
<directories check_all="no" check_group="yes">/testgroup</directories>
<directories check_all="no" check_mtime="yes">/testmtime</directories>
<directories check_all="no" check_inode="yes">/testinode</directories>
<directories check_all="no" check_md5sum="yes">/testmd5sum</directories>
<directories check_all="no" check_sha1sum="yes">/testsha1sum</directories>
<directories check_all="no" check_sha256sum="yes">/testsha256sum</directories>
<directories check_all="no" check_attrs="yes">/testattrs</directories>
<directories check_all="yes" report_changes="yes">/testseechanges</directories>
```
Check FIM alerts ADD, DELETE, MODIFICATION
- [ ] Check option check_size for file and directory (added, modified and deleted alerts).
- [ ] Check option check_perm for file and directory (added, modified and deleted alerts).
- [ ] Check option check_owner for file and directory (added, modified and deleted alerts).
- [ ] Check option check_group for file and directory (added, modified and deleted alerts).
- [ ] Check option check_mtime for file and directory (added, modified and deleted alerts).
- [ ] Check option check_inode for file and directory (added, modified and deleted alerts).
- [ ] Check option check_md5sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha1sum for file and directory (added, modified and deleted alerts).
- [ ] Check option check_sha256sum for file and directory (added, modified and deleted alerts).
- [ ] Check option report_changes for file and directory (added, modified and deleted alerts).

### Configure for monitoring a symbolic link in directories stanza.
Check links:
- [ ] Check syscheck alert for adding a link to a file/folder.
- [ ] Check syscheck doesn't generate alerts if the pointed file is modified or if content is added to the pointed folder.
- [ ] Check syscheck generate modify alerts if the link changes the path where it points.
- [ ] Check syscheck doesn't generate alerts if the pointed file/folder is deleted.
- [ ] Check syscheck doesn't generate alerts if the pointed file/folder is restored (re-create the previous deleted file/folder.
- [ ] Check syscheck alert for deleting a link to a file/folder.
- [ ] Check syscheck add alerts in a monitored link that points to a folder.
- [ ] Check syscheck modify alerts in a monitored link that points to a folder.
- [ ] Check syscheck delete alerts in a monitored link that points to a folder.
- [ ] Check syscheck doesn't generate any alerts when changing the destination of the link to another folder.
- [ ] Check that, before symlink_checker passes the alerts are generated in the former folder (and not in the new one).
- [ ] Check that, after symlink_checker passes the alerts are generated in the new pointed folder (and not in the former one).
- [ ] Check syscheck delete alerts if the pointed folder is deleted (by the next scan) wether symlink_checker has been performed or not.
- [ ] Restore the previously deleted folder, check that no alerts are generated in the next scan (symlink_checker is not performed).
- [ ] Check that alerts are generated for that folder once symlink_checker is performed (next scan).
- [ ] Delete the monitored link, check that alerts are generated in the next scan (symlink_checker is not performed).
- [ ] Check that no alerts are generated for the previously pointed folder once symlink_checker is performed (next scan).
- [ ] Re-create the previously deleted link (monitored), no alerts should be generated in the pointed folder in the next scan (symlink_checker is not performed).
- [ ] Check that the folder generates alerts again once symlink_checker is performed (in the next scan).
- [ ] Change the destination of a monitored link to an already monitored folder. The alerts generated should remain the same as before making this operation (before symlink_checker is performed).
- [ ] Once symlink_checker is performed, check that no alerts are generated from the previously pointed folder and that the already monitored folder still generating alerts with its former options.
- [ ] Restore the link to point to the previous folder and wait for symlink_checker to be performed. Alerts should be generated in both folders as they were before.
- [ ] Change the destination of a link (that points to a folder) to a file. Modify both (before symlink_checker). Alerts should be generated from the folder and not from the file.
- [ ] Modify both again and check that this time alerts are generated from the file and not the folder.
- [ ] Perform the same operation but backward: change the destination of a monitored link from a file to a folder.

### Check ignore and restrict options:
- [ ] Configure ignore `<ignore>file</ignore>`
- [ ] Configure ignore sregex using '^' `<ignore type="sregex">^string</ignore>`
- [ ] Configure ignore sregex using '$' `<ignore type="sregex">string$</ignore>`
- [ ] Configure ignore sregex using '|' `<ignore type="sregex">string1|string2</ignore>`
- [ ] Configure ignore sregex using '!' `<ignore type="sregex">!string</ignore>`
- [ ] Configure restrict sregex using '^' `<directories restrict=" type="sregex">^string>/test</directories>`
- [ ] Configure restrict sregex using '$' `<directories restrict=" type="sregex">string$>/test</directories>`
- [ ] Configure restrict sregex using '|' `<directories restrict=" type="sregex">string1|string2>/test</directories>`
- [ ] Configure restrict sregex using '!' `<directories restrict=" type="sregex">!string>/test</directories>`

### Specifies if syscheck should scan the mounted filesystems, `/dev`, `/sys`, `/proc` directores.
- [ ] Configure `<skip_nfs>no</skip_nfs>`
- [ ] Configure `<skip_dev>no</skip_dev>`
- [ ] Configure `<skip_sys>no</skip_sys>`
- [ ] Configure `<skip_proc>no</skip_proc>`

### Check process priority and max_eps (performance) options:
- [ ] Configure `process_priority` option with different values and check the configured priority is set (with `top` or `htop` in Linux).
- [ ] Configure `max_eps` option.

### Centralized configuration and on-demand configuration
- [ ] Check that `<directories>` in `syscheck` configuration block are overwritten by a configuration specified in the centralized configuration (`agent.conf`) including entries with a trailing slash in a single comma-separated stanza.
- [ ] Check the `syscheck` on-demand configuration (agent configured with `agent.conf` file).

### Updates
- [ ] Check for false positives when an old manager (3.6 or less) is updated.
- [ ] Check for false positives when an old agent is updated.

### Others
- [ ] Configure the `/var/ossec` folder to be monitored `<directories>/var/ossec</directories>`
- [ ] Check nodiff option `<nodiff>/test/file</nodiff>`
- [ ] Check that back up files (created by `report_changes` option) are deleted wether the agent is restarted or a monitored file (with `report_changes`) is deleted.
- [ ] Check if ignore files and folders using tag <ignore> and restrict option (string or sregex) in both options.
- [ ] Check if delete content in `/var/ossec/queue/diff` when deleting any tag <directories report_changes="yes">
- [ ] Check if delete content in `/var/ossec/queue/diff` when report_changes option passed yes to no.
- [ ] Check that duplicate entries are ignored. Include entries with a trailing slash in a single comma-separated stanza.
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for moving a folder with a file in it
- [ ] Check syscheck alert for renaming a file
- [ ] Check that the add file alert does not contain modification information. To do this, create a file with content in the folder being monitored, delete it and add a new file with the name of the deleted file
- [ ] Check syscheck alert for renaming a folder
- [ ] Check syscheck alert for deleting a folder
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check syscheck alert for nested monitoring with <tags> option


## Opened issues:
### General
- [ ] Daylight saving induced false positives: https://github.com/wazuh/wazuh/issues/4167
- [ ] Syscheck frequency values under 10 seconds behaviour: https://github.com/wazuh/wazuh/issues/4003
- [ ] Information message number 6022 can flood the Windows agent log file: https://github.com/wazuh/wazuh/issues/3998
- [ ] Simple and sregex syscheck <registry_ignore> stanzas are incompatible: https://github.com/wazuh/wazuh/issues/3990 (When combining <registry_ignore> and <registry_ignore type="sregex"> stanzas, only the non-sregex ones will be taken into account at the registry ignore process.)
- [ ] Different behavior in configuration while monitoring a drive in whodata and realtime: https://github.com/wazuh/wazuh/issues/3934
- [ ] Failure to monitor directories in real-time when configuring Windows audit policies: https://github.com/wazuh/wazuh/issues/3812
- [ ] Realtime syscheck alerts are not queued if agent is offline: https://github.com/wazuh/wazuh/issues/3811
- [ ] Too generic error when adding an inotify watcher: https://github.com/wazuh/wazuh/issues/3770
- [ ] Receive alert of realtime instead of whodata: https://github.com/wazuh/wazuh/issues/3733
- [ ] Incompatible field types in Kibana: https://github.com/wazuh/wazuh/issues/3171
- [ ] Real time events moving files or directories: https://github.com/wazuh/wazuh/issues/2863
- [ ] Realtime syscheck scan doesn't start: https://github.com/wazuh/wazuh/issues/2798
- [ ] FIM full_log field is being truncated : https://github.com/wazuh/wazuh/issues/2632
- [ ] Add timezone option for syscheck <scan_time>: https://github.com/wazuh/wazuh/issues/2555
- [ ] Executing whodata with inmutable audit configuration: https://github.com/wazuh/wazuh/issues/2432
- [ ] FIM DB synchronization between managers: https://github.com/wazuh/wazuh/issues/2404
- [ ] Syscheck is not attaching the timestamp of a deleted file event when having realtime enabled: https://github.com/wazuh/wazuh/issues/2397
- [ ] Sregex is not useful in restrict option: https://github.com/wazuh/wazuh/issues/2064
- [ ] Whodata for auditd logs: https://github.com/wazuh/wazuh/issues/2042
- [ ] FIM output inconsistency: https://github.com/wazuh/wazuh/issues/2005
- [ ] False positives about new files in FIM: https://github.com/wazuh/wazuh/issues/1881
- [ ] Error with real-time + NFS: https://github.com/wazuh/wazuh/issues/1269
- [ ] Filtering by event type: https://github.com/wazuh/wazuh/issues/1247
### Linux:
- [ ] Syscheck directories tag doesn't recognize directory / it needs /.: https://github.com/wazuh/wazuh/issues/3705
- [ ] FIM is not able to parse some symbols in a Windows Agent: https://github.com/wazuh/wazuh/issues/3310
- [ ] Syscheck hangs analyzing /dev/core: https://github.com/wazuh/wazuh/issues/3007
- [ ] FIM keeps alerting after removing a symbolic link: https://github.com/wazuh/wazuh/issues/2433
- [ ] Ignore option for Syscheck makes global ignores on the manager: https://github.com/wazuh/wazuh/issues/2378
- [ ] Syscheck in realtime doesn't detect changes in hardlinks: https://github.com/wazuh/wazuh/issues/2355
### Windows:
- [ ] Unexpected behavior with links to System32 and SysWOW64 in Syscheck: https://github.com/wazuh/wazuh/issues/3739
- [ ] Wrong ownership value in Windows agent: https://github.com/wazuh/wazuh/issues/2220
- [ ] FIM alerts of Windows Registry keys with empty-string MD5: https://github.com/wazuh/wazuh/issues/858

**FIM rework:**
- https://github.com/wazuh/wazuh/issues/3073 
- https://github.com/wazuh/wazuh/issues/3319
