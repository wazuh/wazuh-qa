---
name: 'Test: Syscheck'
about: Test suite for Syscheck
title: ''
labels: ''
assignees: ''

---

# Testing: Syscheck

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Important

All tests must be run under Valgrind (Linux) or DrMemory (Windows), except for performance analyses.

## Any

- [ ] Check if ignore files and folders using tag <ignore> and restrict option (string or sregex) in both options.
- [ ] Check if delete content in _/var/ossec/queue/diff_ when deleting any tag <directories report_changes="yes">
- [ ] Check if delete content in _/var/ossec/queue/diff_ when report_changes option passed yes to no.
- [ ] Check that duplicate entries are ignored. Include entries with a trailing slash in a single comma-separated stanza.

## Frequency

### Linux

- [ ] Check syscheck alert for files that exist when starting the agent
- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert with report_changes option
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for moving a folder with a file in it
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for renaming a file
- [ ] Check that the add file alert does not contain modification information. To do this, create a file with content in the folder being monitored, delete it and add a new file with the name of the deleted file
- [ ] Check syscheck alert for renaming a folder
- [ ] Check syscheck alert for deleting a file
- [ ] Check syscheck alert for deleting a folder
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check values different values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check the "nodiff" option to don't show the changes of a file
- [ ] Check syscheck flag auto_ignore with attributes "frequency" and "timeframe" (1)
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check syscheck alert for nested monitoring with <tags> option
- [ ] Check syscheck alert for monitoring folder with <restrict> option
- [ ] Check syscheck alert for adding link to a file
- [ ] Check syscheck alert for modifying link
- [ ] Check syscheck alert for deleting a link
- [ ] Check that modification of the file pointed by the monitored link dont generate any alert.

#### Links
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

### Windows

- [ ] Check syscheck alert for files that exist when starting the agent
- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert for deleting text from a file
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for moving a folder with a file in it
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for renaming a file
- [ ] Check that the add file alert does not contain modification information. To do this, create a file with content in the folder being monitored, delete it and add a new file with the name of the deleted file
- [ ] Check syscheck alert for renaming a folder
- [ ] Check syscheck alert with report_changes option and `last-entry` files are stored compressed.
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check syscheck alert for changing attributes of a file
- [ ] Check values diferent values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check syscheck alert for deleting a file
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check syscheck alert for nested monitoring with <tags> option
- [ ] Check syscheck alert for monitoring folder with <restrict> option
- [ ] Check the "nodiff" option to don't show the changes of a file
- [ ] Check syscheck flag auto_ignore with attributes "frequency" and "timeframe" (1)
- [ ] Check syscheck alert for monitoring windows registry with <windows_registry> option
- [ ] Check syscheck alert for adding a registry with <windows_registry> option
- [ ] Check syscheck alert for modifying a registry with <windows_registry> option
- [ ] Check syscheck alert for delete a registry with <windows_registry> option
- [ ] Check syscheck alert with "arch" option (32, 64 and both)
- [ ] Check that no double alerts when using "arch=both" option


## Realtime

### Linux

- [ ] Check syscheck alert for files that exist when starting the agent
- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert with report_changes option
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for moving a folder with a file in it
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for renaming a file
- [ ] Check that the add file alert does not contain modification information. To do this, create a file with content in the folder being monitored, delete it and add a new file with the name of the deleted file
- [ ] Check syscheck alert for renaming a folder
- [ ] Check syscheck alert for deleting a file
- [ ] Check syscheck alert for deleting a folder
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check values different values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check the "nodiff" option to don't show the changes of a file
- [ ] Check syscheck flag auto_ignore with attributes "frequency" and "timeframe" (1)
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check syscheck alert for nested monitoring with <tags> option
- [ ] Check syscheck alert for monitoring folder with <restrict> option
- [ ] Check syscheck alert for adding link to a file
- [ ] Check syscheck alert for modifying link
- [ ] Check syscheck alert for deleting a link
- [ ] Check that modification of the file pointed by the monitored link dont generate any alert.

#### Links
- [ ] Check syscheck alert for adding link to a file/folder.
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
- [ ] Check syscheck delete alerts if the pointed folder is deleted wether symlink_checker has been performed or not.
- [ ] Restore the previously deleted folder, check that no alerts are generated (symlink_checker is not performed).
- [ ] Check that alerts are generated for that folder once symlink_checker is performed.
- [ ] Delete the monitored link, check that alerts are generated (symlink_checker is not performed).
- [ ] Check that no alerts are generated for the previously pointed folder once symlink_checker is performed.
- [ ] Re-create the previously deleted link (monitored), no alerts should be generated in the pointed folder(symlink_checker is not performed).
- [ ] Check that the folder generates alerts again once symlink_checker is performed.
- [ ] Change the destination of a monitored link to an already monitored folder. The alerts generated should remain the same as before making this operation (before symlink_checker is performed).
- [ ] Once symlink_checker is performed, check that no alerts are generated from the previously pointed folder and that the already monitored folder still generating alerts with its former options.
- [ ] Restore the link to point to the previous folder and wait for symlink_checker to be performed. Alerts should be generated in both folders as they were before.
- [ ] Change the destination of a link (that points to a folder) to a file. Modify both (before symlink_checker). Alerts should be generated from the folder and not from the file.
- [ ] Modify both again and check that this time alerts are generated from the file and not the folder.
- [ ] Perform the same operation but backward: change the destination of a monitored link from a file to a folder.

### Windows

- [ ] Check syscheck alert for files that exist when starting the agent
- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert for deleting text from a file
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for moving a folder with a file in it
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for renaming a file
- [ ] Check that the add file alert does not contain modification information. To do this, create a file with content in the folder being monitored, delete it and add a new file with the name of the deleted file
- [ ] Check syscheck alert for renaming a folder
- [ ] Check syscheck alert with report_changes option and `last-entry` files are stored compressed.
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check syscheck alert for changing attributes of a file
- [ ] Check values diferent values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check syscheck alert for deleting a file
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check syscheck alert for nested monitoring with <tags> option
- [ ] Check syscheck alert for monitoring folder with <restrict> option
- [ ] Check the "nodiff" option to don't show the changes of a file
- [ ] Check syscheck flag auto_ignore with attributes "frequency" and "timeframe" (1)


## Who-data

### Linux

- [ ] Check syscheck alert for files that exist when starting the agent
- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert with report_changes option
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for moving a folder with a file in it
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for renaming a file
- [ ] Check that the add file alert does not contain modification information. To do this, create a file with content in the folder being monitored, delete it and add a new file with the name of the deleted file
- [ ] Check syscheck alert for renaming a folder
- [ ] Check syscheck alert for deleting a file
- [ ] Check syscheck alert for deleting a folder
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check values different values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check the "nodiff" option to don't show the changes of a file
- [ ] Check syscheck flag auto_ignore with attributes "frequency" and "timeframe" (1)
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check syscheck alert for nested monitoring with <tags> option
- [ ] Check syscheck alert for monitoring folder with <restrict> option
- [ ] Check syscheck alert for adding link to a file
- [ ] Check syscheck alert for modifying link
- [ ] Check syscheck alert for deleting a link
- [ ] Check that modification of the file pointed by the monitored link dont generate any alert.
- [ ] Check audit rules added (auditctl -l)
- [ ] Check audit rules removed (auditctl -l)
- [ ] Remove audit rule manually and check if the rule is reloaded. (Auto-reload each 30 seconds)
- [ ] Remove rules 5 times and check if whodata stops and realtime is started. (Check alert)
- [ ] Remove monitored folder and check if the rule is removed and re-add the folder. The rule must be re-added.
- [ ] Add blocking rule in audit and check whodata logs and alert. (auditctl -a never,task)
- [ ] Restart auditd. Check whodata connection retries.
- [ ] Stop auditd. Move to realtime.
- [ ] Check if whodata changes to realtime if auditd is disabled while wazuh is running.
- [ ] Check that `realtime` works if `whodata` is used in the configuration without auditd installed.
- [ ] Check that `realtime` works if `whodata` is used in the configuration with auditd disabled.

#### Links
- [ ] Check syscheck alert for adding link to a file/folder.
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
- [ ] Check syscheck delete alerts if the pointed folder is deleted wether symlink_checker has been performed or not.
- [ ] Restore the previously deleted folder, check that no alerts are generated (symlink_checker is not performed).
- [ ] Check that alerts are generated for that folder once symlink_checker is performed.
- [ ] Delete the monitored link, check that alerts are generated (symlink_checker is not performed).
- [ ] Check that no alerts are generated for the previously pointed folder once symlink_checker is performed.
- [ ] Re-create the previously deleted link (monitored), no alerts should be generated in the pointed folder(symlink_checker is not performed).
- [ ] Check that the folder generates alerts again once symlink_checker is performed.
- [ ] Change the destination of a monitored link to an already monitored folder. The alerts generated should remain the same as before making this operation (before symlink_checker is performed).
- [ ] Once symlink_checker is performed, check that no alerts are generated from the previously pointed folder and that the already monitored folder still generating alerts with its former options.
- [ ] Restore the link to point to the previous folder and wait for symlink_checker to be performed. Alerts should be generated in both folders as they were before.
- [ ] Change the destination of a link (that points to a folder) to a file. Modify both (before symlink_checker). Alerts should be generated from the folder and not from the file.
- [ ] Modify both again and check that this time alerts are generated from the file and not the folder.
- [ ] Perform the same operation but backward: change the destination of a monitored link from a file to a folder.

### Windows

- [ ] Check syscheck alert for files that exist when starting the agent
- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert for deleting text from a file
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for moving a folder with a file in it
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for renaming a file
- [ ] Check that the add file alert does not contain modification information. To do this, create a file with content in the folder being monitored, delete it and add a new file with the name of the deleted file
- [ ] Check syscheck alert for renaming a folder
- [ ] Check syscheck alert with report_changes option and `last-entry` files are stored compressed.
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check syscheck alert for changing attributes of a file
- [ ] Check values diferent values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check syscheck alert for deleting a file
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check syscheck alert for nested monitoring with <tags> option
- [ ] Check syscheck alert for monitoring folder with <restrict> option
- [ ] Check the "nodiff" option to don't show the changes of a file
- [ ] Check syscheck flag auto_ignore with attributes "frequency" and "timeframe" (1)
- [ ] Check that the audit policies are restored
- [ ] Verify that whodata does not block files. https://github.com/wazuh/wazuh/pull/3872

## Opened issues:

### General
- [ ] Daylight saving induced false positives: https://github.com/wazuh/wazuh/issues/4167
- [ ] Syscheck frequency values under 10 seconds behaviour: https://github.com/wazuh/wazuh/issues/4003
- [ ] Information message number 6022 can flood the Windows agent log file: https://github.com/wazuh/wazuh/issues/3998
- [ ] Simple and sregex syscheck <registry_ignore> stanzas are incompatible: https://github.com/wazuh/wazuh/issues/3990 (When combining <registry_ignore> and <registry_ignore type="sregex"> stanzas, only the non-sregex ones will be taken into account at the registry ignore process.)
- [ ] Different behavior in configuration while monitoring a drive in whodata and realtime: https://github.com/wazuh/wazuh/issues/3934
- [ ] The windows_audit_interval option should be in whodata block: https://github.com/wazuh/wazuh/issues/3891
- [ ] Failure to monitor directories in real-time when configuring Windows audit policies: https://github.com/wazuh/wazuh/issues/3812
- [ ] Realtime syscheck alerts are not queued if agent is offline: https://github.com/wazuh/wazuh/issues/3811
- [ ] Too generic error when adding an inotify watcher: https://github.com/wazuh/wazuh/issues/3770
- [ ] Receive alert of realtime instead of whodata: https://github.com/wazuh/wazuh/issues/3733
- [ ] Race condition hazards due to non-reentrant function calls: https://github.com/wazuh/wazuh/issues/3474
- [ ] Wazuh rule support for syscheck tags: https://github.com/wazuh/wazuh/issues/3415
- [ ] FIM (ossec-syscheckd) is unable to detect if the SUID bit is set on a monitored file: https://github.com/wazuh/wazuh/issues/3304
- [ ] Incompatible field types in Kibana: https://github.com/wazuh/wazuh/issues/3171
- [ ] Real time events moving files or directories: https://github.com/wazuh/wazuh/issues/2863
- [ ] Realtime syscheck scan doesn't start: https://github.com/wazuh/wazuh/issues/2798
- [ ] Error in the use of wildcards (*) in the system check: https://github.com/wazuh/wazuh/issues/2723
- [ ] Wildcard for restrict option of syscheck: https://github.com/wazuh/wazuh/issues/2428
- [ ] FIM full_log field is being truncated : https://github.com/wazuh/wazuh/issues/2632
- [ ] Add timezone option for syscheck <scan_time>: https://github.com/wazuh/wazuh/issues/2555
- [ ] Queue clients give up on timeout: https://github.com/wazuh/wazuh/issues/2548
- [ ] Add registry scan in whodata mode: https://github.com/wazuh/wazuh/issues/2525
- [ ] New global <fim> block within <global> in ossec.conf: https://github.com/wazuh/wazuh/pull/2504
- [ ] Executing whodata with inmutable audit configuration: https://github.com/wazuh/wazuh/issues/2432
- [ ] FIM DB synchronization between managers: https://github.com/wazuh/wazuh/issues/2404
- [ ] Syscheck is not attaching the timestamp of a deleted file event when having realtime enabled: https://github.com/wazuh/wazuh/issues/2397
- [ ] When sending PUT /{rootcheck,syscheck} the designated agent runs either rootcheck or syscheck but not both: https://github.com/wazuh/wazuh/issues/2236
- [ ] Sregex is not useful in restrict option: https://github.com/wazuh/wazuh/issues/2064
- [ ] Whodata for auditd logs: https://github.com/wazuh/wazuh/issues/2042
- [ ] FIM output inconsistency: https://github.com/wazuh/wazuh/issues/2005
- [ ] False positives about new files in FIM: https://github.com/wazuh/wazuh/issues/1881
- [ ] Implementation Filename Globbing for <ignore> Tag: https://github.com/wazuh/wazuh/issues/1326
- [ ] Error with real-time + NFS: https://github.com/wazuh/wazuh/issues/1269
- [ ] Filtering by event type: https://github.com/wazuh/wazuh/issues/1247
- [ ] Customizable tag for group rules: https://github.com/wazuh/wazuh/issues/999

### Linux:
- [ ] Syscheck directories tag doesn't recognize directory / it needs /.: https://github.com/wazuh/wazuh/issues/3705
- [ ] Several agentless ssh_integrity_check_linux targerts override each other states: https://github.com/wazuh/wazuh/issues/3565
- [ ] FIM is not able to parse some symbols in a Windows Agent: https://github.com/wazuh/wazuh/issues/3310
- [ ] Syscheck hangs analyzing /dev/core: https://github.com/wazuh/wazuh/issues/3007
- [ ] FIM keeps alerting after removing a symbolic link: https://github.com/wazuh/wazuh/issues/2433
- [ ] Ignore option for Syscheck makes global ignores on the manager: https://github.com/wazuh/wazuh/issues/2378
- [ ] Syscheck in realtime doesn't detect changes in hardlinks: https://github.com/wazuh/wazuh/issues/2355
- [ ] Integration of Syscheck with eBFP to capture who-data: https://github.com/wazuh/wazuh/issues/806
- [ ] Check audit.cwd:  https://github.com/wazuh/wazuh/issues/4175
- [ ] Check audit.process.ppname to Linux agent FIM whodata collection: https://github.com/wazuh/wazuh/issues/1310   

### Windows:
- [ ] Unexpected behavior with links to System32 and SysWOW64 in Syscheck: https://github.com/wazuh/wazuh/issues/3739
- [ ] Collect Windows Registry keys permissions: https://github.com/wazuh/wazuh/issues/4223
- [ ] Filter some Windows Registry values from a key or subkey: https://github.com/wazuh/wazuh/issues/4150
- [ ] Wrong ownership value in Windows agent: https://github.com/wazuh/wazuh/issues/2220
- [ ] Windows parent process to FIM whodata: https://github.com/wazuh/wazuh/issues/1311
- [ ] FIM alerts of Windows Registry keys with empty-string MD5: https://github.com/wazuh/wazuh/issues/858
