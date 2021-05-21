# Test Wazuh DB

All these tests are meant to send a specific command (valid or not) to the socket and compare the resulting output with the expected result.

## Overview

Let's consider an example:
```
  name: "Update commands"
  description: "Check success use cases for update commands on global DB"
  test_case:
  -
    input: 'global update-agent-name {"id":1,"name":"TestName2"}'
    output: "ok"
    stage: "global update-agent-name success"
```

All similar tests are grouped by a name, like `Update commands`. Then, every test has:

- **input**: the command that will be sent to the socket
- **output**: the expected result
- **stage**: the name of that particular test

## Objective

Confirm that `wazuh-db` is able to save, update and erase the necessary information into the corresponding databases, using the proper commands and response strings.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 30 | 45s |

## Expected behavior

- Fail if `wazuh-db` response is different from the output
## Testing

Tests description according to its classification
### Checks agent_messages

The **insert/update**, **update_status**, **remove** and **clear** commands for `vuln_cves` table are tested:

- Right insertion of a vulnerability that affects a package that is present in `sys_programs`
- Right insertion of a vulnerability that affects a package without checking its existence
- Unsuccessful insertion of a vulnerability that affects a package that is not present in `sys_programs`
- Attempt to insert a duplicated vulnerability in the database, resulting in a status field update
- Insertion of data that contain spaces
- Attempt to insert incomplete data
- Attempt to insert with an invalid JSON
- Attempt to insert without sending data
- Attempt to modify the database table that contains the vulnerabilities without specifying the action (insert or clear)
- Insert of data after clearing
- Insert an entry with some fields repeated from other existing entries
- Update of all status fields to another value
- Update of the status field by type, `package` or `os`
- Remove a vulnerability that affects a package
- Remove vulnerabilities that affect a package by status
- Clear vulnerabilities information from the database

The **get** and **set** commands for `sys_osinfo` table are tested:

- Right insertion of the operating system information
- Right obtention of operating system information
- Set of triaged field

The **get** command for `sys_programs` and `sys_hotfixes` tables is tested:

- Right obtention of packages when `sys_programs` table is synced
- Attempt to get packages when `sys_programs` table is not synced
- Right obtention of not triaged packages when `sys_programs` table is synced
- Right obtention of hotfixes when `sys_hotfixes` table is synced
- Attempt to get packages when `sys_hotfixes` table is not synced

### Checks FIM

### Checks global_messages

### Checks chunks

### Checks socket timeout disconnection

- The receiver gets 0 bytes due to socket connection timeout

## Code documentation

::: tests.integration.test_wazuh_db.test_wazuh_db
