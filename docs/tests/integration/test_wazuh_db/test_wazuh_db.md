# Test Wazuh DB

All these tests are meant to send a specific command (valid or not) to the socket and compare the resulting output with the expected result.

## Overview

Lets consider an example:
```
  name: "Update commands"
  description: "Check success use cases for update commands on global DB"
  test_case:
  -
    input: 'global update-agent-name {"id":1,"name":"TestName2"}'
    output: "ok"
    stage: "global update-agent-name success"
```

All similar test are grouped by a name, like `Update commands`. Then, every test has:

- **input**: the command that will be sent to the socket
- **output**: the expected result
- **stage**: the name of that particular test

## Objective

Confirm that `wazuh-db` is able to save, update and erase the necessary information into the corresponding databases, using the proper commands and response strings.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 37 | 60s |

## Expected behavior

- Fail if `wazuh-db` response is different from output
## Testing

Tests description according to its classification
### Checks agent_messages

The **insert** and **clear** commands for `vuln_cves` table are tested:

- Right insertion of a vulnerability that affects a package
- Attempt to insert a duplicated vulnerability in the database, resulting in no error message
- Insertion of data that contains spaces
- Attempt to insert incomplete data
- Attempt to insert with an invalid JSON
- Attempt to insert without sending data
- Attempt to modify the database table that contains the vulnerabilities without specifying the action (insert or clear)
- Clear vulnerabilities information from the database
- Insert of data after clearing
- Insert an entry with some fields repeated from other existing entries

### Checks FIM

The creation and update of the FIM DataBase are tested:

- Basics success
- Syntax errors
- Save fails
- Integrity_check_global
- Integrity_check_left
- Integrity clear
- Invalid agent ID
- Update existing file
- Path length
- Checksum field
- Large inode

### Checks global_messages

The different commands to the Global DataBase are tested:

- Insert commands
- Update commands
- Labels commands
- Select commands
- sync-agent-info-get command
- sync-agent-info-set command
- Belongs commands
- Reset connection status command
- get-agents-by-connection-status command
- disconnect-agents command
- Delete commands
- Manager keepalive command
### Checks Syscollector delta messages

The tests cover different operations against agent's inventory tables product of incoming information deltas:

- Operations against invalid db tables
- Invalid syscollector operations against db
- Valid INSERTED, CREATE, and MODIFIED operations to valid tables
- Invalid MODIFIED operations: nonexistent data, wrong number or arguments, invalid type
- Invalid INSERTED operations: duplicated entry, wrong number or arguments, invalid types
- Invalid DELETED operations: nonexistent data, wrong number of arguments, invalid type

### Checks chunks

The special scenario where a command is returned by chunks is tested.

### Checks checksum range behavior

The behavior of the checksum range calculus during an Integrity Check Global is tested.

## Code documentation

::: tests.integration.test_wazuh_db.test_wazuh_db
