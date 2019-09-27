# Mitre

| Version | Revision | 
| --- | --- | 
| x.y.z | rev |

## Summary

- [ ] MIT001

## MIT001

**Short description**

Mitre database should be installed in /var/db/mitre.db, no matter where Mitre Json file is.

**Category**

Mitre

**Description**

There is a Python script called mitredb.py in wazuh/tools/mitre/mitredb.py that is execute in the installation. 
This script creates mitre.db, creates attack, has_phase and has_platform tables and filles them from Mitre json file.
Mitre json file is in wazuh/etc/mitre/enterprise-attack.json. If this file is in another directory, Mitre DB will be installed anyways.
It is important to check the mitre database is created in /var/db/mitre.db after installation.  

**Configuration sample**

```
$ cd wazuh/
$ git checkout 3.10-mitre
# ./install (install Manager)
 ```

If mitre.db is in var/ossec/var/db after installation, move enterprise-attack.json to another directory.
Check Mitre database is in var/ossec/var/db again
```
sudo rm var/ossec/var/db/mitre*
sudo mv wazuh/etc/mitre/enterprise-attack.json wazuh/etc/
# ./install (install manager)
```
**Min/Max compatible versions**

3.11.0

**Expected outputs**
```
# ls var/ossec/var/ossec/var/db
output: agents  global.db  global.db-shm  global.db-wal  mitre.db
``` 
```
# sqlite3 var/ossec/var/ossec/var/db/mitre.db
sqlite> .tables
output: attack has_phase has_platform
```
```
sqlite> SELECT * FROM attack;
sqlite> SELECT * FROM has_phase;
sqlite> SELECT * FROM has_platform;
Ctrl + D
