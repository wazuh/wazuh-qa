# Mitre

| Version | Revision | 
| --- | --- | 
| x.y.z | rev |

## Summary

- [ ] MIT001
- [ ] MIT002
- [ ] MIT003
- [ ] MIT004
- [ ] MIT005
- [ ] MIT006
- [ ] MIT007
- [ ] MIT008
- [ ] MIT009
- [ ] MIT010

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
# ./install (install Manager)
 ```

If mitre.db is in var/ossec/var/db after installation, move enterprise-attack.json to another directory.
Check Mitre database is in var/ossec/var/db after installing again
```
sudo rm var/ossec/var/db/mitre*
sudo mv wazuh/etc/mitre/enterprise-attack.json wazuh/etc/enterprise-attack.json

Then, install manager again
```
**Compatible versions**

3.11.0

**Expected outputs**
```
# ls var/ossec/var/db
output: agents  global.db  global.db-shm  global.db-wal  mitre.db
``` 
```
# sqlite3 var/ossec/var/db/mitre.db
sqlite> .tables
output: attack has_phase has_platform
```
```
sqlite> SELECT * FROM attack;
sqlite> SELECT * FROM has_phase;
sqlite> SELECT * FROM has_platform;
Ctrl + D
```

## MIT002

**Short description**

Wazuh should not stop if Mitre JSON file is not found or has different name

**Category**

Mitre

**Description**

Script mitredb.py will search enterprise-attack.json in order to fill the three tables in mitre.db. If the file is not or has different name, the script will create mitre.db and tables but it won't be able to fill them.

**Configuration sample**

```
$ cd wazuh/etc/mitre
$ sudo mv enterprise-attack.json attack.json
# rm /var/ossec/var/db/mitre*

Then, install Manager
 ```
**Compatible versions**

3.11.0

**Expected logs**
```
# cat ossec.log | grep Mitre
output: 
ossec-analysisd[19213] mitre.c:71 at mitre_load(): DEBUG: Mitre info loading failed. Mitre's database response has 0 elements.
ossec-analysisd[4729] mitre.c:50 at mitre_load(): ERROR: Mitre matrix information could not be loaded.

```
## MIT003

**Short description**

Wazuh should not stop if Mitre JSON file's fields have another name.

**Category**

Mitre

**Description**

Script mitredb.py will search enterprise-attack.json in order to fill the three tables in mitre.db. If the file's json fields have other names, the script will create mitre.db and tables but it won't be able to fill them.

**Configuration sample**

```
$ cd wazuh/etc/mitre
$ sudo nano enterprise-attack.json attack.json
Change line 5: "objects" to "object".

Then, install Manager
 ```
**Compatible versions**

3.11.0

**Expected logs**
```
# cat ossec.log | grep Mitre
output: 
ossec-analysisd[19213] mitre.c:71 at mitre_load(): DEBUG: Mitre info loading failed. Mitre's database response has 0 elements.
ossec-analysisd[4729] mitre.c:50 at mitre_load(): ERROR: Mitre matrix information could not be loaded.

```

## MIT004

**Short description**

Mitre database should be installed in installation path (var/ossec or others). 

**Category**

Mitre

**Description**

Script mitredb.py includes a input parameter to choose the installation path. In that way, if the path installation is /opt/ossec, mitre.db has to be installed in /opt/ossec/var/db/mitre.db.

**Configuration sample**

```
cd wazuh/src
# make deps PREFIX=/opt/ossec && make PREFIX=/opt/ossec TARGET=server DEBUG=1
cd ..
Install Manager and choose /opt/ossec as path installation
 ```
**Compatible versions**

3.11.0

**Expected outputs**
```
# ls opt/ossec/var/db
output: agents  global.db  global.db-shm  global.db-wal  mitre.db
``` 
```
# sqlite3 opt/ossec/var/db/mitre.db
sqlite> .tables
output: attack has_phase has_platform
```
```
sqlite> SELECT * FROM attack;
sqlite> SELECT * FROM has_phase;
sqlite> SELECT * FROM has_platform;
Ctrl + D
```

## MIT005

**Short description**

An alert should show Mitre information. 

**Category**

Mitre

**Description**

When Mitre extension is added to a rule and an event matchs the rule, an alert should show Mitre information. 

**Configuration sample**

```
sudo nano wazuh/etc/rules/0020-syslog_rules.xml

<rule id="5402" level="3">
    <if_sid>5400</if_sid>
    <regex> ; USER=root ; COMMAND=| ; USER=root ; TSID=\S+ ; COMMAND=</regex>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
</rule>
 ```
 ```
 ossec-control restart
 sudo su
 CTRL + D
 sudo su
 CRTL + D
 ```
**Compatible versions**

3.11.0

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":3,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169"],
               "tactics":["Privilege Escalation"]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}

```

## MIT006

**Short description**

When a rule has two o more different Mitre techniques, repeated tactics are not shown in the alert.

**Category**

Mitre

**Description**

When a rule has two o more different Mitre's techniques, repeated tactics are not shown in the alert. Techniques and tactics are shown in different arrays. 

**Configuration sample**

```
sudo nano wazuh/etc/rules/0020-syslog_rules.xml

<rule id="5402" level="3">
    <if_sid>5400</if_sid>
    <regex> ; USER=root ; COMMAND=| ; USER=root ; TSID=\S+ ; COMMAND=</regex>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
</rule>
 ```
 ```
 ossec-control restart
 sudo su
 CTRL + D
 sudo su
 CRTL + D
 ```
**Compatible versions**

3.11.0

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":3,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169","T1078"]
               "tactics":["Privilege Escalation","Defense Evasion","Initial Access","Persistence"]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}

```
In this case, these techniques have in common the "Privilege Escalation" tactic but it appears only once.

## MIT007

**Short description**

When a rule has an ID technique that is not in Mitre database, the ID will appear in the alert.

**Category**

Mitre

**Description**

When a rule has an ID technique that is not in Mitre database, the ID will appear in the alert but its tactics wont because there are no tactics associated with that ID. Wazuh doesn't have to stop. 

**Configuration sample**

```
sudo nano wazuh/etc/rules/0020-syslog_rules.xml

<rule id="5402" level="3">
    <if_sid>5400</if_sid>
    <regex> ; USER=root ; COMMAND=| ; USER=root ; TSID=\S+ ; COMMAND=</regex>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T6000</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
</rule>
 ```
 ```
 ossec-control restart
 sudo su
 CTRL + D
 sudo su
 CRTL + D
 ```
**Compatible versions**

3.11.0

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":3,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169","T6000"]
               "tactics":["Privilege Escalation"]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}

```

## MIT008

**Short description**

When a rule has 0 Techniques, an alert is generated with two empty arrays.

**Category**

Mitre

**Description**

When a rule has 0 ID Techniques, an alert is generated with two empty arrays. The rule has to have Mitre and ID XML tags. 

**Configuration sample**

Remove techniques:

```
sudo nano wazuh/etc/rules/0020-syslog_rules.xml

<rule id="5402" level="3">
    <if_sid>5400</if_sid>
    <regex> ; USER=root ; COMMAND=| ; USER=root ; TSID=\S+ ; COMMAND=</regex>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <ids></ids>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
</rule>
 ```
 ```
 ossec-control restart
 sudo su
 CTRL + D
 sudo su
 CRTL + D
 ```
**Compatible versions**

3.11.0

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":3,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":[""],
               "tactics":[]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}
```

## MIT009

**Short description**

When a rule has an incorrect Mitre XML tag or it does not have one, Wazuh stops.

**Category**

Mitre

**Description**

When a rule has an incorrect Mitre XML tag name or it does not have any, an critical error is generated and Wazuh stops.

**Configuration sample**

Change <id> to <ids> in rule:

```
sudo nano wazuh/etc/rules/0020-syslog_rules.xml

<rule id="5402" level="3">
    <if_sid>5400</if_sid>
    <regex> ; USER=root ; COMMAND=| ; USER=root ; TSID=\S+ ; COMMAND=</regex>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <ids>T1169</ids>
      <ids>T1078</ids>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
</rule>
 ```
 Or remove <id>:
 ```
 <rule id="5402" level="3">
    <if_sid>5400</if_sid>
    <regex> ; USER=root ; COMMAND=| ; USER=root ; TSID=\S+ ; COMMAND=</regex>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      T1169
      T1078
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>
 ``` 
 ```
 ossec-control restart
 sudo su
 CTRL + D
 sudo su
 CRTL + D
 ```
**Compatible versions**

3.11.0

**Expected logs**
```
ossec-analysisd[22563] analysisd.c:572 at main(): CRITICAL: (1220): Error loading the rules: 'ruleset/rules/0020-syslog_rules.xml'.

```

## MIT010

**Short description**

Check there are not memory leaks using Valgrind

**Category**

Mitre

**Description**

Check there are not memory leaks in analysisd using Valgrind. Analysisd is responsible for filling in Mitre database and generating alerts.

**Configuration sample**

```
valgrind --leak-check=full --trace-children=yes --read-var-info=yes --track-origins=yes --show-leak-kinds=all --read-var-info=yes /var/ossec/bin/ossec-analysisd -f
```
**Compatible versions**

3.11.0

**Expected outputs**

100 bytes of memory leak are expected:
```
LEAK SUMMARY:
==2268==    definitely lost: 100 bytes in 9 blocks
==2268==    indirectly lost: 0 bytes in 0 blocks
==2268==      possibly lost: 20,128 bytes in 74 blocks
==2268==    still reachable: 12,118,135 bytes in 58,600 blocks
==2268==         suppressed: 0 bytes in 0 blocks
```
