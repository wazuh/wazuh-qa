| Name | About | Title | Labels | Assigness |
| --- | --- | --- | --- | --- | 
| Test: Mitre | Test suite for Mitre | '' | '' | '' |

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
- [ ] MIT011
- [ ] MIT012
- [ ] MIT013
- [ ] MIT014
- [ ] MIT015
- [ ] MIT016
- [ ] MIT017
- [ ] MIT018

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

3.11.0 - Current

**Expected outputs**
```
# ls var/ossec/var/db
```
> agents  global.db  global.db-shm  global.db-wal  mitre.db
```
# sqlite3 var/ossec/var/db/mitre.db
sqlite> .tables
```
> attack has_phase has_platform
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

3.11.0 - Current

**Expected logs**

```
# cat ossec.log | grep Mitre
```
> ossec-analysisd[19213] mitre.c:71 at mitre_load(): DEBUG: Mitre info loading failed. Mitre's database response has 0 elements.

> ossec-analysisd[4729] mitre.c:50 at mitre_load(): ERROR: Mitre matrix information could not be loaded.

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
$ sudo nano enterprise-attack.json
Change line 5: "objects" to "object".

Then, install Manager
 ```
**Compatible versions**

3.11.0 - Current

**Expected logs**

```
# cat ossec.log | grep Mitre
```
> ossec-analysisd[19213] mitre.c:71 at mitre_load(): DEBUG: Mitre info loading failed. Query's response has 0 elements.

> ossec-analysisd[4729] mitre.c:50 at mitre_load(): ERROR: Mitre matrix information could not be loaded.

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

3.11.0 - Current

**Expected outputs**
```
# ls opt/ossec/var/db
```
> agents  global.db  global.db-shm  global.db-wal  mitre.db
```
# sqlite3 opt/ossec/var/db/mitre.db
sqlite> .tables
```
> attack has_phase has_platform
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

If Mitre extension is added to a rule and an event matchs the rule, an alert should show Mitre information. 

**Configuration sample**

Add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
 ```
 ```
 wazuh-control restart
 CTRL + D
 sudo su
 CRTL + D
 sudo su
 ```
**Compatible versions**

3.11.0 - Current

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
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

If a rule has two o more different Mitre techniques IDs, repeated tactics should not be shown in the alert.

**Category**

Mitre

**Description**

If a rule has two o more different Mitre's techniques, repeated tactics should not be shown in the alert. Technique IDs and tactics are shown in different arrays. 

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
 ```
 ```
 wazuh-control restart
 CTRL + D
 sudo su
 CRTL + D
 sudo su
 ```
**Compatible versions**

3.11.0 - Current

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
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

If a rule has repeated Mitre Technique IDs, repeated IDs should not be shown in the alert.

**Category**

Mitre

**Description**

If a rule has repeated Mitre Technique IDs, repeated IDs should not be shown in the alert. In that way, the alert will be clearer for the user.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T1078</id>
      <id>T1169</id>
      <id>T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
 ```
 ```
 wazuh-control restart
 CTRL + D
 sudo su
 CRTL + D
 sudo su
 ```
**Compatible versions**

3.11.0 - Current

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
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
Techniques appear only once.

## MIT008

**Short description**

If a rule has an ID technique that is not in Mitre database, the ID should appear in the alert and a warning message should be generated. 

**Category**

Mitre

**Description**

If a rule has an ID technique that is not in Mitre database, the ID should appear in the alert but its tactics should not because there are no tactics associated with that ID. Wazuh doesn't have to stop. In addition, a warning message will be generated. 

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T6000</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
 ```
 ```
 wazuh-control restart
 CTRL + D
 sudo su
 CRTL + D
 sudo su
 ```
**Compatible versions**

3.11.0 - Current

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
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
> ossec-analysisd[27311] to_json.c:110 at Eventinfo_to_jsonstr(): WARNING: Mitre Technique ID T6000 is not in mitre database.

## MIT009

**Short description**

If a rule has two or more technique IDs separated by commas,the IDs should appear in the alert and a warning message should be generated. 

**Category**

Mitre

**Description**

If a rule has two or more technique IDs separated by commas, they will not be splittered so it will not be possible to get their tactics. IDs should appear in the alert and a warning message should be generated.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169, T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
 ```
 ```
 wazuh-control restart
 CTRL + D
 sudo su
 CRTL + D
 sudo su
 ```
**Compatible versions**

3.11.0 - Current

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169, T1078"]
               "tactics":[]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}

```
> ossec-analysisd[27311] to_json.c:109 at Eventinfo_to_jsonstr(): WARNING: Mitre Technique ID T1169, T1078 is not in mitre database.

## MIT010

**Short description**

If a rule has 0 Techniques, an alert should be generated without Mitre info.

**Category**

Mitre

**Description**

If a rule has 0 ID Techniques, an alert should be generated without Mitre info. The rule has to have Mitre and ID XML tags. 

**Configuration sample**

Remove techniques:

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <ids></ids>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
 ```
 ```
 wazuh-control restart
 CTRL + D
 sudo su
 CRTL + D
 sudo su
 ```
**Compatible versions**

3.11.0 - Current

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
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

## MIT011

**Short description**

A rule has two o more different Mitre techniques IDs but they are not together inside 'mitre' tags.

**Category**

Mitre

**Description**

If a rule has two o more different Mitre techniques IDs but they are not together inside 'mitre' tags, there will be no errors.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
    </mitre>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
 ```
 ```
 wazuh-control restart
 CTRL + D
 sudo su
 CRTL + D
 sudo su
 ```
**Compatible versions**

3.11.0 - Current

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169","T1078"],
               "tactics":["Privilege Escalation","Defense Evasion","Initial Access","Persistence"]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}

```

## MIT012

**Short description**

A rule has two o more different Mitre techniques IDs but they are not together inside 'mitre' tags and there are duplicated technique IDs.

**Category**

Mitre

**Description**

If a rule has two o more different Mitre techniques IDs but they are not together inside 'mitre' tags and there are duplicated technique IDs, there will be no errors.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T1110</id>
    </mitre>
    <mitre>
      <id>T1169</id>
      <id>T1154</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
 ```
 ```
 wazuh-control restart
 CTRL + D
 sudo su
 CRTL + D
 sudo su
 ```
**Compatible versions**

3.11.0 - Current

**Expected alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169","T1110","T1154"],
               "tactics":["Privilege Escalation","Credential Access","Execution","Persistence"]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}

```

## MIT013

**Short description**

If has_phase table is not in mitre.db, tactics should not be shown in alerts and Wazuh should show error messages.

**Category**

Mitre

**Description**

If has_phase table is not in mitre.db, tactics should not be shown in alerts and Wazuh should show error messages. It does not have to stop Wazuh.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
```
```
sqlite3 /var/ossec/var/db/mitre.db
sqlite> DROP TABLE has_phase;
CTRL + D
wazuh-control restart
 ```
**Compatible versions**

3.11.0 - Current

**Expected logs and alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169","T1078"],
               "tactics":[]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}
```
```
# cat ossec.log | grep Mitre
```
> wazuh-db[7314] wdb_parser.c:348 at wdb_parse(): DEBUG: Mitre DB Cannot execute SQL query; err database var/db/mitre.db: no such table: has_phase

> ossec-remoted[7354] wazuhdb_op.c:94 at wdb_send_query(): ERROR: Bad response 'err Cannot execute Mitre database query; no such table: has_phase'

> ossec-analysisd[7339] mitre.c:98 at mitre_load(): DEBUG: Mitre info loading failed. No response or bad response from wazuh-db: err Cannot execute Mitre database query; no such table: has_phase

> ossec-analysisd[7339] mitre.c:99 at mitre_load(): ERROR: Mitre matrix information could not be loaded.

## MIT014

**Short description**

If attack table is not in mitre.db, tactics should not be shown in alerts and Wazuh should show error messages.

**Category**

Mitre

**Description**

If attack table is not in mitre.db, tactics should not be shown in alerts and Wazuh should show error messages. It does not have to stop Wazuh.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
```

```
sqlite3 /var/ossec/var/db/mitre.db
sqlite> DROP TABLE attack;
CTRL + D
wazuh-control restart
 ```
**Compatible versions**

3.11.0 - Current

**Expected logs and alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169","T1078"],
               "tactics":[]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}
```
```
# cat ossec.log | grep Mitre
```
> wazuh-db[27581] wdb_parser.c:348 at wdb_parse(): DEBUG: Mitre DB Cannot execute SQL query; err database var/db/mitre.db: no such table: attack

> ossec-remoted[27593] wazuhdb_op.c:94 at wdb_send_query(): ERROR: Bad response 'err Cannot execute Mitre database query; no such table: attack'

> ossec-analysisd[27609] mitre.c:48 at mitre_load(): DEBUG: Mitre info loading failed. Query gave an error response: err Cannot execute Mitre database query; no such table: attack

> ossec-analysisd[27609] mitre.c:49 at mitre_load(): ERROR: Mitre matrix information could not be loaded.

## MIT015

**Short description**

If the attack table's colum called 'id' has other different names, tactics should not be shown in alerts and Wazuh should show error messages.

**Category**

Mitre

**Description**

If the attack table's column called 'id' has other different names, tactics should not be shown in alerts and Wazuh should show error messages. It does not have to stop Wazuh.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
```

```
# nano /wazuh/tools/mitre/mitredb.py
Change  id for ids in sql_create_attack = """CREATE TABLE IF NOT EXISTS attack (id TEXT PRIMARY KEY, json TEXT);"""
 ```
**Compatible versions**

3.11.0 - Current

**Expected logs and alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169","T1078"],
               "tactics":[]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}
```
```
# cat ossec.log | grep Mitre
```
> wazuh-db[28187] wdb_parser.c:358 at wdb_parse(): DEBUG: Mitre DB Cannot execute SQL query; err database var/db/mitre.db: no such column: id

> ossec-remoted[28195] wazuhdb_op.c:94 at wdb_send_query(): ERROR: Bad response 'err Cannot execute Mitre database query; no such column: id'

> ossec-analysisd[28215] mitre.c:48 at mitre_load(): DEBUG: Mitre info loading failed. No response or bad response from wazuh-db: err Cannot execute Mitre database query; no such column: id

> ossec-analysisd[28215] mitre.c:49 at mitre_load(): ERROR: Mitre matrix information could not be loaded.

## MIT016

**Short description**

If the has_phase table's column called 'phase_name' has other different names, tactics should not be shown in alerts and Wazuh should show error messages.

**Category**

Mitre

**Description**

If the has_phase table's column called 'phase_name' has other different names, tactics should not be shown in alerts and Wazuh should show error messages. It does not have to stop Wazuh.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
```

```
# nano /wazuh/tools/mitre/mitredb.py
Change phase_name for phase in sql_create_has_phase = """CREATE TABLE IF NOT EXISTS has_phase (
                                    attack_id TEXT, 
                                    phase_name TEXT,
                                    FOREIGN KEY(attack_id) REFERENCES attack(id),
                                    PRIMARY KEY (attack_id, phase_name)
                                );"""
 ```
**Compatible versions**

3.11.0 - Current

**Expected logs and alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169","T1078"],
               "tactics":[]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}
```
```
# cat ossec.log | grep Mitre
```
> wazuh-db[3303] wdb_parser.c:358 at wdb_parse(): DEBUG: Mitre DB Cannot execute SQL query; err database var/db/mitre.db: no such table: has_phase

> ossec-remoted[3319] wazuhdb_op.c:94 at wdb_send_query(): ERROR: Bad response 'err Cannot execute Mitre database query; no such table: has_phase'

> ossec-analysisd[3331] mitre.c:98 at mitre_load(): DEBUG: Mitre info loading failed. No response or bad response from wazuh-db: err Cannot execute Mitre database query; no such table: has_phase

> ossec-analysisd[3331] mitre.c:99 at mitre_load(): ERROR: Mitre matrix information could not be loaded.

## MIT017

**Short description**

If Mitre database does not exist, tactics should not be shown in alerts and Wazuh should show error messages.

**Category**

Mitre

**Description**

If Mitre database does not exist, tactics should not be shown in alerts and Wazuh should show error messages. It does not have to stop.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <id>T1169</id>
      <id>T1078</id>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
```

```
rm /var/ossec/var/db/mitre*
wazuh-control restart
 ```
**Compatible versions**

3.11.0 - Current

**Expected logs and alerts**
```
# tail -f /var/ossec/logs/alerts/alerts.json | grep Mitre

{
"timestamp":"2019-09-30T13:12:29.416+0200",
"rule":{
      "level":5,
      "description":"Successful sudo to ROOT executed",
      "id":"5402",
      "mitre":{"id":["T1169","T1078"],
               "tactics":[]
               },
      "firedtimes":1,
      "mail":false,
      "groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.3.1","IA.10"]
       },
       
       ...
}
```
```
# cat ossec.log | grep Mitre
```
> wazuh-db[14586] wdb.c:212 at wdb_open_mitre(): ERROR: Can't open SQLite database 'var/db/mitre.db': unable to open database file

> wazuh-db[14586] wdb_parser.c:320 at wdb_parse(): ERROR: Couldn't open DB mitre

> ossec-remoted[14614] wazuhdb_op.c:94 at wdb_send_query(): ERROR: Bad response 'err Couldn't open DB mitre'.

> ossec-analysisd[14614] mitre.c:48 at mitre_load(): DEBUG: Mitre info loading failed. Query gave an error response: err Couldn't open DB mitre

> ossec-analysisd[14614] mitre.c:49 at mitre_load(): ERROR: Mitre matrix information could not be loaded.

## MIT018

**Short description**

If a rule has an incorrect Mitre XML tag or it does not have one, Wazuh should stop.

**Category**

Mitre

**Description**

If a rule has an incorrect Mitre XML tag name or it does not have any, a critical error should be generated and Wazuh will stop.

**Configuration sample**

Delete rule '100002' and add the following lines in /var/ossec/etc/rules/local_rules.xml (we change 'id' label for 'ids').
```
<group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      <ids>T1169</ids>
      <ids>T1078</ids>
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
</rule>
 ```
 Or remove 'id':
 ```
 <group name="syslog,errors,">

  <rule id="100002" level="5">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed</description>
    <mitre>
      T1169
      T1078
    </mitre>
    <group>pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.3.1,nist_800_53_IA.10,</group>
  </rule>

</group>
 ``` 
**Compatible versions**

3.11.0 - Current

**Expected logs**

> ossec-analysisd[22563] analysisd.c:572 at main(): CRITICAL: (1220): Error loading the rules: 'ruleset/rules/0020-syslog_rules.xml'.
