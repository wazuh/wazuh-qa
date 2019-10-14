---
name: 'Test: Vulnerability detector'
about: Test suite for Vulnerability detector.
title: ''
labels: ''
assignees: ''

---

# Vulnerability detector

| Version | Revision |
| --- | --- |
| x.y.z | rev |

## Summary
- [ ] VUL001
- [ ] VUL002
- [ ] VUL003
- [ ] VUL004
- [ ] VUL005
- [ ] VUL006
- [ ] VUL007
- [ ] VUL008
- [ ] VUL009
- [ ] VUL010
- [ ] VUL011
- [ ] VUL012
- [ ] VUL013
- [ ] VUL014
- [ ] VUL015


## VUL001

**Short description**

Vulnerability-detector must update the local DBs with the latest feeds.

**Category**

Vulnerability-detector

**Subcategory**

Database updates

**Description**

Vulnerability-detector needs to update the DB each `frequency` time, it is required to check in the logs if the downloads are working properly.

**Configuration sample**

``` XML
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>100d</interval>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os update_interval="10m">precise</os>
      <os update_interval="20m">trusty</os>
      <os update_interval="30m">xenial</os>
      <os>bionic</os>
      <update_interval>40m</update_interval>
    </provider>
    <provider name="debian">
      <enabled>yes</enabled>
      <os>wheezy</os>
      <os>stretch</os>
      <os>jessie</os>
      <update_interval>30m</update_interval>
    </provider>
    <provider name="redhat">
      <enabled>yes</enabled>
      <update_from_year>2015</update_from_year>
      <update_interval>10m</update_interval>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2015</update_from_year>
      <update_interval>15m</update_interval>
    </provider>
  </vulnerability-detector>
```

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

We should see a `5461` message approximately every individual interval is reached. If you apply the previous configuration:

- **Ubuntu Precise** every 10 minutes.
- **Ubuntu Trusty** every 20 minutes.
- **Ubuntu Xenial** every 30 minutes.
- **Ubuntu Bionic** every 40 minutes.
- **Debian Wheezy** every 30 minutes.
- **Debian Stretch** every 30 minutes.
- **Debian Jessie** every 30 minutes.
- **Red Hat** every 10 minutes.
- **National Vulnerability Database** every 15 minutes.

> 2019/09/25 11:31:56 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Ubuntu Bionic database update.
> 2019/09/25 11:32:03 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Ubuntu Bionic feed finished successfully.
> 2019/09/25 11:32:03 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Ubuntu Xenial database update.
> 2019/09/25 11:32:14 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Ubuntu Xenial feed finished successfully.
> 2019/09/25 11:32:14 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Ubuntu Trusty database update.
> 2019/09/25 11:32:26 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Ubuntu Trusty feed finished successfully.
> 2019/09/25 11:32:26 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Ubuntu Precise database update.
> 2019/09/25 11:32:42 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Ubuntu Precise feed finished successfully.
> 2019/09/25 11:32:42 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Debian Stretch database update.
> 2019/09/25 11:32:51 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Debian Stretch feed finished successfully.
> 2019/09/25 11:32:51 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Debian Jessie database update.
> 2019/09/25 11:32:59 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Debian Jessie feed finished successfully.
> 2019/09/25 11:32:59 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Debian Wheezy database update.
> 2019/09/25 11:33:00 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Debian Wheezy feed finished successfully.
> 2019/09/25 11:33:00 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Red Hat Enterprise Linux database update.
> 2019/09/25 11:33:15 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Red Hat Enterprise Linux feed finished successfully.
> 2019/09/25 11:33:16 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting National Vulnerability Database database update.
> 2019/09/25 11:34:43 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the National Vulnerability Database feed finished successfully.


## VUL002

**Short description**

Vulnerability-detector must accept the deprecated `<disabled>` option.

**Category**

Vulnerability-detector

**Subcategory**

Retro compatibility

**Description**

This option `<disabled>` has been in favour of `<enabled>`, but it should work during several versions and warn that it is deprecated.

**Configuration sample**

``` XML
  <vulnerability-detector>
    <disabled>no</disabled>
  </vulnerability-detector>
```

**Min/Max compatible versions**
3.11.0 - 4.0.0

**Expected logs**

> 2019/09/25 12:35:21 wazuh-modulesd: WARNING: 'disabled' option at module 'vulnerability-detector' is deprecated. Use 'enabled' instead.
> 2019/09/25 12:35:22 wazuh-modulesd:vulnerability-detector: INFO: (5452): Starting vulnerability scanning.


## VUL003

**Short description**

Vulnerability-detector must not update the feeds if they are updated.

**Category**

Vulnerability-detector

**Subcategory**

Database updates

**Description**

Vulnerability-detector is able to check if a vulnerability feed is outdated or not, to update it if it is necessary. The tests consist on to verify that the feeds are not being updated if the remote database has not changed. We will observe different behaviour depending on what feed is updating.

- For **Canonical** and **Debian** feeds, Vulnerability Detector will download the entire OVAL file, but it won't try to index it if that version has already been updated.
- For the **National Vulnerability Database** feed, Vulnerability Detector will download lightweight metadata files that will be used to evaluate if the database (heavier file) must be fetched too. This is checked for each file, as this feed divides the vulnerabilities into annual files which can be updated at different times.
- The **Red Hat** feed doest not follow this rule because we have not a way to verify if that feed has been updated since last time we indexed it.

**Configuration sample**

``` XML
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>100d</interval>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os update_interval="1m">precise</os>
      <os update_interval="1m">trusty</os>
      <os update_interval="1m">xenial</os>
      <os>bionic</os>
      <update_interval>1m</update_interval>
    </provider>
    <provider name="debian">
      <enabled>yes</enabled>
      <os>wheezy</os>
      <os>stretch</os>
      <os>jessie</os>
      <update_interval>1m</update_interval>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2015</update_from_year>
      <update_interval>1m</update_interval>
    </provider>
  </vulnerability-detector>
```

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

To view those logs you need to enable the level 2 debug in modulesd.

> 2019/09/25 13:43:10 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:2256 at wm_vuldet_fetch_oval(): DEBUG: (5457): Ubuntu Bionic OVAL is in its latest version. Update date: 2019-09-25T12:43:19
> 2019/09/25 13:43:15 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:2256 at wm_vuldet_fetch_oval(): DEBUG: (5457): Ubuntu Xenial OVAL is in its latest version. Update date: 2019-09-25T12:43:19
> 2019/09/25 13:43:27 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:2256 at wm_vuldet_fetch_oval(): DEBUG: (5457): Ubuntu Trusty OVAL is in its latest version. Update date: 2019-04-26T13:07:52
> 2019/09/25 13:43:50 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:2256 at wm_vuldet_fetch_oval(): DEBUG: (5457): Ubuntu Precise OVAL is in its latest version. Update date: 2017-05-10T19:31:06
> 2019/09/25 13:43:51 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:2256 at wm_vuldet_fetch_oval(): DEBUG: (5457): Debian Stretch OVAL is in its latest version. Update date: 2019-09-25T11:30:20.188-04:00
> 2019/09/25 13:43:53 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:2256 at wm_vuldet_fetch_oval(): DEBUG: (5457): Debian Jessie OVAL is in its latest version. Update date: 2019-09-25T11:30:08.188-04:00
> 2019/09/25 13:43:54 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:2256 at wm_vuldet_fetch_oval(): DEBUG: (5457): Debian Wheezy OVAL is in its latest version. Update date: 2019-09-25T11:30:02.188-04:00
> 2019/09/25 13:43:54 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:3738 at wm_vuldet_fetch_wazuh_cpe(): DEBUG: (5457): Wazuh CPE dictionary OVAL is in its latest version. Update date: 2019-07-05T00:33Z


## VUL004

**Short description**

Vulnerability-detector must download the feeds from the year indicated by `<update_from_year>`.

**Category**

Vulnerability-detector

**Subcategory**

Database updates

**Description**

This option is only valid for the Red Hat and National Vulnerability feeds. To verify that all is working as expected, you can filter

**Configuration sample**

``` XML
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>100d</interval>
    <run_on_start>yes</run_on_start>
    <provider name="redhat">
      <enabled>yes</enabled>
      <update_from_year>2013</update_from_year>
      <update_interval>1m</update_interval>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2013</update_from_year>
      <update_interval>1m</update_interval>
    </provider>
  </vulnerability-detector>
```

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

If you are using the previous configuration, for the National Vulnerability Database feed you should see the following logs:

> 2019/09/25 13:43:55 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:1124 at wm_vuldet_update_feed(): DEBUG: (5512): Synchronizing the year 2015 of the vulnerability database.
> 2019/09/25 13:43:56 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:1124 at wm_vuldet_update_feed(): DEBUG: (5512): Synchronizing the year 2016 of the vulnerability database.
> 2019/09/25 13:43:57 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:1124 at wm_vuldet_update_feed(): DEBUG: (5512): Synchronizing the year 2017 of the vulnerability database.
> 2019/09/25 13:43:57 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:1124 at wm_vuldet_update_feed(): DEBUG: (5512): Synchronizing the year 2018 of the vulnerability database.
> 2019/09/25 13:43:58 wazuh-modulesd:vulnerability-detector[4618] wm_vuln_detector.c:1124 at wm_vuldet_update_feed(): DEBUG: (5512): Synchronizing the year 2019 of the vulnerability database.

The Red Hat update can be verified by seeing the API call. In the following log, we can see that the requests start in 2013 (according to the configuration):

> 2019/09/25 13:47:16 wazuh-modulesd:vulnerability-detector[4665] wm_vuln_detector.c:2294 at wm_vuldet_fetch_redhat(): DEBUG: (5554): Trying to download 'https://access.redhat.com/labs/securitydataapi/cve.json?after=2015-01-01&per_page=1000&page=1'.

Those logs will only be displayed if you enable the level 1 debug for modulesd.


## VUL005

**Short description**

The package comparations must have sense.

**Category**

Vulnerability-detector

**Subcategory**

Vulnerability detection

**Description**

To evaluate if a package is vulnerable or not, the module performs a comparison between its version and the version where the vulnerability was fixed/disappeared. These checks are displayed en the `ossec.log` file if debug level of modulesd is level 2.

You can verify that the result of those checks is correct by checking the messages whose ID is 5467, 5468, 5533 or 5456.

If this test were automatized, we could use an external library or module to parse these messages and evaluate if the comparison results in a false positive, negative or it is correct.

**Configuration sample**

Test results will be more accurate the more systems the configuration covers and the more agents supported are connected.

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

Logs depend on the agents being analysed, and whether or not they are vulnerable. Examples:

> 2019/09/25 14:44:57 wazuh-modulesd:vulnerability-detector[5541] wm_vuln_detector_nvd.c:2624 at wm_vuldet_check_hotfix(): DEBUG: (5533): Agent 1 is vulnerable to CVE-2017-0076 because does not have the '4012212' patch installed.
> 2019/09/25 14:45:04 wazuh-modulesd:vulnerability-detector[5541] wm_vuln_detector.c:931 at wm_vuldet_report_agent_vulnerabilities(): DEBUG: (5456): The 'libmpfr4' package from agent 0 is not vulnerable to CVE-2014-9474. Condition: package version (3.1.4-1) less than 3.1.2-2.


## VUL006

**Short description**

The vulnerability database must be removed between updates.

**Category**

Vulnerability-detector

**Subcategory**

File integrity

**Description**

The information stored in `<installation_path>/queue/vulnerabilities/cve.db` is not currently persistent, so the database must be removed between updates.

To verify it, perform a vulnerability scan or update, check that the database exists, modify the `ossec.conf` file to disable the module, and update Wazuh. After this, the database should not exist.

Implicated code:
- [RPM SPECS](https://github.com/wazuh/wazuh-packages/blob/48abb535e609d608fec1be6104391794664a7a07/rpms/SPECS/3.11.0/wazuh-manager-3.11.0.spec#L213).
- [DEB postinstall](https://github.com/wazuh/wazuh-packages/blob/549915e2f720d0a5f58f60e6586fdf83ccf845c4/debs/SPECS/3.10.0/wazuh-manager/debian/postinst#L114).

**Configuration sample**

Doesn't matter.

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

Package installation logs, but we don't need to check them for the test.


## VUL007

**Short description**

There does not have to be duplicated alerts.

**Category**

Vulnerability-detector

**Subcategory**

Vulnerability Detection

**Description**

This test consists in check that there are no duplicated alerts. We consider a report duplicated where we found two or more alerts with the same value in the following fields:

``` JSON
agents.id
data.vulnerability.cve
data.vulnerability.software.name
data.vulnerability.software.version
data.vulnerability.software.architecture
data.vulnerability.software.generated_cpe
```

Please note that some of the fields mentioned above may not appear.

**Configuration sample**

Test results will be more accurate the more systems the configuration covers and the more agents supported are connected.

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

This test must be performed by checking the `alerts.json` file.


## VUL008

**Short description**

Vulnerability-detector must be able to perform an offline update.

**Category**

Vulnerability-detector

**Subcategory**

Database updates

**Description**

We understand offline update as the one in which we indicate an alternative repository where getting the vulnerability database.

This type of update is performed through the `path` and `url` options, and the way to configure it depends on the provider type (multi-provider o single-provider). You can find this process explained in the Vulnerability Detector documentation.

**Configuration sample**


``` XML
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>100d</interval>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os url="http://local_repo/com.ubuntu.bionic.cve.oval.xml">bionic</os>
      <os url="http://local_repo/com.ubuntu.xenial.cve.oval.xml">xenial</os>
      <os path="/local_path/com.ubuntu.trusty.cve.oval.xml">trusty</os>
      <os path="/local_path/com.ubuntu.precise.cve.oval.xml">precise</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="debian">
      <enabled>yes</enabled>
      <os url="http://local_repo/oval-definitions-stretch.xml">stretch</os>
      <os url="http://local_repo/oval-definitions-jessie.xml">jessie</os>
      <os path="/local_path/oval-definitions-wheezy.xml">wheezy</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="redhat">
      <enabled>yes</enabled>
      <path>/local_path/rh-feed/redhat-feed.*json$</path>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
      <url start="2002" end="2019">http://local_repo/rh-feed/redhat-feed[-].json</url>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>
```

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

If you perform a vulnerability update with a configuration like the one above, which is covering all the cases, you should see the following log sequence:


> 2019/09/26 07:26:30 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Ubuntu Bionic database update.
> 2019/09/26 07:26:37 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Ubuntu Bionic feed finished successfully.
> 2019/09/26 07:26:37 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Ubuntu Xenial database update.
> 2019/09/26 07:26:48 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Ubuntu Xenial feed finished successfully.
> 2019/09/26 07:26:48 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Ubuntu Trusty database update.
> 2019/09/26 07:26:59 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Ubuntu Trusty feed finished successfully.
> 2019/09/26 07:26:59 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Ubuntu Precise database update.
> 2019/09/26 07:27:09 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Ubuntu Precise feed finished successfully.
> 2019/09/26 07:27:09 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Debian Stretch database update.
> 2019/09/26 07:27:17 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Debian Stretch feed finished successfully.
> 2019/09/26 07:27:17 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Debian Jessie database update.
> 2019/09/26 07:27:26 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Debian Jessie feed finished successfully.
> 2019/09/26 07:27:26 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Debian Wheezy database update.
> 2019/09/26 07:27:27 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Debian Wheezy feed finished successfully.
> 2019/09/26 07:27:27 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting Red Hat Enterprise Linux database update.
> 2019/09/26 07:27:59 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the Red Hat Enterprise Linux feed finished successfully.
> 2019/09/26 07:28:00 wazuh-modulesd:vulnerability-detector: INFO: (5461): Starting National Vulnerability Database database update.
> 2019/09/26 07:31:06 wazuh-modulesd:vulnerability-detector: INFO: (5494): The update of the National Vulnerability Database feed finished successfully.


## VUL009

**Short description**

Vulnerability-detector must be able to analyze vulnerabilities in all supported agents.

**Category**

Vulnerability-detector

**Subcategory**

Vulnerability detection

**Description**

All supported OS must be taken into account when a vulnerability scan is performed. To check it, connect an agent of each supported system and enable its feeds.

**Configuration sample**


``` XML
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>1m</interval>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>bionic</os>
      <os>xenial</os>
      <os>trusty</os>
      <os>precise</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="debian">
      <enabled>yes</enabled>
      <os>stretch</os>
      <os>jessie</os>
      <os>wheezy</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="redhat">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>
```

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

You should be an ID `5486` message for each supported agent with modulesd in debug mode of level 1. If there is an agent with a supported OS that is not displayed with this log, the test fails.

> 2019/09/26 08:04:07 wazuh-modulesd:vulnerability-detector[5303] wm_vuln_detector.c:1029 at wm_vuldet_check_agent_vulnerabilities(): DEBUG: (5486): Starting vulnerability assessment for agent 47.


## VUL010

**Short description**

Vulnerability-detector must ignore the unsupported agents.

**Category**

Vulnerability-detector

**Subcategory**

Vulnerability detection

**Description**

This test is the reverse of `VUL009`. It consists on to verify that all continue working if an unsupported agent is connected to de manager.

An agent may be unsupported because the module does not accept its distribution, such as Fedora, or because of its version (Debian Sid).

**Configuration sample**

Doesn't matter.

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

Since this test is the reverse of `VUL009`, verify that the `ossec.log` file does not have a false positive of that test.


## VUL011

**Short description**

Vulnerability-detector must allow checking vulnerabilities in an unsupported agent if the user specifies it.

**Category**

Vulnerability-detector

**Subcategory**

Vulnerability detection

**Description**

The `allow` option of Vulnerability Detector is used to configure the vulnerability scan of an unsupported OS by simulating that the agent system is supported.

**Configuration sample**

To test it, connect several agents of similar or derivated distributions to the manager and configure its monitoring using this tag.

The following configuration example is adding support for `Pop! OS 16` and `Ubuntu 15` as if they were `Ubuntu 16`, `Linux Mint 19` as `Ubuntu 18`, `Oracle Linux 7` as `Red Hat 7`, and `Oracle Linux 6` as `Red Hat 6`.

``` XML
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>1m</interval>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>no</enabled>
      <os allow="Pop!_OS-16,Ubuntu-15">xenial</os>
      <os allow="Linux Mint-19">bionic</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="redhat">
      <enabled>yes</enabled>
      <allow replaced_os="Red Hat-7">Oracle Linux-7</allow>
      <allow replaced_os="Red Hat-6">Oracle Linux-6</allow>
      <update_interval>1h</update_interval>
      <update_from_year>2010</update_from_year>
    </provider>
  </vulnerability-detector>
```

You can find more information about how to configure this option in the documentation.

**Min/Max compatible versions**
3.11.0 - Current

**Expected logs**

You can verify that the agent is being taken into account with the check from `VUL009`.


## VUL012

**Short description**

Vulnerability-detector must be retro compatible with old configuration structures.

**Category**

Vulnerability-detector

**Subcategory**

Vulnerability detection

**Description**

The module has to accept the deprecated configuration structure to guarantee that the manager does not break between updates for this reason.

**Configuration sample**

``` XML
  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>1d</interval>
    <run_on_start>yes</run_on_start>
    <update_ubuntu_oval interval="60m" version="16,14">yes</update_ubuntu_oval>
    <update_redhat_oval interval="60m" version="7,6">yes</update_redhat_oval>
  </wodle>
```

**Min/Max compatible versions**
3.11.0 - 4.0

**Expected logs**

It is expected to find log messages warning about that configuration is deprecated.

> 2019/09/26 08:04:07 wazuh-modulesd:vulnerability-detector[5303] WARN: This vulnerability-detector declaration is deprecated. Use <vulnerability-detector> instead.


## VUL013

**Short description**

Vulnerability-detector must respect the scan interval specifies for `<ignore_time>` for each agent independently.

**Category**

Vulnerability-detector

**Subcategory**

Vulnerability detection

**Description**

The `<ignore_time>` option is used to configure the interval time during the agent will not be fully scanned. This means during that time only the new packages of the agent, or those that have been updated will be analyzed.

Note that this option defines an interval for each agent, and the time must start to count when the first scan of the agent is performed.

The test must also verify that the ignore interval is respected, and not restarted, between manager restarts.

**Configuration sample**

The following block configures an ignore interval of 6 hours, which is the default value if the option is not specified.

``` XML

  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>precise</os>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="debian">
      <enabled>yes</enabled>
      <os>wheezy</os>
      <os>stretch</os>
      <os>jessie</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="redhat">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>
```

**Min/Max compatible versions**
3.11.0 - current

**Expected logs**

You should see the following debug messages with the ignore time has not been reached and a scan is performed.

> 2019/09/26 09:46:57 wazuh-modulesd:vulnerability-detector[6099] wm_vuln_detector.c:2815 at wm_vuldet_get_software_info(): DEBUG: (5574): A partial scan will be run on agent 47.
> 2019/09/26 09:46:57 wazuh-modulesd:vulnerability-detector[6099] wm_vuln_detector.c:2950 at wm_vuldet_get_software_info(): DEBUG: (5475): No changes have been found with respect to the last package inventory for agent 47.


## VUL014

**Short description**

Vulnerability-detector must scan an agent if it has hotfix or package inventory.

**Category**

Vulnerability-detector

**Subcategory**

Vulnerability detection

**Description**

Vulnerability Detector checks if there is a package inventory available for each Linux agent to decide if the agent has to be scanned or not. However, this check is not the same for Windows agents since they can also be scanned if a hotfixes inventory is available.

The purpose of this test is to verify if Vulnerability Detector takes into account the supported agents with a package/hotfixes inventory, or discards them otherwise.

To see the related messages modulesd must be launched with level 1 debug. The message code which confirms that an agent is going to be reported is `5454`.

**Configuration sample**

The following configuration will help us to cover all use cases combining it with agents of different type and configuration.

``` XML
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>xenial</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="redhat">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>
```

Using this configuration, the test should replicate an environment such as the following or similar.

An Ubuntu Xenial manager with the following configuration for Syscollector:

``` XML
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <packages>yes</packages>
  </wodle>
```

A Windows agent with the packages scan disabled, but which will be able to scan hotfixes.

``` XML
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <os>yes</os> 
    <packages>no</packages>
  </wodle>
```

A Centos 7 agent with the package scan disabled:

``` XML
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <packages>no</packages>
  </wodle>
```

Another Windows agent with Syscollector disabled:

``` XML
  <wodle name="syscollector">
    <disabled>yes</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
  </wodle>
```

**Min/Max compatible versions**
3.11.0 - current

**Expected logs**

Using the previous configuration, and taking into account that the agents with deactivated scans have not sent any before, these are the expected logs:

> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:4975 at wm_vuldet_run_scan(): INFO: (5452): Starting vulnerability scanning.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:1028 at wm_vuldet_check_agent_vulnerabilities(): DEBUG: (5486): Starting vulnerability assessment for agent 0.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2752 at wm_vuldet_get_software_info(): DEBUG: (5462): Getting agent 0 software.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2763 at wm_vuldet_get_software_info(): DEBUG: (5573): A full scan will be run on agent 0.

The module notifies that the agent 0 (the manager) can bee fully analyzed because it is its first scan, or the ignore time has been reached.

> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:1028 at wm_vuldet_check_agent_vulnerabilities(): DEBUG: (5486): Starting vulnerability assessment for agent 1.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2752 at wm_vuldet_get_software_info(): DEBUG: (5462): Getting agent 1 software.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2763 at wm_vuldet_get_software_info(): DEBUG: (5573): A full scan will be run on agent 1.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2784 at wm_vuldet_get_software_info(): DEBUG: (5576): The package inventory of the agent 1 is not available, but an hotfix analysis will be launched.

The first Windows agent does not have the package inventory available but will try to analyze its hotfixes.

> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:1028 at wm_vuldet_check_agent_vulnerabilities(): DEBUG: (5486): Starting vulnerability assessment for agent 3.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2752 at wm_vuldet_get_software_info(): DEBUG: (5462): Getting agent 3 software.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2763 at wm_vuldet_get_software_info(): DEBUG: (5573): A full scan will be run on agent 3.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2779 at wm_vuldet_get_software_info(): DEBUG: (5434): No package inventory found for agent 3, so their vulnerabilities will not be checked.

Agent 3 (Centos 7) is directly discarded due to it does not have the necessary package scan.

> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:1028 at wm_vuldet_check_agent_vulnerabilities(): DEBUG: (5486): Starting vulnerability assessment for agent 4.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2752 at wm_vuldet_get_software_info(): DEBUG: (5462): Getting agent 4 software.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2763 at wm_vuldet_get_software_info(): DEBUG: (5573): A full scan will be run on agent 4.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2784 at wm_vuldet_get_software_info(): DEBUG: (5576): The package inventory of the agent 4 is not available, but an hotfix analysis will be launched.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:2860 at wm_vuldet_get_software_info(): DEBUG: (5577): It is not possible to perform a hotfix scan on agent 4.

On the other hand, agent 4 (Windows) has no inventory of hotfixes or packages available, so it will also be discarded.

> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:856 at wm_vuldet_report_agent_vulnerabilities(): DEBUG: (5454): Analyzing agent 1 vulnerabilities.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:992 at wm_vuldet_report_agent_vulnerabilities(): DEBUG: (5487): Finished vulnerability assessment for agent 1.
> 2019/10/09 16:21:35 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:856 at wm_vuldet_report_agent_vulnerabilities(): DEBUG: (5454): Analyzing agent 0 vulnerabilities.
> 2019/10/09 16:21:36 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:992 at wm_vuldet_report_agent_vulnerabilities(): DEBUG: (5487): Finished vulnerability assessment for agent 0.
> 2019/10/09 16:21:36 wazuh-modulesd:vulnerability-detector[30183] wm_vuln_detector.c:4983 at wm_vuldet_run_scan(): INFO: (5453): Vulnerability scanning finished.

Finally, we can see that only the agents 1 and 0 has been scanned.


## VUL015

**Short description**

Vulnerability-detector must not report as vulnerable the software that has been updated if Syscollector has notified it.

**Category**

Vulnerability-detector

**Subcategory**

Vulnerability detection

**Description**

The purpose of this test is to verify that the module is useful for locating packages that need to be updated and correcting their vulnerabilities.

To verify it for Windows and Linux programs, we can install a vulnerable version, check how it is reported, and fix it.

The test is different for those vulnerabilities which can only be fixed by installing a hotfix.

**Configuration sample**

The use case of this test will be a vulnerable Ubuntu Bionic manager and a Windows Server 2008 R2 agent. We can use this configuration:

``` XML
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>bionic</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>
```

For Syscollector:

``` XML
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <packages>yes</packages>
    <packages>os</packages>
  </wodle>
```

**Min/Max compatible versions**
3.11.0 - current

**Expected logs**

We can start the test by installing the `libkrb5support0` package to a vulnerable version (`1.16-2ubuntu0.1`) as follows:


``` BASH
apt install libkrb5support0=1.16-2ubuntu0.1
```

After this, the next scan should trigger the next alert:

```
** Alert 1571046780.345938: - vulnerability-detector,gdpr_IV_35.7.d,
2019 Oct 14 09:53:00 8d31315b480e->vulnerability-detector
Rule: 23503 (level 5) -> 'CVE-2018-5710 on Ubuntu 18.04 LTS (bionic) - low.'
{"vulnerability":{"cve":"CVE-2018-5710","title":"CVE-2018-5710 on Ubuntu 18.04 LTS (bionic) - low.","severity":"Low","published":"2018-01-16T09:29:00Z","state":"Fixed","software":{"name":"libkrb5support0","version":"1.16-2ubuntu0.1","architecture":"amd64"},"condition":"Package less than 1.16.1-1","reference":"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710"}}
vulnerability.cve: CVE-2018-5710
vulnerability.title: CVE-2018-5710 on Ubuntu 18.04 LTS (bionic) - low.
vulnerability.severity: Low
vulnerability.published: 2018-01-16T09:29:00Z
vulnerability.state: Fixed
vulnerability.software.name: libkrb5support0
vulnerability.software.version: 1.16-2ubuntu0.1
vulnerability.software.architecture: amd64
vulnerability.condition: Package less than 1.16.1-1
vulnerability.reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710
```

It is not necessary to wait for the ignore time to expire because new or updated packages are always analyzed.

If we set the debug level to 2 and filter by the package we should see a message indicating that the package is vulnerable and the condition to confirm the vulnerability.

> 2019/10/14 09:57:54 wazuh-modulesd:vulnerability-detector[3641] wm_vuln_detector.c:946 at wm_vuldet_report_agent_vulnerabilities(): DEBUG: (5467): The 'libkrb5support0' package from agent 0 is vulnerable to CVE-2018-5710. Condition: package version (1.16-2ubuntu0.1) less than 1.16.1-1.

Finally, if we update the package and Syscollector index that change:

> 2019/10/14 10:18:45 wazuh-modulesd:vulnerability-detector[4122] wm_vuln_detector.c:939 at wm_vuldet_report_agent_vulnerabilities(): DEBUG: (5456): The 'libkrb5support0' package from agent 0 is not vulnerable to CVE-2018-5710. Condition: package version (1.16.3-3.1) less than 1.16.1-1.

For the Windows vulnerability, we will use a Windows Server 2008 R2 which is vulnerable to `CVE-2017-0055` for not having the `KB4012212` hotfix installed. We should see the following alert.

```
** Alert 1571048511.2019462: - vulnerability-detector,gdpr_IV_35.7.d,
2019 Oct 14 10:21:51 (agwin) 172.16.210.128->vulnerability-detector
Rule: 23504 (level 7) -> 'Microsoft Internet Information Server (IIS) in Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to perform cross-site scripting and run script with local user privileges via a crafted request, aka "Microsoft IIS Server XSS Elevation of Privilege Vulnerability."'
{"vulnerability":{"cve":"CVE-2017-0055","title":"Microsoft Internet Information Server (IIS) in Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to perform cross-site scripting and run script with local user privileges via a crafted request, aka \"Microsoft IIS Server XSS Elevation of Privilege Vulnerability.\"","severity":"Medium","published":"2017-03-17","updated":"2017-07-12","state":"Fixed","cvss":{"cvss2":{"vector":{"attack_vector":"network","access_complexity":"medium ","authentication":"none","integrity_impact":"partial ","availability":"none"},"base_score":4.3},"cvss3":{"vector":{"attack_vector":"network","access_complexity":"low","confidentiality_impact":"low","availability":"none","privileges_required":"none","user_interaction":"required ","scope":"changed "},"base_score":6.1}},"software":{"name":"Windows Server 2008 R2","generated_cpe":"o:microsoft:windows_server_2008:r2:sp1::::::"},"condition":"4012212 patch is not installed.","cwe_reference":"CWE-79","reference":"http://www.securityfocus.com/bid/96622"}}
vulnerability.cve: CVE-2017-0055
vulnerability.title: Microsoft Internet Information Server (IIS) in Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to perform cross-site scripting and run script with local user privileges via a crafted request, aka "Microsoft IIS Server XSS Elevation of Privilege Vulnerability."
vulnerability.severity: Medium
vulnerability.published: 2017-03-17
vulnerability.updated: 2017-07-12
vulnerability.state: Fixed
vulnerability.cvss.cvss2.vector.attack_vector: network
vulnerability.cvss.cvss2.vector.access_complexity: medium 
vulnerability.cvss.cvss2.vector.authentication: none
vulnerability.cvss.cvss2.vector.integrity_impact: partial 
vulnerability.cvss.cvss2.vector.availability: none
vulnerability.cvss.cvss2.base_score: 4.300000
vulnerability.cvss.cvss3.vector.attack_vector: network
vulnerability.cvss.cvss3.vector.access_complexity: low
vulnerability.cvss.cvss3.vector.confidentiality_impact: low
vulnerability.cvss.cvss3.vector.availability: none
vulnerability.cvss.cvss3.vector.privileges_required: none
vulnerability.cvss.cvss3.vector.user_interaction: required 
vulnerability.cvss.cvss3.vector.scope: changed 
vulnerability.cvss.cvss3.base_score: 6.100000
vulnerability.software.name: Windows Server 2008 R2
vulnerability.software.generated_cpe: o:microsoft:windows_server_2008:r2:sp1::::::
vulnerability.condition: 4012212 patch is not installed.
vulnerability.cwe_reference: CWE-79
vulnerability.reference: http://www.securityfocus.com/bid/96622
```

We can download the patch suggested by the alert from https://www.catalog.update.microsoft.com/search.aspx?q=kb4012212.

After applying the hotfix, and once the agent has updated its hotfix inventory through Syscollector, we will see the following debug message in Vulnerability Detector when running a full-scan.

> 2019/10/14 10:29:42 wazuh-modulesd:vulnerability-detector[4463] wm_vuln_detector_nvd.c:2611 at wm_vuldet_check_hotfix(): DEBUG: (5534): Agent 1 has installed KB4012212 that corrects the vulnerability CVE-2017-0055.

Note that the hotfixes scan is only performed each time a full-scan is launched, or in other words, each time the value set by `<ignore_time>` is reached. Only packages can be scanned with a partial scan.
