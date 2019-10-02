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
      <update_from_year>2015</update_from_year>
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

The information stored in `<installation_path>/queue/vulnerability/cve.db` is not currently persistent, so the database must be removed between updates.

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
