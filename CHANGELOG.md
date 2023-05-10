# Changelog

All notable changes to this project will be documented in this file.

## [4.3.11] - 20-04-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/776fda906581a1e4ee170c3e7e73a58d69e41f95 \
Release report: https://github.com/wazuh/wazuh/issues/16758

### Fixed

- Fix flacky `test_authd_valid_name_ip` IT to make it clean the env before each case. ([#4155](https://github.com/wazuh/wazuh-qa/pull/4155)) \- (Tests)

## [4.3.10] - 16-11-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/89530f11c9e592cd2e551432209b0080f08ff8e5 \
Release report: https://github.com/wazuh/wazuh/issues/15372

## [4.3.9] - 13-10-2022

Wazuh commit: https://github.com/wazuh/wazuh-qa/commit/8af0a5083bd69765f4d7878df9d3b785bb239723 \
Release report: https://github.com/wazuh/wazuh/issues/15090

### Added

- Add a test to check the analysisd socket properties ([#3365](https://github.com/wazuh/wazuh-qa/pull/3365))

## [4.3.8] - 19-09-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/88bf15d2cbb2040e197e34a94dda0f71f607afad \
Release report: https://github.com/wazuh/wazuh/issues/14827

### Added

- Analysisd - add new test to check analysisd socket properties ([#2405](https://github.com/wazuh/wazuh-qa/pull/2405))

### Changed

- Change required version of urllib3 and requests dependencies \- (Framework)
- Update wazuh-logtest messages for integration tests \- (Tests)

### Fixed

- Fix Integratord tests. ([#3362](https://github.com/wazuh/wazuh-qa/pull/3362)) \- (Framework + Tests)

## [4.3.7] - 24-08-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/e2b514bef3d148acd4bcae1a1c7fa8783b82ca3a \
Release report: https://github.com/wazuh/wazuh/issues/14562

### Added
- Added IT test to verify Active Response works with overwritten rules. ([#2984](https://github.com/wazuh/wazuh-qa/pull/2984)) \- (Framework + Tests)
- Add Integratord IT - new test_integratord suite ([#3125](https://github.com/wazuh/wazuh-qa/pull/3125)) \- (Framework + Tests)
- Add system test to check synchronization status in the cluster ([#3180](https://github.com/wazuh/wazuh-qa/pull/3180)) \- (Framework + Tests)

### Changed

- Increase framework version of jq and pytest in the requirements file to support python3.10 ([#3107](https://github.com/wazuh/wazuh-qa/pull/3108)) \- (Framework)

## [4.3.6] - 20-07-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/be15851b8ead7512d9cd4ef1ee18b3b953173211 \
Release report: https://github.com/wazuh/wazuh/issues/14188

### Added
- Add Remoted IT - test_multi_groups ([#3060](https://github.com/wazuh/wazuh-qa/pull/3060)) \- (Framework + Tests)

### Fixed

- Fix GCloud IT - test_max_messages error ([#3006](https://github.com/wazuh/wazuh-qa/pull/3006)) \- (Framework + Tests)
- Fix Remoted IT - test_agent_communication ([#3088](https://github.com/wazuh/wazuh-qa/pull/3088)) \- (Framework)


## [4.3.5] - 29-06-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/2a2b88bfb2ea30903728372471b33540a3b3d976 \
Release report: https://github.com/wazuh/wazuh/issues/13966

### Fixed

- Fix Solaris and Macos FIM integration failures ([#2977](https://github.com/wazuh/wazuh-qa/pull/2977)) \- (Framework + Tests)


## [4.3.4] - 09-06-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/ccbc9490bc38718717233c50e3d6daeff102e388 \
Release report: https://github.com/wazuh/wazuh/issues/13669


## [4.3.3] - 01-06-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/ccbc9490bc38718717233c50e3d6daeff102e388 \
Release report: -


## [4.3.2] - 30-05-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/5b3d501f5a10c5134b53771f13c48dc94c54beb2 \
Release report: https://github.com/wazuh/wazuh/issues/13629


## [4.3.1] - 18-05-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/8ee2a5646a12d22bf662b2f59a19c12b4b8d0a4e \
Release report: https://github.com/wazuh/wazuh/issues/13448


## [4.3.0] - 05-05-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/5bae1c1830dbf11acc8a06e01f7a5a134b767760 \
Release report: https://github.com/wazuh/wazuh/issues/13321

### Added

- Add specific version of libcst to install in python lower than 3.7. ([#2459](https://github.com/wazuh/wazuh-qa/pull/2459))
- Add system test to check synchronization between agent and manager. ([#2443](https://github.com/wazuh/wazuh-qa/pull/2443))
- Make `simulate-api-load` CLI run tasks simultaneously. ([#2392](https://github.com/wazuh/wazuh-qa/pull/2392))
- Add `qa-ctl` `v0.3`. ([#2307](https://github.com/wazuh/wazuh-qa/pull/2307))
- Add `qa-ctl` `v0.2`. ([#2299](https://github.com/wazuh/wazuh-qa/pull/2299))
- Improve the `agent_files_deletion` test . ([#2296](https://github.com/wazuh/wazuh-qa/pull/2296))
- Add scripts to add agents to client.keys, create agent-groups and unsynchronize agents. ([#2295](https://github.com/wazuh/wazuh-qa/pull/2295))
- Add cluster performance test. ([#2130](https://github.com/wazuh/wazuh-qa/pull/2130))
- IT Wazuh-logtest: Ruleset reloading at runtime. ([#2077](https://github.com/wazuh/wazuh-qa/pull/2077))
- Add script to parse and obtain stats from cluster CSVs. ([#2032](https://github.com/wazuh/wazuh-qa/pull/2032))
- Add `qa-ctl` tool v0.1. ([#1895](https://github.com/wazuh/wazuh-qa/pull/1895))
- Enable WPK tests for macOS agents. ([#1853](https://github.com/wazuh/wazuh-qa/pull/1853))
- Create local_internal_options configuration handler fixture. ([#1835](https://github.com/wazuh/wazuh-qa/pull/1835))
- Create file monitoring fixture handler. ([#1833](https://github.com/wazuh/wazuh-qa/pull/1833))
- Create daemon handler fixture for integration test. ([#1826](https://github.com/wazuh/wazuh-qa/pull/1826))
- Add test to check new possible flaws in wodles, framework and API code. ([#1659](https://github.com/wazuh/wazuh-qa/pull/1659))
- Add test to scan all python packages. ([#1652](https://github.com/wazuh/wazuh-qa/pull/1652))
- ITs for logtest verbose mode added. ([#1587](https://github.com/wazuh/wazuh-qa/pull/1587))
- Integration and system tests to ensure removed agent files are deleted. ([#1527](https://github.com/wazuh/wazuh-qa/pull/1527))
- Add wdb checksum range test case. ([#1502](https://github.com/wazuh/wazuh-qa/pull/1502))
- Add integration tests for max_upload_size API option. ([#1494](https://github.com/wazuh/wazuh-qa/pull/1494))
- Add support for Amazon Linux in vulnerability detector. ([#1473](https://github.com/wazuh/wazuh-qa/pull/1473))
- Add tests for invalid config of github and office365 modules. ([#1460](https://github.com/wazuh/wazuh-qa/pull/1460))
- Add test to check the behavior of test_max_fd_win_rt option.. ([#1387](https://github.com/wazuh/wazuh-qa/pull/1387))
- Add FIM Windows 4659 events tests. ([#648](https://github.com/wazuh/wazuh-qa/pull/648))

### Changed

- Migrate `test_rids` documentation to `qa-docs`. ([#2422](https://github.com/wazuh/wazuh-qa/pull/2422))
- Google Cloud. IT Tests: Fixing and rework for 4.3.0-RC2. ([#2420](https://github.com/wazuh/wazuh-qa/pull/2420))
- Refactor: FIM `test_report_changes` according to new standard.  Phase 1. ([#2417](https://github.com/wazuh/wazuh-qa/pull/2417))
- Fix `wazuh-metrics` CLI bug when child processes restart. ([#2416](https://github.com/wazuh/wazuh-qa/pull/2416))
- IT Solaris Jenkins: Fix requirements. ([#2415](https://github.com/wazuh/wazuh-qa/pull/2415))
- Fix the `agent_info_sync` test according to new changes. ([#2411](https://github.com/wazuh/wazuh-qa/pull/2411))
- Migrate test_cpe_indexing documentation to qa-docs. ([#2407](https://github.com/wazuh/wazuh-qa/pull/2407))
- WazuhDB IT: Fix for 4.3. ([#2400](https://github.com/wazuh/wazuh-qa/pull/2400))
- Migrate test_scan_results documentation to qa-docs. ([#2398](https://github.com/wazuh/wazuh-qa/pull/2398))
- Migrate test_general_setting documentation to qa-docs. ([#2387](https://github.com/wazuh/wazuh-qa/pull/2387))
- Migrate test_providers documentation to qa-docs. ([#2377](https://github.com/wazuh/wazuh-qa/pull/2377))
- Update API configuration integration tests. ([#2370](https://github.com/wazuh/wazuh-qa/pull/2370))
- Refactor FIM `test_synchronization` according to new standard (1). ([#2358](https://github.com/wazuh/wazuh-qa/pull/2358))
- Migrate test_feeds documentation to qa-docs. ([#2357](https://github.com/wazuh/wazuh-qa/pull/2357))
- Fix autoconfigure `test_add_old_resource`. ([#2356](https://github.com/wazuh/wazuh-qa/pull/2356))
- Migrate test_wazuh_db documentation to qa-docs. ([#2346](https://github.com/wazuh/wazuh-qa/pull/2346))
- Adapt `wazuh-metrics` and `data-visualizer` CLIs to handle multiprocessing. ([#2278](https://github.com/wazuh/wazuh-qa/pull/2278))
- Change `time_to_sync`  variable. ([#2275](https://github.com/wazuh/wazuh-qa/pull/2275))
- Bump pytest-html dependency. ([#2205](https://github.com/wazuh/wazuh-qa/pull/2205))
- Update remoted CSV headers in visualization tool. ([#2202](https://github.com/wazuh/wazuh-qa/pull/2202))
- Migrate `test_rootcheck` documentation to qa-docs. ([#2194](https://github.com/wazuh/wazuh-qa/pull/2194))
- Migrate `test_logtest` documentation to `qa-docs`. ([#2191](https://github.com/wazuh/wazuh-qa/pull/2191))
- Migrate test_office365 documentation to `qa-docs`. ([#2181](https://github.com/wazuh/wazuh-qa/pull/2181))
- fix: Change logtest custom rules ids. ([#2177](https://github.com/wazuh/wazuh-qa/pull/2177))
- Authd replacement configurations QA. ([#2171](https://github.com/wazuh/wazuh-qa/pull/2171))
- Migrate `test_github` documentation to `qa-docs`. ([#2144](https://github.com/wazuh/wazuh-qa/pull/2144))
- Migrate `test_glcoud` documentation to `qa-docs`. ([#2141](https://github.com/wazuh/wazuh-qa/pull/2141))
- Merge 4.2 into master branch . ([#2132](https://github.com/wazuh/wazuh-qa/pull/2132))
- Migrate `test_auth` documentation to `qa-docs`. ([#2129](https://github.com/wazuh/wazuh-qa/pull/2129))
- Migrate `test_registry_restrict` and `test_registry_tags` of `test_fim/test_registry`, and `test_fim/test_synchronization` documentation to `qa-docs`. ([#2128](https://github.com/wazuh/wazuh-qa/pull/2128))
- Migrate `test_registry_report_changes` of `test_fim/test_registry` documentation to `qa-docs`. ([#2127](https://github.com/wazuh/wazuh-qa/pull/2127))
- Migrate `test_registry_file_limit`, `test_registry_multiple_registries`, and `test_registry_recursion_level` of `test_fim/test_registry` documentation to `qa-docs`. ([#2126](https://github.com/wazuh/wazuh-qa/pull/2126))
- Migrate `test_registry_checks`, `test_registry_ignore`, and `test_registry_nodiff` of `test_fim/test_registry` documentation to `qa-docs`. ([#2125](https://github.com/wazuh/wazuh-qa/pull/2125))
- Migrate `test_registry_basic_usage` of `test_fim/test_registry` documentation to `qa-docs`. ([#2124](https://github.com/wazuh/wazuh-qa/pull/2124))
- Migrate `test_registry_ambiguous_confs` of `test_fim/test_registry` documentation to `qa-docs`. ([#2123](https://github.com/wazuh/wazuh-qa/pull/2123))
- Migrate `test_tags`, `test_timezone_changes`, `test_wildcards_complex`, and `test_windows_audit_interval` of `test_fim/test_files` documentation to `qa-docs`. ([#2122](https://github.com/wazuh/wazuh-qa/pull/2122))
- Migrate `test_scan`, `test_skip`, and `test_stats_integrity_sync` of `test_fim/test_files` documentation to `qa-docs`. ([#2121](https://github.com/wazuh/wazuh-qa/pull/2121))
- Migrate `test_fim/test_files/test_report_changes` documentation to `qa-docs`. ([#2120](https://github.com/wazuh/wazuh-qa/pull/2120))
- Migrate `test_process_priority`, `test_recursion_level`, and `test_restrict` of `test_fim/test_files` documentation to `qa-docs`. ([#2118](https://github.com/wazuh/wazuh-qa/pull/2118))
- Migrate `test_multiple_dirs`, `test_nodiff`, and `test_prefilter_cmd` of `test_fim/test_files` documentation to `qa-docs`. ([#2117](https://github.com/wazuh/wazuh-qa/pull/2117))
- Migrate `test_max_eps`, `test_max_files_per_second`, and `test_moving_files` of `test_fim/test_files` documentation to `qa-docs`. ([#2115](https://github.com/wazuh/wazuh-qa/pull/2115))
- Migrate `test_ignore`, `test_inotify`, and `test_invalid` of `test_fim/test_files` documentation to `qa-docs`. ([#2114](https://github.com/wazuh/wazuh-qa/pull/2114))
- Migrate `test_fim/test_files/test_follow_symbolic_link` documentation to `qa-docs`. ([#2112](https://github.com/wazuh/wazuh-qa/pull/2112))
- Migrate `test_env_variables` and `test_file_limit` of `test_fim/test_files` documentation to `qa-docs`. ([#2111](https://github.com/wazuh/wazuh-qa/pull/2111))
- Migrate `test_benchmark` and `test_checks` of `test_fim/test_files` documentation to `qa-docs`. ([#2110](https://github.com/wazuh/wazuh-qa/pull/2110))
- Migrate `test_basic_usage` of `test_fim/test_files` documentation to `qa-docs`. ([#2109](https://github.com/wazuh/wazuh-qa/pull/2109))
- Migrate `test_ambiguous_confs` and `test_audit` of `test_fim/test_files` documentation to qa-docs. ([#2108](https://github.com/wazuh/wazuh-qa/pull/2108))
- Migrate `test_api` documentation to `qa-docs`. ([#2107](https://github.com/wazuh/wazuh-qa/pull/2107))
- Migrate `test_analysisd` documentation to `qa-docs`. ([#2047](https://github.com/wazuh/wazuh-qa/pull/2047))
- Migrate `test_agentd` documentation to `qa-docs`. ([#2006](https://github.com/wazuh/wazuh-qa/pull/2006))
- Migrate `test_active_response` documentation to `qa-docs`. ([#1960](https://github.com/wazuh/wazuh-qa/pull/1960))
- Fix requirements in master. ([#2063](https://github.com/wazuh/wazuh-qa/pull/2063))
- Update system tests for agent key polling. ([#2119](https://github.com/wazuh/wazuh-qa/pull/2119))
- macOS logcollector - Fixes and new tests. ([#2043](https://github.com/wazuh/wazuh-qa/pull/2043))
- Update API performance tests. ([#1881](https://github.com/wazuh/wazuh-qa/pull/1881))
- Integrate qa-docs into wazuh-qa framework. ([#1854](https://github.com/wazuh/wazuh-qa/pull/1854))
- Update user used by `Kibana` in the cluster performance tests. ([#1822](https://github.com/wazuh/wazuh-qa/pull/1822))
- Fix cached dependencies, typos and debian repos. ([#1732](https://github.com/wazuh/wazuh-qa/pull/1732))
- Adapt the JSON event schema to parse WIN perms in JSON. ([#1541](https://github.com/wazuh/wazuh-qa/pull/1541))
- Update API performance tests. ([#1519](https://github.com/wazuh/wazuh-qa/pull/1519))
- Rework of simulate agents script. Add new balance mode to distribute EPS between agents. ([#1491](https://github.com/wazuh/wazuh-qa/pull/1491))
- Fix missing argument in test_macos_format_basic IT. ([#1478](https://github.com/wazuh/wazuh-qa/pull/1478))
- Check if scheduled mode is set when realtime is not available. ([#1474](https://github.com/wazuh/wazuh-qa/pull/1474))

### Removed
- Remove unnecessary `CLIENT_KEYS_PATH`. ([#2419](https://github.com/wazuh/wazuh-qa/pull/2419))
- Remove deprecated configurations. ([#2380](https://github.com/wazuh/wazuh-qa/pull/2380))
- Remove deprecated test_use_only_authd. ([#2294](https://github.com/wazuh/wazuh-qa/pull/2294))
- Remove expected `force` option from the received request in the `agent_enrollment` system tests. ([#2289](https://github.com/wazuh/wazuh-qa/pull/2289))
- Remove old check. ([#2281](https://github.com/wazuh/wazuh-qa/pull/2281))
- Remove the disk i/o % usage calculation from the performance tools. ([#1897](https://github.com/wazuh/wazuh-qa/pull/1897))
- Remove FIM hard link tests. ([#1485](https://github.com/wazuh/wazuh-qa/pull/1485))


## [v4.2.0]
### Added
- Add agent labels to agent simulator tool [#1153](https://github.com/wazuh/wazuh-qa/pull/1153)
- Add the capability to know which CVE’s affect an agent [#7479](https://github.com/wazuh/wazuh/issues/7479)
- Add new tests for Wazuh-DB insert commands in agents' CVEs table [#1092](https://github.com/wazuh/wazuh-qa/pull/1092)
- Add integration tests for syslog [#1086](https://github.com/wazuh/wazuh-qa/pull/1086)
- Add remoted integration tests: basic configuration tests [#1073](https://github.com/wazuh/wazuh-qa/pull/1073)
- Add the tier 0 integration tests for wazuh-remoted [#1024](https://github.com/wazuh/wazuh-qa/issues/1024)
- Add new features to the Agent simulator [#1106](https://github.com/wazuh/wazuh-qa/pull/1106)
- Add new integration tests to cover the stats of wazuh-agentd [#1039](https://github.com/wazuh/wazuh-qa/pull/1039)
- Add the documentation of Wazuh-QA repository [#1066](https://github.com/wazuh/wazuh-qa/pull/1066)
- Add new functionality for mocking agents [#1054](https://github.com/wazuh/wazuh-qa/pull/1054)
- Add support to `wodle` sections for ossec.conf generator tool [#1048](https://github.com/wazuh/wazuh-qa/pull/1048)
- Add new tests for Active Response [#1029](https://github.com/wazuh/wazuh-qa/pull/1029)
- Add focal feed and improve vulnerability scan tests [#1025](https://github.com/wazuh/wazuh-qa/pull/1025)
- Add new cases to test_env_variables to check some possible errors [#1014](https://github.com/wazuh/wazuh-qa/pull/1014)
- Add a test to verify no duplicate entries for vulnerability detector [#1010](https://github.com/wazuh/wazuh-qa/pull/1010)
- Add new case to test_basic_usage_changes to check wildcards [#1009](https://github.com/wazuh/wazuh-qa/pull/1009)
- Add some cases in test_ignore_valid, to check entire disk ignore [#1000](https://github.com/wazuh/wazuh-qa/pull/1000)
- Add new test case for duplicate registry entries [#998](https://github.com/wazuh/wazuh-qa/pull/998)
### Changed
- Rename sockets directory according to the product [#1090](https://github.com/wazuh/wazuh-qa/pull/1090)
- Improve the stop/start behavior of DB's related functions [#1068](https://github.com/wazuh/wazuh-qa/pull/1068)
- Update mock_vulnerability_scan fixture from vulnerability scan tests [#1058](https://github.com/wazuh/wazuh-qa/pull/1058)
- Update insert_vulnerability to meet new constrains [#1059](https://github.com/wazuh/wazuh-qa/pull/1059)
- Refactor the code to be PEP8 compliance [#1043](https://github.com/wazuh/wazuh-qa/pull/1043)
- Deprecate the ossec-init.conf [#1013](https://github.com/wazuh/wazuh-qa/pull/1013)
- Rename ossec-control in framework tests [#983](https://github.com/wazuh/wazuh-qa/pull/983)
- Change names of daemons in integration tests [#973](https://github.com/wazuh/wazuh-qa/pull/973)
- Rename all ossec-control references [#965](https://github.com/wazuh/wazuh-qa/pull/965)
### Fixed
- Fix an error in the Active Response tests related to the configuration file [#1080](https://github.com/wazuh/wazuh-qa/pull/1080)
- Fix an error in the Agent simulator while parsing the messages received from the manager [#1084](https://github.com/wazuh/wazuh-qa/pull/1084).
- Fix msu tests for Windows 10 [#1075](https://github.com/wazuh/wazuh-qa/pull/1075)
- Fix sqlite3.OperationalError: no such table: VULNERABILITIES error [#1067](https://github.com/wazuh/wazuh-qa/pull/1067)
- Fix test_general_settings_ignore_time test [#1056](https://github.com/wazuh/wazuh-qa/pull/1056)
- Avoid problematic race-condition on VD integration tests for Windows [#1047](https://github.com/wazuh/wazuh-qa/pull/1047)
- QA Integration tests stabilization [#1002](https://github.com/wazuh/wazuh-qa/pull/1002)
### Deleted
- Deleted `behind_proxy_server` API config test. ([#1065](https://github.com/wazuh/wazuh-qa/pull/1065))
