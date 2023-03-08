# Changelog

All notable changes to this project will be documented in this file.

## [4.5.0] - Development (unreleased)

Wazuh commit: TBD \
Release report: TBD

### Added

- Add tests for msu patches with no associated CVE . ([#4009](https://github.com/wazuh/wazuh-qa/pull/4009)) \- (Framework + tests)
- Add tests with new options to avoid FIM synchronization overlapping. ([#3318](https://github.com/wazuh/wazuh-qa/pull/3318)) \- (Framework + tests)
- Add Logcollector millisecond granularity support test case ([#3910](https://github.com/wazuh/wazuh-qa/pull/3910)) \- (Tests)
- Add Windows System folders FIM monitoring tests ([#3720](https://github.com/wazuh/wazuh-qa/pull/3720)) \- (Tests)
- Add 'test_whodata_policy_changes' tests ([#3627](https://github.com/wazuh/wazuh-qa/pull/3627)) \- (Framework + Tests)
- Add test to check if active-response netsh generates alerts when firewall is disabled. ([#3787](https://github.com/wazuh/wazuh-qa/pull/3787)) \- (Framework + Tests)
- Add new tests for logcollector 'ignore' and 'restrict' options ([#3582](https://github.com/wazuh/wazuh-qa/pull/3582)) \- (Tests)
- Add 'Force reconnect' feature to agent_simulator tool. ([#3111](https://github.com/wazuh/wazuh-qa/pull/3111)) \- (Tools)

### Changed

- Update FIM `test_audit` tests to new framework ([#3939](https://github.com/wazuh/wazuh-qa/pull/3939)) \- (Framework + Tests)
- Update FIM test to new FIM DBSync process  ([#2728](https://github.com/wazuh/wazuh-qa/pull/2728)) \- (Framework + Tests)
- Update file_limit and registry_limit tests ([#3280](https://github.com/wazuh/wazuh-qa/pull/3280)) \- (Tests)
- Change expected timestamp for proftpd analysisd test predecoder test case ([#3900](https://github.com/wazuh/wazuh-qa/pull/3900)) \- (Tests)
- Skip test_large_changes test module ([#3783](https://github.com/wazuh/wazuh-qa/pull/3783)) \- (Tests)
- Update report_changes tests ([#3405](https://github.com/wazuh/wazuh-qa/pull/3405)) \- (Tests)
- Update Authd force_insert tests ([#3379](https://github.com/wazuh/wazuh-qa/pull/3379)) \- (Tests)
- Update cluster logs in reliability tests ([#2772](https://github.com/wazuh/wazuh-qa/pull/2772)) \- (Tests)
- Use correct version format in agent_simulator tool ([#3198](https://github.com/wazuh/wazuh-qa/pull/3198)) \- (Tools)

### Fixed

- Fix imports and add windows support for test_report_changes_and_diff IT ([#3548](https://github.com/wazuh/wazuh-qa/issues/3548)) \- (Framework + Tests)
- Fix a regex error in the FIM integration tests ([#3061](https://github.com/wazuh/wazuh-qa/issues/3061)) \- (Framework + Tests)
- Fix an error in the cluster performance tests related to CSV parser ([#2999](https://github.com/wazuh/wazuh-qa/pull/2999)) \- (Framework + Tests)


## [4.4.0] - Development (unreleased)

Wazuh commit: TBD \
Release report: TBD

### Added

- Add new integration test for `authd` to validate error when `authd.pass` is empty ([#3721](https://github.com/wazuh/wazuh-qa/pull/3721)) \- (Framework + Tests)
- Add new test to check missing fields in `cpe_helper.json` file ([#3766](https://github.com/wazuh/wazuh-qa/pull/3766)) \- (Framework + Tests)
- Add new test to check cpe_helper.json file ([#3731](https://github.com/wazuh/wazuh-qa/pull/3731))
- Add new tests analysid handling of invalid/empty rule signature IDs ([#3649]
(https://github.com/wazuh/wazuh-qa/pull/3649)) \- (Framework + Tests)
- Add integration test to check statistics format ([#3813](https://github.com/wazuh/wazuh-qa/pull/3813)) \- (Framework + Tests)
- Add new test to check vulnerable packages with triaged null([#3587](https://github.com/wazuh/wazuh-qa/pull/3587)) \- (Framework + Tests)
- Add new tests analysid handling of invalid/empty rule signature IDs ([#3649](https://github.com/wazuh/wazuh-qa/pull/3649)) \- (Framework + Tests)
- Add integration test to check agent database version ([#3768](https://github.com/wazuh/wazuh-qa/pull/3768)) \- (Tests)
- Fix Yara and VirusTotal E2E basic usage tests ([#3660](https://github.com/wazuh/wazuh-qa/pull/3660))
- Add new test to check if syslog message are parsed correctrly in the `archives.json` file ([#3609](https://github.com/wazuh/wazuh-qa/pull/3609)) \- (Framework + Tests)
- Add new logging tests for analysisd EPS limitation ([#3509](https://github.com/wazuh/wazuh-qa/pull/3509)) \- (Framework + Tests)
- New testing suite for checking analysisd EPS limitation ([#2947](https://github.com/wazuh/wazuh-qa/pull/3181)) \- (Framework + Tests)
- Add stress results comparator tool ([#3478](https://github.com/wazuh/wazuh-qa/pull/3478)) \- (Tools)
- Add E2E tests for demo cases ([#3293](https://github.com/wazuh/wazuh-qa/pull/3293)) \- (Framework + Tests)
- Add configuration files for Jenkins automation of system/E2E tests ([#3221](https://github.com/wazuh/wazuh-qa/pull/3221)) \- (Framework)
- New vulnerability Detector integration tests for Ubuntu 22.04 ([#2957](https://github.com/wazuh/wazuh-qa/pull/2957)) \- (Framework + Tests)
- New vulnerability Detector integration tests for Amazon Linux 2022 ([#2955](https://github.com/wazuh/wazuh-qa/pull/2955)) \- (Framework + Tests)
- New vulnerability detector tests for SUSE Linux Enterpise Support ([#2945](https://github.com/wazuh/wazuh-qa/pull/2945)) \- (Framework + Tests)
- New tests for checking API log formats ([#2635](https://github.com/wazuh/wazuh-qa/pull/2635)) \- (Framework + Tests)
- New tests for the migration of agent-group files ([#2815](https://github.com/wazuh/wazuh-qa/pull/2815)) \- (Framework + Tests)
- Add `qa-docs` `v0.1` ([#2649](https://github.com/wazuh/wazuh-qa/pull/2649)) \- (Framework + Tools + Documentation)
- Add test fim with file currently open ([#2300](https://github.com/wazuh/wazuh-qa/pull/2300)) \- (Framework + Tests)
- Test manager sends AR log format as expected ([#2347](https://github.com/wazuh/wazuh-qa/pull/2347)) \- (Framework + Tests)
- Syscollector deltas IT ([#2146](https://github.com/wazuh/wazuh-qa/pull/2146)) \- (Framework + Tests)
- CVEs alerts inventory for Vulnerability Detector - VDT and WDB Integration Tests implementation ([#1243](https://github.com/wazuh/wazuh-qa/pull/1243)) \- (Framework + Tests)
- Analysisd - add new test to check the pre-decoding stage of analysisd ([#2406](https://github.com/wazuh/wazuh-qa/pull/2406)) \- (Tests)
- Add test to check if files can be accessed while FIM has them opened ([#705](https://github.com/wazuh/wazuh-qa/pull/705)) \- (Framework + Tests)
- Analysisd - add a new test to check analysisd socket properties ([#2405](https://github.com/wazuh/wazuh-qa/pull/2405)) \- (Framework + Tests)
- Add system test to check synchronization between agent and manager when one of this was stopped. ([#2536](https://github.com/wazuh/wazuh-qa/pull/2536)) \- (Tests)
- API - Test the format of the logs (JSON logs support) ([#2635](https://github.com/wazuh/wazuh-qa/pull/2635/)) \- (Tests)
- Add a test to check the multigroups shared file content. ([#2746](https://github.com/wazuh/wazuh-qa/pull/2746)) \- (Framework + Tests)
- Add wpk test documentation ([#2409](https://github.com/wazuh/wazuh-qa/pull/2409)) \- (Documentation)

### Changed

- Increase NVE download feed test timeout([#3769](https://github.com/wazuh/wazuh-qa/pull/3769)) \- (Tests)
- Adapt wazuhdb integration tests for auto-vacuum ([#3613](https://github.com/wazuh/wazuh-qa/issues/3613)) \- (Tests)
- Update logcollector format test due to audit changes ([#3641](https://github.com/wazuh/wazuh-qa/pull/3641)) \- (Framework)
- Refactor `test_basic_usage_realtime_unsupported` FIM test to avoid using time travel ([#3623](https://github.com/wazuh/wazuh-qa/pull/3623)) \- (Tests)
- Add `monitord.rotate_log` to `local_internal_options` file for `test_macos_format_query` ([#3602](https://github.com/wazuh/wazuh-qa/pull/3602)) \- (Tests)
- Adapt analysisd integration tests for EPS ([#3559](https://github.com/wazuh/wazuh-qa/issues/3559)) \- (Tests)
- Improve `test_remove_audit` FIM test to retry install and remove command ([#3562](https://github.com/wazuh/wazuh-qa/pull/3562)) \- (Tests)
- Update pattern and expected condition for multi_groups tests ([#3565](https://github.com/wazuh/wazuh-qa/pull/3565)) \- (Tests)
- Skip unstable integration tests for gcloud ([#3531](https://github.com/wazuh/wazuh-qa/pull/3531)) \- (Tests)
- Skip unstable integration test for agentd ([#3538](https://github.com/wazuh/wazuh-qa/pull/3538))
- Update wazuhdb_getconfig and EPS limit integration tests ([#3146](https://github.com/wazuh/wazuh-qa/pull/3146)) \- (Tests)
- Refactor: logcollector `test_only_future_events` according to new standard. ([3484](https://github.com/wazuh/wazuh-qa/pull/3484)) \- (Framework + Tests)
- Update python packages scan test to use a file with known vulnerabilities to be skipped ([#3473](https://github.com/wazuh/wazuh-qa/pull/3473)) \- (Framework + Tests)
- Change required version of urllib3 and requests dependencies ([#3315](https://github.com/wazuh/wazuh-qa/pull/3315)) \- (Framework)
- Skip flaky Logcollector tests ([#3218](https://github.com/wazuh/wazuh-qa/pull/3217)) \- (Tests)
- Change how 'service_control' collects clusterd and apid pids ([#3140](https://github.com/wazuh/wazuh-qa/pull/3140)) \- (Framework)
- Change scan test module fixtures to allow use commit instead of branches ([#3134](https://github.com/wazuh/wazuh-qa/issues/3134)) \- (Tests)
- Update syscollector deltas integration tests ([#2921](https://github.com/wazuh/wazuh-qa/pull/2921)) \- (Tests)
- Update deprecated WDB commands ([#2966](https://github.com/wazuh/wazuh-qa/pull/2966)) \- (Tests)
- Move the 'get_datetime_diff' function to 'wazuh-testing' utils module ([#2782](https://github.com/wazuh/wazuh-qa/pull/2782)) \- (Framework + Tests)
- Change method from GET to POST in API login requests ([#2810](https://github.com/wazuh/wazuh-qa/pull/2810)) \- (Framework + Tests)
- Update failed test_basic_configuration_log_format ([#2924](https://github.com/wazuh/wazuh-qa/pull/2650)) \- (Framework + Tests)
- Refactor VDT integration tests: feeds and scan types ([#2650](https://github.com/wazuh/wazuh-qa/pull/2650)) \- (Framework + Tests)
- Refactor: FIM `test_synchronization` according to new standard. Phase 1. ([#2358](https://github.com/wazuh/wazuh-qa/pull/2358)) \- (Framework + Tests)
- Refactor: FIM `test_registry_file_limit` and `test_registry_report_changes`. ([#2478](https://github.com/wazuh/wazuh-qa/pull/2478)) \- (Framework + Tests)
- Refactor: FIM `test_files/test_file_limit` and updated imports to new standard. ([#2501](https://github.com/wazuh/wazuh-qa/pull/2501)) \- (Framework + Tests)
- Adapt ITs related to syscollector deltas ([#2146](https://github.com/wazuh/wazuh-qa/pull/2146)) \- (Framework + Tests)
- Migrate test_age, test_command_monitoring, and test_keep_running of test_logcollector documentation to qa-docs ([#2162](https://github.com/wazuh/wazuh-qa/pull/2162)) \- (Documentation)
- Migrate test_configuration (1/2) of test_logcollector documentation to qa-docs ([#2163](https://github.com/wazuh/wazuh-qa/pull/2163)) \- (Documentation)
- Migrate test_configuration (2/2) of test_logcollector documentation to qa-docs ([#2165](https://github.com/wazuh/wazuh-qa/pull/2165)) \- (Documentation)
- Migrate test_macos of test_logcollector documentation to qa-docs ([#2175](https://github.com/wazuh/wazuh-qa/pull/2175)) \- (Documentation)
- Migrate several test groups of test_logcollector documentation to qa-docs ([#2180](https://github.com/wazuh/wazuh-qa/pull/2180)) \- (Documentation)
- Migrate test_remoted documentation to schema 2.0 ([#2426](https://github.com/wazuh/wazuh-qa/pull/2426)) \- (Documentation)
- Replace callback_generator function to generate_monitoring_callback ([#2535](https://github.com/wazuh/wazuh-qa/pull/2535)) \- (Framework + Tests)
- Analysisd: Reduce execution time of tests with tier 0 ([#2546](https://github.com/wazuh/wazuh-qa/pull/2546)) \- (Tests)
- Adapt logtest ITs given the rules skipping ([#2200](https://github.com/wazuh/wazuh-qa/pull/2200)) \- (Tests)
- Updated the Authd response when a multigroup is too long ([#3746](https://github.com/wazuh/wazuh-qa/pull/3746)) \- (Tests)

### Fixed

- Fix test_db_backup for Ubuntu OS ([#3802](https://github.com/wazuh/wazuh-qa/pull/3802)) \- (Tests)
- Fix commit option of the scan module for master case ([#3157](https://github.com/wazuh/wazuh-qa/pull/3157)) \- (Tests)
- Fix Vulnerability Detector IT: test_validate_feed_content yaml cases had wrong extension. ([#3299](https://github.com/wazuh/wazuh-qa/pull/3299)) \- (Tests)
- Fix Analysisd IT: test_syscollector_events failure on wait_for_analysisd_startup. ([#3110](https://github.com/wazuh/wazuh-qa/pull/3110)) \- (Tests)
- Fix GCloud IT: test_max_messages error not received expected messages - ([#3083](https://github.com/wazuh/wazuh-qa/pull/3083)) \- (Tests)
- Fix Solaris and Macos FIM integration tests failures ([#2976](https://github.com/wazuh/wazuh-qa/pull/2976)) \- (Framework + Tests)
- Fix the unstable FIM tests that need refactoring ([#2458](https://github.com/wazuh/wazuh-qa/pull/2458)) \- (Framework + Tests)
- Fix version validation in qa-ctl config generator ([#2454](https://github.com/wazuh/wazuh-qa/pull/2454)) \- (Framework)
- Fix invalid reference for test_api_endpoints_performance.py xfail items ([#3378](https://github.com/wazuh/wazuh-qa/pull/3378)) \- (Tests)
- Fix undeclared API token variable in multigroups system tests ([#3674](https://github.com/wazuh/wazuh-qa/pull/3674)) \- (Framework + Tests)
- Fix error in requirements.txt ([#3689](https://github.com/wazuh/wazuh-qa/pull/3689)) \- (Framework)
- Fix sleep time in `test_agent_default_group_added`. ([#3692](https://github.com/wazuh/wazuh-qa/pull/3692)) \- (Tests)
- Fix syscollector deltas integration tests. ([#3695](https://github.com/wazuh/wazuh-qa/pull/3695)) \- (Tests)

### Removed

- Remove all FIM Integration skipped tests ([#2927](https://github.com/wazuh/wazuh-qa/issues/2927)) \- (Framework + Tests)
- VDT ITs: Remove Debian Stretch test support. ([#3172](https://github.com/wazuh/wazuh-qa/pull/3172)) \- (Tests)

## [4.3.9] - 13-10-2022

Wazuh commit: https://github.com/wazuh/wazuh-qa/commit/8af0a5083bd69765f4d7878df9d3b785bb239723 \
Release report: https://github.com/wazuh/wazuh/issues/15090

### Added

- Add a test to check the analysisd socket properties ([#3365](https://github.com/wazuh/wazuh-qa/pull/3365))

## [4.3.8] - 19-09-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/88bf15d2cbb2040e197e34a94dda0f71f607afad \
Release report: https://github.com/wazuh/wazuh/issues/14827

### Changed

- Update wazuh-logtest messages for integration tests \- (Tests)

## [4.3.7] - 24-08-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/e2b514bef3d148acd4bcae1a1c7fa8783b82ca3a \
Release report: https://github.com/wazuh/wazuh/issues/14562

## Added
- Added IT test to verify Active Response works with overwritten rules. ([#2984](https://github.com/wazuh/wazuh-qa/pull/2984)) \- (Framework + Tests)
- Add Integratord IT - new test_integratord suite ([#3125](https://github.com/wazuh/wazuh-qa/pull/3125)) \- (Framework + Tests)
- Add system test to check synchronization status in the cluster ([#3180](https://github.com/wazuh/wazuh-qa/pull/3180)) \- (Framework + Tests)
- Add system test to check big files synchronization in the cluster ([#3202](https://github.com/wazuh/wazuh-qa/pull/3202)) \- (Framework + Tests)

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
