# Changelog

All notable changes to this project will be documented in this file.

## [5.0.0] - TBD

## [4.10.0] - TBD

## [4.9.1] - TBD

## [4.9.0] - TBD

### Added

- Add RockyLinux 8.10 to Allocator module ([#5524](https://github.com/wazuh/wazuh-qa/pull/5524)) \- (Framework)
- Add Deployability testing tier 1 ([#5190](https://github.com/wazuh/wazuh-qa/pull/5190)) \- (Framework + Documentation + Tests)
- Add Workflow module to Wazuh-qa repository ([#4990](https://github.com/wazuh/wazuh-qa/pull/4990)) \- (Tests)
- Add an IT to check that the agent erases its wazuh-agent.state file ([#4716](https://github.com/wazuh/wazuh-qa/pull/4716)) \- (Tests)
- Add integration tests for Update field to CPE_Helper ([#4574](https://github.com/wazuh/wazuh-qa/pull/4574)) \- (Framework + Tests)

### Changed

- Increase Feed update timeout in waiters.py ([#5668](https://github.com/wazuh/wazuh-qa/pull/5668)) \- (Framework)
- Set `/active-response` as xfail ([#5660](https://github.com/wazuh/wazuh-qa/pull/5660)) \- (Tests)
- Modify the directory name for machines deployed in AWS ([#5635](https://github.com/wazuh/wazuh-qa/pull/5635)) \- (Framework)
- Add task information in the allocation logs when create or delete an instance ([#5623](https://github.com/wazuh/wazuh-qa/pull/5623)) \- (Framework)
- Changed _run_tests in testing.py ([#5621](https://github.com/wazuh/wazuh-qa/pull/5621)) \- (Framework)
- Deleted custom field from PUT /active-response performance test. ([#5612](https://github.com/wazuh/wazuh-qa/pull/5612)) \- (Tests)
- Update CentOS 7 Vagrant box ([#5546](https://github.com/wazuh/wazuh-qa/pull/5546)) \- (Framework)
- Update CentOS 7 AMIs ([#5545](https://github.com/wazuh/wazuh-qa/pull/5545)) \- (Framework)
- Update OpenSUSE 15 AMI ([#5536](https://github.com/wazuh/wazuh-qa/pull/5536)) \- (Framework)
- Update Debian 12 AMIs ([#5529](https://github.com/wazuh/wazuh-qa/pull/5529)) \- (Framework)
- Update AL2023 AMIs ([#5530](https://github.com/wazuh/wazuh-qa/pull/5530)) \- (Framework)
- Update Oracle Linux 9 AMI ([#5525](https://github.com/wazuh/wazuh-qa/pull/5525)) \- (Framework)
- Update the API script file name ([#5351](https://github.com/wazuh/wazuh-qa/pull/5351)) \- (Framework + Tests)
- Enhance the PR template ([#4881](https://github.com/wazuh/wazuh-qa/pull/4881)) \- (Framework)
- Update integration tests README ([#4742](https://github.com/wazuh/wazuh-qa/pull/4742)) \- (Documentation)

### Fixed

- Fixed unnecesary reference to debian file in dashboard provisioning task ([#5643](https://github.com/wazuh/wazuh-qa/pull/5643)) \- (Framework)
- Changed 'Ensure that the manager version is' expected warning to an agnostic version of regex ([#5630](https://github.com/wazuh/wazuh-qa/pull/5630)) \- (Tests)
- Adding fixed and dynamic waits to port status checks ([#5627](https://github.com/wazuh/wazuh-qa/pull/5627)) (Framework)
- Fixed custom storage for AMIs ([#5625](https://github.com/wazuh/wazuh-qa/pull/5625)) \- (Framework)
- Vulnerability regex changed to match with 4.9.0 solved vulnerability alerts ([#5624](https://github.com/wazuh/wazuh-qa/pull/5624)) \- (Tests)
- Fix cluster reliability test internal error ([#5620](https://github.com/wazuh/wazuh-qa/pull/5620)) \- (Tests)
- Fix CentOS 9 AMI in Allocator module ([#5523](https://github.com/wazuh/wazuh-qa/pull/5523)) \- (Framework)
- Fix stability in cluster reliability tests ([#5477](https://github.com/wazuh/wazuh-qa/pull/5477)) \- (Tests)
- Fix agent_simulator response for active-response configuration commands ([#4895](https://github.com/wazuh/wazuh-qa/pull/4895)) \- (Framework + Tests)
- Fix manager_agent system tests environment ([#4808](https://github.com/wazuh/wazuh-qa/pull/4808)) \- (Framework)

### Deleted

- Remove configobj library from requirements.txt ([#4803](https://github.com/wazuh/wazuh-qa/pull/4803)) \- (Framework)

## [4.8.2] - 20/08/2024

## [4.8.1] - 18/07/2024

### Added

- Added the capability to plot indexed alerts and vulnerabilities. ([#5518](https://github.com/wazuh/wazuh-qa/pull/5518)) \- (Framework)
- Add functionality to unify data of the binary processes with their subprocesses to plot ([#5500](https://github.com/wazuh/wazuh-qa/pull/5500)) \- (Framework)
s
### Changed

- Remove hardcoded references in provision playbook for E2E tests ([#5517](https://github.com/wazuh/wazuh-qa/pull/5517)) \- (Framework)
- Fix test_consistency_initial_scans by adding a 30-minute wait before collecting vulnerabilities. ([#5507](https://github.com/wazuh/wazuh-qa/pull/5507)) \- (Tests)
- Update `wazuh_template_branch` in filebeat provision template ([#5499]https://github.com/wazuh/wazuh-qa/pull/5499) \- (Test)


### Fixed

- Fix indexer data visualizaiton class generation ([#5520](https://github.com/wazuh/wazuh-qa/pull/5520)) and ([#5526]https://github.com/wazuh/wazuh-qa/pull/5526) \- (Framework)


## [4.8.0] - 12/06/2024

### Added

- Add functionality to obtain metrics from the dashboard ([#5432](https://github.com/wazuh/wazuh-qa/pull/5432)) \- (Framework)
- Add `Timestamp` field to the indexer statistics ([#5357](https://github.com/wazuh/wazuh-qa/pull/5357)) \- (Framework)
- Add `GeneratorVulnerabilityEvents` in agent simulator ([#5265](https://github.com/wazuh/wazuh-qa/pull/5265)) \- (Framework)
- Add functionality to obtain statistics and metrics from the indexer ([#5090](https://github.com/wazuh/wazuh-qa/pull/5090)) \- (Framework)
- Add support for the installation/uninstallation of npm packages ([#5092](https://github.com/wazuh/wazuh-qa/pull/5092)) \- (Tests)
- Add alert.json file to Vulnerability Detector E2E test report ([#5147](https://github.com/wazuh/wazuh-qa/pull/5147)) \- (Framework)
- Add documentation about markers for system tests ([#5080](https://github.com/wazuh/wazuh-qa/pull/5080)) \- (Documentation)
- Add AWS Custom Buckets Integration tests ([#4675](https://github.com/wazuh/wazuh-qa/pull/4675)) \- (Framework + Tests)
- Add Vulnerability Detector end to end tests ([#4878](https://github.com/wazuh/wazuh-qa/pull/4878)) \- (Framework + Tests)
- Agent Simulator: Syscollector message generation refactoring ([#4868](https://github.com/wazuh/wazuh-qa/pull/4868)) \- (Framework)
- Migrate Wazuh Ansibles Roles. ([#4642](https://github.com/wazuh/wazuh-qa/pull/4642)) \- (Framework)
- Add scans environment setup documentation. ([#4444](https://github.com/wazuh/wazuh-qa/pull/4444)) \- (Tests)
- Add system test for global group hash ([#4015](https://github.com/wazuh/wazuh-qa/pull/4015)) \- (Tests)
- Add tests for new FIM audit buffer option. ([#4485](https://githubhttps://github.com/wazuh/wazuh-qa/pull/4497#pullrequestreview-1654748331.com/wazuh/wazuh-qa/pull/4485)) \- (Framework + tests)
- Add tests for merged.mg file generation. ([#4129](https://github.com/wazuh/wazuh-qa/pull/4129)) \- (Tests)
- Added tests for checking agent status upon ungraceful closure.([#4146](https://github.com/wazuh/wazuh-qa/pull/4146)) \- (Tests)
- Agent syncronization testing after group deleting ([#4143](https://github.com/wazuh/wazuh-qa/pull/4143)) \- (Tests)
- Add test for AWS Custom Logs. ([#4675](https://github.com/wazuh/wazuh-qa/pull/4675)) \- (Tests)
- Add new behaviour for endpoints marked as xfail in api_endpoints_performance test ([#4657](https://github.com/wazuh/wazuh-qa/pull/4657)) \ (Tests)

### Changed

- Fix workload benchmark plots ([#5364](https://github.com/wazuh/wazuh-qa/pull/5364)) \- (Framework)
- Increase feed update time in Vulnerability Detection E2E tests to 10h ([#5424](https://github.com/wazuh/wazuh-qa/pull/5424)) \- (Tests)
- Migrate E2E Vulnerability Detector test packages to S3 repository ([#5376](https://github.com/wazuh/wazuh-qa/pull/5376)) \- (Framework)
- Include "Agent key already in use" in the E2E Vulnerability Detection expected error list. ([#5409](https://github.com/wazuh/wazuh-qa/pull/5409)) \- (Tests)
- Update vulnerability state index name ([#5402](https://github.com/wazuh/wazuh-qa/pull/5402)) \- (Framework)
- Include new package information from wdb ([#5350](https://github.com/wazuh/wazuh-qa/pull/5350)) \- (Tests)
- Disable debug evidences for Vulnerability Detector E2E tests by default ([#5331](https://github.com/wazuh/wazuh-qa/pull/5331)) \- (Tests)
- Include CVE-2023-4822 vulnerability to grafana packages ([#5332](https://github.com/wazuh/wazuh-qa/pull/5332)) \- (Framework)
- Remove sslverify from host manager install package method ([#5339](https://github.com/wazuh/wazuh-qa/pull/5339)) \- (Framework)
- Include additional Vulnerability Detector E2E tests ([#5287](https://github.com/wazuh/wazuh-qa/pull/5287)) \- (Framework + Tests)
- Change Vulnerability Detection feed updated waiter ([#5227](https://github.com/wazuh/wazuh-qa/pull/5227)) \- (Tests)
- Replace timestamp filter with vulnerabilities detected_at field.([#5266](https://github.com/wazuh/wazuh-qa/pull/5266)) \- (Framework + Tests)
- Changes macOS packages with new ones that generate vulnerabilities ([#5174](https://github.com/wazuh/wazuh-qa/pull/5174)) \- (Tests)
- Refactor initial scan Vulnerability E2E tests ([#5081](https://github.com/wazuh/wazuh-qa/pull/5081)) \- (Framework + Tests)
- Update Packages in TestScanSyscollectorCases ([#4997](https://github.com/wazuh/wazuh-qa/pull/4997)) \- (Framework + Tests)
- Reduced test_shutdown_message runtime ([#4986](https://github.com/wazuh/wazuh-qa/pull/4986)) \- (Tests)
- Change e2e vd configuration keystore ([#4952](https://github.com/wazuh/wazuh-qa/pull/4952)) \- (Framework)
- Updating tests after removing references to the legacy vulnerability detector module ([#4872](https://github.com/wazuh/wazuh-qa/pull/4872)) \- (Tests)
- Fix wazuhdb API statistics parsing ([#5007](https://github.com/wazuh/wazuh-qa/pull/5007)) \- (Framework)
- Enhance StatisticMonitor with API support ([#4970](https://github.com/wazuh/wazuh-qa/pull/4970)) \- (Framework)
- Deactivate tests and update vulnerability-detector configuration ([#4784](https://github.com/wazuh/wazuh-qa/pull/4784)) \- (Framework + Tests)
- Fix body format for get_api_token ([#4797](https://github.com/wazuh/wazuh-qa/pull/4797)) \- (Framework)
- Fix one_manager_agent_env pytest marker for System Tests ([#4782](https://github.com/wazuh/wazuh-qa/pull/4782)) \- (Tests)
- Updated Filebeat module to 0.4 ([#4775](https://github.com/wazuh/wazuh-qa/pull/4775)) \- (Framework)
- Include APT repository update before the installation of Ubuntu E2E agent installation ([#4761](https://github.com/wazuh/wazuh-qa/pull/4761)) \- (Framework)
- Enhance macOS deployment ansible taks ([#4685](https://github.com/wazuh/wazuh-qa/pull/4685)) \- (Framework)
- Updated Filebeat module to 0.3 ([#4700](https://github.com/wazuh/wazuh-qa/pull/4700)) \- (Framework)
- Change database v13 to v12. ([#4677](https://github.com/wazuh/wazuh-qa/pull/4677)) \- (Tests)
- Enable Windows Vulnerability Detector E2E. ([#4251](https://github.com/wazuh/wazuh-qa/pull/4251)) \- (Tests)
- Update certifi library due to a vulnerability. ([#4486](https://github.com/wazuh/wazuh-qa/pull/4486)) \- (Tests)
- Enable Ubuntu Vulnerability Detector E2E. ([#4252](https://github.com/wazuh/wazuh-qa/pull/4252)) \- (Tests)
- Update _wazuh_db_ schema database version ([#4353](https://github.com/wazuh/wazuh-qa/pull/4353)) \- (Tests)
- Update the JSON schema with the required fields for the output content of the migration tool ([#4375](https://github.com/wazuh/wazuh-qa/pull/4375)) \- (Tests)
- Update framework known flaws file ([#4443](https://github.com/wazuh/wazuh-qa/pull/4443)) \- (Tests)
- Align migration tool system tests to the tool's new output directory structure ([#4561](https://github.com/wazuh/wazuh-qa/pull/4561)) \- (Tests)
- Update the migration tool's system tests to match the new log file naming convention ([#4618](https://github.com/wazuh/wazuh-qa/pull/4618)) \- (Tests)
- Update file descriptors threshold values used in cluster performance tests ([#5073](https://github.com/wazuh/wazuh-qa/pull/5073)) \- (Tests)

### Fixed

- Set a stable `requets` version ([#5476](https://github.com/wazuh/wazuh-qa/pull/5476)) \- (Framework)
- Include logic to retry package installation if the lock file is currently in use ([#5421](https://github.com/wazuh/wazuh-qa/pull/5421)) \- (Framework)
- Increase E2E Vulnerability detection change manager test timeout ([#5414](https://github.com/wazuh/wazuh-qa/pull/5414)) \- (Tests)
- Fix filter vulnerabilities function in case of multiple packages are used ([#5419](https://github.com/wazuh/wazuh-qa/pull/5419)) \- (Framework)
- Remove false positive from E2E Vulnerability Detection tests ([#5369](https://github.com/wazuh/wazuh-qa/pull/5369)) \- (Framework)
- Fix multigroups guess system test ([#5396](https://github.com/wazuh/wazuh-qa/pull/5396)) \- (Tests)
- Fix hotfixes syscollector agent simulator messages ([#5379](https://github.com/wazuh/wazuh-qa/pull/5379)) \- (Framework)
- Fix restart agent in change manager Vulnerability Detector E2E test case ([#5355](https://github.com/wazuh/wazuh-qa/pull/5355)) \- (Tests)
- Fix E2E Vulnerability Detection Windows package installation error ([#5363](https://github.com/wazuh/wazuh-qa/pull/5363)) \- (Framework)
- Fix shutdown messages system test ([#5298](https://github.com/wazuh/wazuh-qa/pull/5298)) \- (Framework + Tests)
- Fix upgrade macOS package cases for vulnerability scanner E2E ([#5334](https://github.com/wazuh/wazuh-qa/pull/5334)) \- (Tests)
- Fix test cases in Vulnerability Detection E2E test by adding new packages ([#5349](https://github.com/wazuh/wazuh-qa/pull/5349)) \- (Tests)
- Fix macOS alert collection for E2E Vulnerability Detection tests ([#5337](https://github.com/wazuh/wazuh-qa/pull/5337)) \- (Framework)
- Fix packages in Windows and macOS upgrade cases ([#5223](https://github.com/wazuh/wazuh-qa/pull/5223)) \- (Framework + Tests)
- Fix vulnerabilities and add new packages to Vulnerability Detector E2E tests ([#5234](https://github.com/wazuh/wazuh-qa/pull/5234)) \- (Tests)
- Fix provision macOS endpoints with npm ([#5128](https://github.com/wazuh/wazuh-qa/pull/5158)) \- (Tests)
- Fix timestamps alerts and logs filter ([#5157](https://github.com/wazuh/wazuh-qa/pull/5157)) \- (Framework + Tests)
- Fix macOS and Windows agents timezone ([#5178](https://github.com/wazuh/wazuh-qa/pull/5178)) \- (Framework)
- Fix Vulnerability Detector E2E tests by adding description to all tests ([#5151](https://github.com/wazuh/wazuh-qa/pull/5151)) \- (Tests)
- Fix parser for non package vulnerabilities ([#5146](https://github.com/wazuh/wazuh-qa/pull/5146)) \- (Framework)
- Fix remote_operations_handler functions to Vulnerability Detector E2E tests ([#5155](https://github.com/wazuh/wazuh-qa/pull/5155)) \- (Framework)
- Fix enrollment cluster system tests ([#5134](https://github.com/wazuh/wazuh-qa/pull/5134)) \- (Tests)
- Fix `test_synchronization` system test ([#5089](https://github.com/wazuh/wazuh-qa/pull/5089)) \- (Framework + Tests)
- Fix number of files and their size for `test_zip_size_limit` ([#5133](https://github.com/wazuh/wazuh-qa/pull/5133)) \- (Tests)
- Fix test_shutdown_message system test ([#5087](https://github.com/wazuh/wazuh-qa/pull/5087)) \- (Tests)
- Include timeout to test_authd system tests ([#5083](https://github.com/wazuh/wazuh-qa/pull/5083)) \- (Tests)
- Fix Vulnerability Detection mismatch in scans ([#5053](https://github.com/wazuh/wazuh-qa/pull/5053)) \- (Tests)
- Fix agent groups tests for enrollment_cluster environment ([#5086](https://github.com/wazuh/wazuh-qa/pull/5086)) \- (Framework + Tests)
- Fix initial scans tests ([5032](https://github.com/wazuh/wazuh-qa/pull/5032)) \- (Framework + Tests)
- Handle VDT data missing in wazuh-db API ([5014](https://github.com/wazuh/wazuh-qa/pull/5014)) \- (Framework + Tests)
- Fixed x-axis labels in data-visualizer script ([#4987 ](https://github.com/wazuh/wazuh-qa/pull/4987)) \- (Framework)
- Fix monitoring module for e2e tests ([#4959](https://github.com/wazuh/wazuh-qa/pull/4959)) \- (Framework)
- Fix get_host_variables for system tests ([#4958](https://github.com/wazuh/wazuh-qa/pull/4958)) \- (Framework)
- Fix install package HostManager method ([#4954](https://github.com/wazuh/wazuh-qa/pull/4954)) \- (Framework)
- Fix Modify file method in system module ([#4953](https://github.com/wazuh/wazuh-qa/pull/4953)) \- (Framework)
- Fix timeout and performance issues in E2E Vulnerability Detector tests ([#5003](https://github.com/wazuh/wazuh-qa/pull/5003)) \- (Framework)
- Fixed Filebeat provisioning role with pre-release and staging URLs ([#4950](https://github.com/wazuh/wazuh-qa/pull/4950)) \- (Framework)
- Fix macOS Vulnerability Detection handler provision in E2E tests ([#4948](https://github.com/wazuh/wazuh-qa/pull/4948)) \- (Framework)
- Migrate Vulnerability Detection timeouts variables to the waiters module ([#4949](https://github.com/wazuh/wazuh-qa/pull/4949)) \- (Framework)
- Migrate HostMonitor to system_monitoring to avoid Windows import of ansible module ([#4917](https://github.com/wazuh/wazuh-qa/pull/4917/)) \- (Framework)
- Fixed ansible_runner import conditional to avoid errors on Windows and python 3.6 ([#4916](https://github.com/wazuh/wazuh-qa/pull/4916)) \- (Framework)
- Fixed IT control_service Windows loop ([#4765](https://github.com/wazuh/wazuh-qa/pull/4765)) \- (Framework)
- Fix macOS agents provision to enable registration and connection with managers. ([#4770](https://github.com/wazuh/wazuh-qa/pull/4770/)) \- (Framework)
- Fix hardcoded python interpreter in qa_framework role. ([#4658](https://github.com/wazuh/wazuh-qa/pull/4658)) \- (Framework)
- Fix duplicated jq dependency ([#4678](https://github.com/wazuh/wazuh-qa/pull/4678)) \- (Framework)
- Fix test_file_checker in check_mtime case ([#4873](https://github.com/wazuh/wazuh-qa/pull/4873)) \- (Tests)
- Fix test cluster performance. ([#4780](https://github.com/wazuh/wazuh-qa/pull/4780)) \- (Framework)
- Fixed the graphic generation for the logcollectord statistics files. ([#5021](https://github.com/wazuh/wazuh-qa/pull/5021)) \- (Framework)

## [4.7.5] - 31/05/2024

- No changes

## [4.7.4] - 29/04/2024

- No changes

## [4.7.3] - 04/03/2024

### Changed

- Upgrade wazuh-db agent database version. ([#4992](https://github.com/wazuh/wazuh-qa/pull/4992)) \- (Tests)

## [4.7.2] - 10/01/2024

### Fixed

- Fix the generation of syscollector events in the agent simulator class. ([#4773](https://github.com/wazuh/wazuh-qa/pull/4773)) \- (Framework)

## [4.7.1] - 20/12/2023

### Changed

- Remove deprecated message from cluster System Tests. ([#4740](https://github.com/wazuh/wazuh-qa/pull/4740)) \- (Tests)
- Enhance control_service error handling on windows agents. ([#4741](https://github.com/wazuh/wazuh-qa/pull/4741)) \- (Framework)
- Add XFAIL mark to Cluster reliability logs test. ([#4706](https://github.com/wazuh/wazuh-qa/pull/4706)) \- (Tests)

## [4.7.0] - 27/11/2023

### Added

- Add callbacks and IT tests for Integratord options tag. ([#4166](https://github.com/wazuh/wazuh-qa/pull/4166)) \- (Framework + tests)
- Add vulnerability Detector integration tests for Amazon Linux 2023 ([#4482](https://github.com/wazuh/wazuh-qa/pull/4482)) \- (Core)

### Changed

- Revert a pattern log in analysisd test ([#4688](https://github.com/wazuh/wazuh-qa/pull/4688)) \- (Framework)
- Clean environment between basic_cluster tests ([#4656](https://github.com/wazuh/wazuh-qa/pull/4656)) \- (Tests)
- Upgrade gcc version in system tests image ([#4655](https://github.com/wazuh/wazuh-qa/pull/4655)) \- (Framework)
- Add option to run some logcollector tests isolated (without a manager) ([#4226](https://github.com/wazuh/wazuh-qa/pull/4226)) \- (Tests + Framework)
- Update code analysis and dependencies known flaws. ([#4083](https://github.com/wazuh/wazuh-qa/pull/4083)) \- (Tests)
- Update _wazuh_db_ schema database version([#4405](https://github.com/wazuh/wazuh-qa/pull/4405)) \- (Tests)
- Update framework known flaws file ([#4313](https://github.com/wazuh/wazuh-qa/pull/4313)) \- (Tests)

### Fixed

- Deprecate source installation in System Tests ([#4686](https://github.com/wazuh/wazuh-qa/pull/4686)) \- (Framework)
- Update default vacuum settings in IT ([#4671](https://github.com/wazuh/wazuh-qa/pull/4671)) \- (Tests)
- Fix registry wildcards path ([#4400](https://github.com/wazuh/wazuh-qa/pull/4400)) \- (Tests)
- Fix warnings in the rids tests([#4151](https://github.com/wazuh/wazuh-qa/pull/4151)) \- (Framework + Tests)

## [4.6.0] - 31/10/2023

### Added

- Add EC2 information for system tests. ([#4536](https://github.com/wazuh/wazuh-qa/pull/4536)) \- (Documentation)
- Add Debian Bookworm VDT IT support. ([#4463](https://github.com/wazuh/wazuh-qa/pull/4463)) \- (Tests)
- Add new test cases for the `discard_regex` functionality of `CloudWatchLogs` and `Inspector` services. ([#4278](https://github.com/wazuh/wazuh-qa/pull/4278)) \- (Tests)
- Add Windows location wildcards tests ([#4263](https://github.com/wazuh/wazuh-qa/pull/4263)) \- (Tests + Framework)
- New 'SCA' test suite and framework. ([#3566](https://github.com/wazuh/wazuh-qa/pull/3566)) \- (Framework + Tests)
- Add integration tests for AWS module. ([#3911](https://github.com/wazuh/wazuh-qa/pull/3911)) \- (Framework + Tests + Documentation)
- Add tests for msu patches with no associated CVE . ([#4009](https://github.com/wazuh/wazuh-qa/pull/4009)) \- (Framework + Tests)
- Add tests with new options to avoid FIM synchronization overlapping. ([#3318](https://github.com/wazuh/wazuh-qa/pull/3318)) \- (Framework + tests)
- Add Logcollector millisecond granularity support test case ([#3910](https://github.com/wazuh/wazuh-qa/pull/3910)) \- (Tests)
- Add Windows System folders FIM monitoring tests ([#3720](https://github.com/wazuh/wazuh-qa/pull/3720)) \- (Tests)
- Add 'test_whodata_policy_changes' tests ([#3627](https://github.com/wazuh/wazuh-qa/pull/3627)) \- (Framework + Tests)
- Add test to check if active-response netsh generates alerts when firewall is disabled. ([#3787](https://github.com/wazuh/wazuh-qa/pull/3787)) \- (Framework + Tests)
- Add new tests for logcollector 'ignore' and 'restrict' options ([#3582](https://github.com/wazuh/wazuh-qa/pull/3582)) \- (Tests)
- Add 'Force reconnect' feature to agent_simulator tool. ([#3111](https://github.com/wazuh/wazuh-qa/pull/3111)) \- (Tools)
- Add new module to support migration tool. ([#3837](https://github.com/wazuh/wazuh-qa/pull/3837))
- Add IT tests FIM registry monitoring using wildcards. ([#4270](https://github.com/wazuh/wazuh-qa/pull/4270)) \- (Framework + Tests)
- Update schema database version ([#4128](https://github.com/wazuh/wazuh-qa/pull/4128)) \- (Tests)
- Update framework known flaws files ([#4380](https://github.com/wazuh/wazuh-qa/pull/4380)) \- (Tests)
- Add tests for Vulnerability Detector: Red Hat 9 support ([#4497](https://github.com/wazuh/wazuh-qa/pull/4497)) \- (Tests)
- Add AlmaLinux VDT IT support ([#4376](https://github.com/wazuh/wazuh-qa/pull/4376)) \- (Tests)
- Add new FIM test to verify checks in configuration ([#4373](https://github.com/wazuh/wazuh-qa/pull/4373)) \- (Tests)

### Changed

- Change expected database version ([#5111](https://github.com/wazuh/wazuh-qa/pull/5111)) \- (Tests)
- `Agentless_cluster` system tests timeout changed in order to reduce EC2 requirements ([#4534](https://github.com/wazuh/wazuh-qa/pull/4534)) \- (Tests)
- Skip `test_authd_ssl_options` cases that use TLS 1.1 causing errors on several OpenSSL versions. ([#4229](https://github.com/wazuh/wazuh-qa/pull/4229)) \- (Tests)
- Update database version ([#4467](https://github.com/wazuh/wazuh-qa/pull/4467)) \- (Tests)
- Remove versionStartIncluding from NVD custom feed ([#4441](https://github.com/wazuh/wazuh-qa/pull/4441)) \- (Tests)
- Updated syscollector wmodules prefix ([#4384](https://github.com/wazuh/wazuh-qa/pull/4384)) \- (Framework)
- Replace embedded python invocations with generic `python3`. ([#4186](https://github.com/wazuh/wazuh-qa/pull/4186)) - (Tests)
- Fix FIM test_large_changes test suite ([#3948](https://github.com/wazuh/wazuh-qa/pull/3948)) \- (Tests)
- Update `get_test_cases_data` function so it handles fim_mode parameter ([#4185](https://github.com/wazuh/wazuh-qa/pull/4185)) \- (Framework)
- Change FIM `regular_file_cud` and `EventChecker` file modification steps ([#4183](https://github.com/wazuh/wazuh-qa/pull/4183)) \- (Framework + Tests)
- Refactor library to change the environment ([#4145](https://github.com/wazuh/wazuh-qa/pull/4145)) \- (Framework)
- Improve the way that environment data is managed ([#4059](https://github.com/wazuh/wazuh-qa/pull/4059)) \- (Framework)
- Update FIM test_ambiguous_confs IT to new framework ([#4121](https://github.com/wazuh/wazuh-qa/pull/4121)) \- (Tests + Framework)
- Update `test_logcollector` invalid configs log level ([#4094](https://github.com/wazuh/wazuh-qa/pull/4094)) \- (Tests)
- Update `test_office365` to support the new tag `API_TYPE` ([#4065](https://github.com/wazuh/wazuh-qa/pull/4065)) \- (Framework + Tests)
- Update `test_wazuh_db` & `test_enrollment` to support new column `status_code` and new value on the enrollment `payload`. ([#4021](https://github.com/wazuh/wazuh-qa/pull/4021)) \- (Tests)
- Update FIM `test_audit` tests to new framework ([#3939](https://github.com/wazuh/wazuh-qa/pull/3939)) \- (Framework + Tests)
- Update FIM test to new FIM DBSync process  ([#2728](https://github.com/wazuh/wazuh-qa/pull/2728)) \- (Framework + Tests)
- Update file_limit and registry_limit tests ([#3280](https://github.com/wazuh/wazuh-qa/pull/3280)) \- (Tests)
- Change expected timestamp for proftpd analysisd test predecoder test case ([#3900](https://github.com/wazuh/wazuh-qa/pull/3900)) \- (Tests)
- Skip test_large_changes test module ([#3783](https://github.com/wazuh/wazuh-qa/pull/3783)) \- (Tests)
- Update report_changes tests ([#3405](https://github.com/wazuh/wazuh-qa/pull/3405)) \- (Tests)
- Update Authd force_insert tests ([#3379](https://github.com/wazuh/wazuh-qa/pull/3379)) \- (Tests)
- Update cluster logs in reliability tests ([#2772](https://github.com/wazuh/wazuh-qa/pull/2772)) \- (Tests)
- Use correct version format in agent_simulator tool ([#3198](https://github.com/wazuh/wazuh-qa/pull/3198)) \- (Tools)
- Upgrade PyYAML to 6.0.1. ([#4326](https://github.com/wazuh/wazuh-qa/pull/4326)) \- (Framework)
- Update schema database version ([#4128](https://github.com/wazuh/wazuh-qa/pull/4128)) \- (Tests)
- Update framework known flaws files ([#4380](https://github.com/wazuh/wazuh-qa/pull/4380)) \- (Tests)

### Fixed

- Fix Integration Test FIM tests skip marks changed ([#4569] (https://github.com/wazuh/wazuh-qa/pull/4569)) \- (Tests)
- Fix invalid AR conf in integration tests ([#4521](https://github.com/wazuh/wazuh-qa/pull/4521)) \- (Tests)
- Fix an error in AR library and test ([#4511](https://github.com/wazuh/wazuh-qa/pull/4511)) \- (Framework + Tests)
- Fix provisioned pytest failure fixed ([#4520](https://github.com/wazuh/wazuh-qa/pull/4520)) \- (Framework)
- Fix FIM framework to validate path in event correctly ([#4390](https://github.com/wazuh/wazuh-qa/pull/4390)) \- (Framework)
- Fix an error related to logs format in reliability test ([#4387](https://github.com/wazuh/wazuh-qa/pull/4387)) \- (Tests)
- Fix boto3 version requirement for legacy OS ([#4150](https://github.com/wazuh/wazuh-qa/pull/4150)) \- (Framework)
- Fix cases yaml of the analysisd windows registry IT ([#4149](https://github.com/wazuh/wazuh-qa/pull/4149)) \- (Tests)
- Fix a bug in on Migration tool's library ([#4106](https://github.com/wazuh/wazuh-qa/pull/4106)) \- (Framework)
- Fix imports and add windows support for test_report_changes_and_diff IT ([#3548](https://github.com/wazuh/wazuh-qa/issues/3548)) \- (Framework + Tests)
- Fix a regex error in the FIM integration tests ([#3061](https://github.com/wazuh/wazuh-qa/issues/3061)) \- (Framework + Tests)
- Fix an error in the cluster performance tests related to CSV parser ([#2999](https://github.com/wazuh/wazuh-qa/pull/2999)) \- (Framework + Tests)
- Fix bug in the framework on migration tool ([#4027](https://github.com/wazuh/wazuh-qa/pull/4027)) \- (Framework)
- Fix test cluster / integrity sync system test and configuration to avoid flaky behavior ([#4406](https://github.com/wazuh/wazuh-qa/pull/4406)) \- (Tests)
- Fix misspelling regex and error in test_cluster_connection ([#4392](https://github.com/wazuh/wazuh-qa/pull/4392)) \- (Tests)
- Fix test validate feed content - Canonical ([#4381](https://github.com/wazuh/wazuh-qa/pull/4381)) \- (Tests)
- Fix flaky test in AR suite (excecd) ([#4360](https://github.com/wazuh/wazuh-qa/pull/4360)) \- (Tests)
- Fix registry wildcards path ([#4357](https://github.com/wazuh/wazuh-qa/pull/4357)) \- (Tests)

## [4.5.4] - 24/10/2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/48870c11207b1f0ba20ae29688d75564bfc04489 \
Release report: https://github.com/wazuh/wazuh/issues/19764

## [4.5.3] - 10/10/2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/388ce54b704d7b6aa2dda1b30258ad1642b26a2d \
Release report: https://github.com/wazuh/wazuh/issues/19446

### Changed

- Update the cluster master logs reliability test to run with python 3.7 [#4445](https://github.com/wazuh/wazuh-qa/pull/4478) \- (Tests)
- Update ITs URL for SUSE OVAL ([#4496](https://github.com/wazuh/wazuh-qa/pull/4496/))

### Fixed

- Fix enrollment system tests ([#4562](https://github.com/wazuh/wazuh-qa/pull/4562/)) \- (Tests)
- Update the request method used to call the login API endpoint. ([#4492](https://github.com/wazuh/wazuh-qa/pull/4492)) \- (Tests)
- Enhancing the handling of authd and remoted simulators in case of restart failures ([#Wazuh-jenkins#3487](https://github.com/wazuh/wazuh-qa/pull/4205)) \- (Tests)
- Fix py dependency version to install for Windows after the change to Python 3.11([#4523](https://github.com/wazuh/wazuh-qa/pull/4523)) \- (Framework)

## [4.5.2] - 06-08-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/2efea7428ad34bce8ea0bd32d56b5faccad114a6 \
Release report: https://github.com/wazuh/wazuh/issues/18794

### Changed

- Update ITs URL for Debian OVAL ([#4491](https://github.com/wazuh/wazuh-qa/pull/4491)) \- (Tests)
- Syscollector package inventory deltas fix ([#4483](https://github.com/wazuh/wazuh-qa/pull/4483)) \- (Tests)
- Update schema sys_programs table ([#4451](https://github.com/wazuh/wazuh-qa/pull/4451)) \- (Tests)
- Update enrollment logs in system test ([#4442](https://github.com/wazuh/wazuh-qa/pull/4442)) \- (Tests)
- Fix one_manager_agent environment provisioning by packages for system tests ([#4438](https://github.com/wazuh/wazuh-qa/pull/4438)) \- (Framework)
- Update framework known flaws files ([#4379](https://github.com/wazuh/wazuh-qa/pull/4379)) \- (Tests)

### Fixed

- Minor fixes in the `tests_python_flaws.py` scan ([#4439](https://github.com/wazuh/wazuh-qa/pull/4439)) \- (Tests)

## [4.5.1] - 24-08-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/731cdf39a430d2fb6fa02f3721624e07f887b02f
Release report: https://github.com/wazuh/wazuh/issues/18475

### Added

- Add an integration test to check the wazuh-analysisd's decoder parser ([#4286](https://github.com/wazuh/wazuh-qa/pull/4286)) \- (Tests)

### Changed

- Update python integration test dependencies in the README ([#4427](https://github.com/wazuh/wazuh-qa/pull/4427)) \- (Documentation)
- Update vulnerability detector IT outdated URLs ([#4428](https://github.com/wazuh/wazuh-qa/pull/4428)) \- (Tests)

## [4.5.0] - 11-08-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/f6aba151d08ef065dfc1bdc9b8885c3d4f618fca
Release report: https://github.com/wazuh/wazuh/issues/18235

### Changed

- Delete `update_from_year` from system and E2E tests configuration ([#4372](https://github.com/wazuh/wazuh-qa/pull/4372)) \- (Tests)
- Upgrade PyYAML to 6.0.1. ([#4326](https://github.com/wazuh/wazuh-qa/pull/4326)) \- (Framework)
- Change Vulnerability Detector ITs to support the development of the NVD 2.0 refactor. ([#4327](https://github.com/wazuh/wazuh-qa/pull/4327)) \- (Tests)

## [4.4.5] - 10-07-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/8d17d2c9c11bc10be9a31c83bc7c17dfbac0d2a0 \
Release report: https://github.com/wazuh/wazuh/issues/17844

## [4.4.4] - 13-06-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/32b9b4684efb7c21ce71f80d845096549a5b4ed5  \
Release report: https://github.com/wazuh/wazuh/issues/17520

### Added

- Change test_python_flaws.py to accept branch or commit in the same argument. ([#4209](https://github.com/wazuh/wazuh-qa/pull/4209)) \- (Tests)
- Fix test_dependencies.py for the changes in the feature. ([#4210](https://github.com/wazuh/wazuh-qa/pull/4210)) \- (Tests)

### Fixed

- Fix syscollector tests failure (get_configuration fixture has different scope) ([#4154](https://github.com/wazuh/wazuh-qa/pull/4154)) \- (Framework + Tests)

## [4.4.3] - 25-06-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/f7080df56081adaeaad94529522233e2f0bbd577 \
Release report: https://github.com/wazuh/wazuh/issues/17198

### Fixed

- Fix missing comma in setup.py. ([#4180](https://github.com/wazuh/wazuh-qa/pull/4180)) (Framework)
- Changed the last uses of 4.4.2 in setup.py and schema.yaml. ([#4172](https://github.com/wazuh/wazuh-qa/pull/4172)) \- (Framework)

## [4.4.2] - 18-05-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/b2901d5086e7a073d89f4f72827e070ce3abd8e8 \
Release report: https://github.com/wazuh/wazuh/issues/17004

### Added

- Add package support for system tests ([#3965](https://github.com/wazuh/wazuh-qa/pull/3966)) \- (Framework)
- Add test to check the Syscollector configuration. ([#3584](https://github.com/wazuh/wazuh-qa/pull/3584)) \- (Framework + Tests)
- Add system tests for groups deletion ([#4057](https://github.com/wazuh/wazuh-qa/pull/4057)) \- (Tests)

### Changed

- Change integratord test to use slack instead of virustotal ([#3540](https://github.com/wazuh/wazuh-qa/pull/3540)) \- (Framework + Tests)

### Fixed

- Stabilize multiple wday tests (GCloud integration) ([#4176](https://github.com/wazuh/wazuh-qa/pull/4176)) \- (Tests)
- Remove old XFail marker (API suite) ([#4177](https://github.com/wazuh/wazuh-qa/pull/4177)) \- (Tests)
- Mark VD download feeds test as xfail ([#4197](https://github.com/wazuh/wazuh-qa/pull/4197)) \- (Tests)
- Skip test_age_datetime_changed ([#4182](https://github.com/wazuh/wazuh-qa/pull/4182)) \- (Tests)
- Limit urllib3 major required version ([#4162](https://github.com/wazuh/wazuh-qa/pull/4162)) \- (Framework)
- Fix daemons_handler fixture (fix GCP IT) ([#4134](https://github.com/wazuh/wazuh-qa/pull/4134)) \- (Tests)
- Fix wazuhdb IT. ([#3584](https://github.com/wazuh/wazuh-qa/pull/3584)) \- (Framework + Tests)
- Fix agentd IT for python3.10 AMI ([#3973](https://github.com/wazuh/wazuh-qa/pull/3973)) \- (Tests)
- Fix unstable system tests ([#4080](https://github.com/wazuh/wazuh-qa/pull/4080)) \- (Tests)

### Changed

- Modify authd ITs test_authd_valid_name_ip to avoid flackyness. ([#4164](https://github.com/wazuh/wazuh-qa/pull/4164)) \- (Tests)

## [4.4.1] - 12-04-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/63a0580562007c4ba9c117f4a232ce90160481ff \
Release report: https://github.com/wazuh/wazuh/issues/16620

## [4.4.0] - 28-03-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/2477e9fa50bc1424e834ac8401ce2450a5978e75 \
Release report: https://github.com/wazuh/wazuh/issues/15504

### Added

- Add new integration test for `authd` to validate error when `authd.pass` is empty ([#3721](https://github.com/wazuh/wazuh-qa/pull/3721)) \- (Framework + Tests)
- Add new test to check missing fields in `cpe_helper.json` file ([#3766](https://github.com/wazuh/wazuh-qa/pull/3766)) \- (Framework + Tests)
- Add multigroups tests cases for `test_assign_groups_guess` ([#3979](https://github.com/wazuh/wazuh-qa/pull/3979)) \- (Tests)
- Add new group_hash case and update the `without condition` case output in `wazuh_db/sync_agent_groups_get` ([#3959](https://github.com/wazuh/wazuh-qa/pull/3959)) \- (Tests)
- Add markers for each system test environment ([#3961](https://github.com/wazuh/wazuh-qa/pull/3961)) \- (Framework + Tests)
- Adapt binary performance module to wazuh-cluster script renaming ([#3944](https://github.com/wazuh/wazuh-qa/pull/3944)) \- (Framework)
- Add an option to store logs in system tests ([#2445](https://github.com/wazuh/wazuh-qa/pull/2445)) \- (Framework + Tests)
- Add new test to check cpe_helper.json file ([#3731](https://github.com/wazuh/wazuh-qa/pull/3731))
- Add integration test to check statistics format ([#3813](https://github.com/wazuh/wazuh-qa/pull/3813)) \- (Framework + Tests)
- Add new test to check vulnerable packages with triaged null([#3587](https://github.com/wazuh/wazuh-qa/pull/3587)) \- (Framework + Tests)
- Add new tests analysid handling of invalid/empty rule signature IDs ([#3649](https://github.com/wazuh/wazuh-qa/pull/3649)) \- (Framework + Tests)
- Add integration test to check agent database version ([#3768](https://github.com/wazuh/wazuh-qa/pull/3768)) \- (Tests)
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

- Improve `test_agent_groups_new_cluster_node` ([#3971](https://github.com/wazuh/wazuh-qa/pull/3971)) \- (Tests)
- Improve `test_assign_groups_guess` ([#3901](https://github.com/wazuh/wazuh-qa/pull/3901)) \- (Tests)
- Update `test_cluster_worker_logs_order` test ([#3896](https://github.com/wazuh/wazuh-qa/pull/3896)) \- (Tests)
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
- Refactor ITs related to syscollector deltas alerts ([#3579](https://github.com/wazuh/wazuh-qa/pull/3579)) \- (Tests)

### Fixed

- Fix `test_assign_agent_group_with_enrollment` ([#3956](https://github.com/wazuh/wazuh-qa/pull/3956)) \- (Tests)
- Fix `test_file_limit_delete_full` module ([#3990](https://github.com/wazuh/wazuh-qa/pull/3990)) \- (Tests)
- Fix test_agent_groups system test ([#3955](https://github.com/wazuh/wazuh-qa/pull/3964)) \- (Tests)
- Fix Solaris agent provision schema ([#3750](https://github.com/wazuh/wazuh-qa/issues/3744)) \- (Framework)
- Fix wazuh-db integration tests for agent-groups ([#3926](https://github.com/wazuh/wazuh-qa/pull/3926)) \- (Tests + Framework)
- Fix `test_set_agent_groups` ([#3920](https://github.com/wazuh/wazuh-qa/pull/3920)) \- (Tests)
- Fix test_sync_agent_groups_get, replace hardcoded hash to a dinamically calculated one ([#3895](https://github.com/wazuh/wazuh-qa/pull/3895)) \- (Framework + Tests)
- Fix `test_agent_groups` ([#3889](https://github.com/wazuh/wazuh-qa/pull/3889)) \- (Tests + Framework)
- Fix test_db_backup for Ubuntu OS ([#3802](https://github.com/wazuh/wazuh-qa/pull/3802)) \- (Tests)
- Fix Yara and VirusTotal E2E basic usage tests ([#3660](https://github.com/wazuh/wazuh-qa/pull/3660)) \- (Tests)
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
- Fix test_response_postprocessing: duplicated slash in API endpoints ([#4048](https://github.com/wazuh/wazuh-qa/pull/4048)) \- (Tests)

### Removed

- Remove all FIM Integration skipped tests ([#2927](https://github.com/wazuh/wazuh-qa/issues/2927)) \- (Framework + Tests)
- VDT ITs: Remove Debian Stretch test support. ([#3172](https://github.com/wazuh/wazuh-qa/pull/3172)) \- (Tests)

## [4.3.11] - 20-04-2023

Wazuh commit: https://github.com/wazuh/wazuh/commit/776fda906581a1e4ee170c3e7e73a58d69e41f95 \
Release report: https://github.com/wazuh/wazuh/issues/16758

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

### Changed

- Update wazuh-logtest messages for integration tests \- (Tests)

## [4.3.7] - 24-08-2022

Wazuh commit: https://github.com/wazuh/wazuh/commit/e2b514bef3d148acd4bcae1a1c7fa8783b82ca3a \
Release report: https://github.com/wazuh/wazuh/issues/14562

### Added
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
