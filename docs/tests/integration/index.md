
# Overview

Our newest integration tests are located in `wazuh-qa/tests/integration/`. They are organized by capabilities:

- _test_analysisd_
- _test_api_
- _test_cluster_
- _test_fim_
- _test_gcloud_
- _test_mitre_
- _test_sca_
- **[_test_remoted_](test_remoted#test_remoted)**
- **[_test_vulnerability_detector_](test_vulnerability_detector#tests-vulnerability-detector)**
- _test_wazuh_db_

## How to setup the test environment

To run the tests you need to have `python3 >= 3.6` installed along with a set of additional dependencies.

You can see all the information about it **[here](set_up_environment.md#setting-up-a-test-environment)**

##  About test structure

See **[here](help.md#integration-tests-structure)** more information about the testing files structure or about `pytest`
testing framework.
