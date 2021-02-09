# SCA tests

These tests are not part of the current testing framework for Wazuh, so they have to be executed manually. The necessary
instructions are described below.

## Introduction
---------------

A brief knowledge of SCA is recommended, the documentation covers it in detail
in [How SCA works](https://documentation.wazuh.com/4.2/user-manual/capabilities/sec-config-assessment/how_it_works.html)
. Also, there is a blog post
about [Security Configuration Assessment](https://wazuh.com/blog/security-configuration-assessment/).

Basically, the tests inside **data** folder contain different _.yml_ policies that will test the general capabilities
of **SCA**. It will be necessary to install a Manager and register an agent. There is more information about this part
of the process in the [Installation Guide](https://documentation.wazuh.com/4.0/installation-guide/index.html).

## Directory structure
----------------------

    ├── test_basic_usage/data
    │ ├── sca_commands_test_suite.yml
    │ ├── sca_compare_test_suite.yml
    │ ├── sca_condition_test_suite.yml
    │ ├── sca_directories_test_suite.yml
    │ ├── sca_files_test_suite.yml
    │ ├── sca_negation_test_suite.yml
    │ ├── sca_processes_test_suite.yml
    │ ├── sca_repeated_global_ids_1.yml     # Will be skipped
    │ ├── sca_repeated_global_ids_2.yml     # Will be skipped
    │ ├── sca_repeated_local.yml            # Will be skipped
    │ ├── sca_win_registry_test_suite.yml
    │ ├── set_linux_config_to_compliance.sh # Script to improve the SCA score
    |
    ├── README.md

## Test execution
-----------------

The **SCA** module has to be enabled in the agent

```
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>
```

And the test policies have to copied to __INSTALL_DIR/ruleset/sca__. Then, restart the agent to force the policy
evaluation.

## Results
----------

The agent will log to __ossec.log__ these type of messages

```
 sca: INFO: Starting evaluation of policy: 'policy.yml'
 sca: INFO: Evaluation finished for policy: 'policy.yml'
```

Some scans will not be performed, because there are some policies that have the same ID on purpose to test this
situation. For example:

```
sca: WARNING: Found duplicated check ID: 200100. First appearance at policy 'sca_files_test_suite'
sca: WARNING: Error found while validating policy file: '/var/ossec/ruleset/sca/sca_repeated_global_ids_1.yml'. Skipping it.
```

After all the scans finish, the results can be checked in the manager with this API request

```
curl -k -X GET "https://localhost:55000/sca/001?pretty=true" -H "Authorization: Bearer $TOKEN"
```

```
    ...
    {
        "invalid": 6,
        "total_checks": 24,
        "fail": 11,
        "references": "NULL",
        "description": "This document includes file rules for testing purposes with the syntax rule of Wazuh v3.10.0",
        "start_scan": "2020-12-22T20:16:26Z",
        "hash_file": "8688d6b8ae1828f9512d3dc9b68b904d8d08cde1f8709d76cdb9954f382656f2",
        "name": "Test suite for conditions.",
        "pass": 7,
        "policy_id": "sca_condition_test_suite",
        "score": 38,
        "end_scan": "2020-12-22T20:16:26Z"
    },
    ...
```

The scan results and those described in the test must be equal

```
...
    policy:
    id: sca_condition_test_suite
    file: sca_condition_test_suite.yml
    name: Test suite for conditions.
    description: This document includes file rules for testing purposes with the syntax rule of Wazuh v3.10.0
    ############### Expected results
    # Pass = 7
    # Fail = 11
    # Invalid = 6
    # Total checks = 24
...
```

## Compliance script
--------------------

The _set_linux_config_to_compliance.sh_ script modifies some configurations in a Linux environment to improve the tests
scores for policies like _cis_debian9_L1.yml_ and _cis_debian9_L2.yml_.
