# wazuh-qa

Wazuh - System quality assurance automation templates

## Setting up a test environment

To run these tests we need to use a **Linux** machine with direct connection to another machine with Wazuh installed.

### Dependencies

In addition, we need the `wazuh-testing` package in addition to the default requirements from this repository.

## Performance API tests

These tests are designed to work on another machine to test our API endpoints on custom environments, such as a loaded Wazuh cluster.

#### conftest

The conftest is prepared to accept the `--html=report.html` option to generate an HTML report with useful information.

#### data

Folder which includes the configuration that will be applied to the test. This includes connection information in addition to the request template.

##### configuration.yaml

```yaml
---
configuration:
  host: 'localhost'
  port: 55000
  restart_delay: 30

test_cases:
  - endpoint: /agents
    method: post
    parameters: {}
    body:
      name: "new_test_agent"
      ip: "any"
      
  - endpoint: /cluster/restart
    method: put
    parameters: {}
    body: {}
    restart: True

  ( ... )

```

**Configuration**
- **host**: Host IP or name to make the requests to.
- **port**: Wazuh API port.
- **restart_delay**: Delay in seconds to apply after endpoints that may restart an agent or manager.

**Test cases**
- **endpoint**: API endpoint.
- **method**: Method to apply to the request.
- **parameters**: Parameters to add to the request (dict format).
- **body**: Body to add to the request (dict format).
- **restart (optional)**: On `PUT` endpoints, this option must be added to define if there will be a delay after that test passes.

### Pytest

These tests will be run with `pytest`. You can apply any of the pytest options, but it is recommended to add the following at least:
- **--html=report.html**: Generate an HTML report with useful information about the tests.
- **--disable-warnings**: Hide test warnings (`requests` module will generate some warnings as we are doing unverified requests).

An example would be the following:

```shell script
root@wazuh-test-master:/wazuh-qa/tests/performance# python3 -m pytest test_api/test_api.py --self-contained-html --disable-warnings
```
