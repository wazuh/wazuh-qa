# Provision module Unit Testing using Pytest

The provision module includes pytest unit tests.

## Requirements

- Make sure you have Python installed on your system. You can download it from [python.org](https://www.python.org/downloads/).
- Clone the wazuh-qa repository in your local environment.
- Install the necessary dependencies by running:
```bash
git clone https://github.com/wazuh/wazuh-qa.git -b [your-branch]
cd wazuh-qa
pip install -r deployability/deps/requirements.txt
pip install -r deployability/deps/remote_requirements.txt
```
- Configure the `PYTHONPATH` variable with the full path to the directory `deployability`, for example if you've
cloned the `wazuh-qa` repository into `/wazuh/wazuh-qa`, configure the `PYTHONPATH` in this way:
```bash
> pwd
/wazuh/wazuh-qa
> export PYTHONPATH=$PYTHONPATH:$PWD/deployability
> echo $PYTHONPATH
/wazuh/wazuh-qa/deployability
```

## Test Structure
The directory `deployability/modules/provision/tests/` contains the unit test files for the `provision` module.

## Running Tests
To run the tests, make sure that your system meets the requirements by executing the following command from the project
root:

```bash
pytest -vv deployability/modules/provision
```
This command will run all tests in the `tests/` directory.  Using additional arguments, you can also run specific tests
or directories. The output of this command looks like this:
```bash
pytest -vv deployability/modules/provision/
=================================================================================== test session starts ===================================================================================
platform linux -- Python 3.10.13, pytest-8.0.1, pluggy-1.4.0 -- /home/marcelo/.pyenv/versions/wazuh-qa/bin/python
cachedir: .pytest_cache
rootdir: /home/marcelo/wazuh/wazuh-qa/deployability/modules
collected 51 items

deployability/modules/provision/tests/test_actions.py::test_action_constructor[install-package0] PASSED                                                                             [  1%]
deployability/modules/provision/tests/test_actions.py::test_action_constructor[install-package1] PASSED                                                                             [  3%]
deployability/modules/provision/tests/test_actions.py::test_action_constructor[install-source] PASSED                                                                               [  5%]
deployability/modules/provision/tests/test_actions.py::test_action_execute[logger_mock0] PASSED                                                                                     [  7%]
deployability/modules/provision/tests/test_actions.py::test_action_get_os_family[logger_mock0] PASSED                                                                               [  9%]
deployability/modules/provision/tests/test_actions.py::test_provision_handler_get_playbook PASSED                                                                                   [ 11%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor[logger_mock0-wazuh-manager-install-package] PASSED                                        [ 13%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor[logger_mock0-wazuh-manager-install-assistant] PASSED                                      [ 15%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor[logger_mock0-wazuh-manager-install-source] PASSED                                         [ 17%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor[logger_mock0-wazuh-manager-uninstall-package] PASSED                                      [ 19%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor[logger_mock0-wazuh-manager-uninstall-assistant] PASSED                                    [ 21%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor[logger_mock0-wazuh-manager-uninstall-source] PASSED                                       [ 23%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor[logger_mock0-wazuh-agent-uninstall-source] PASSED                                         [ 25%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor[logger_mock0-wazuh-agent-uninstall-assistant] PASSED                                      [ 27%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor_fail[wazuh-manager-INSTALL-package-Unsupported action: INSTALL] PASSED                    [ 29%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor_fail[wazuh-manager-UNINSTALL-assistant-Unsupported action: UNINSTALL] PASSED              [ 31%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor_fail[wazuh-manager-other-source-Unsupported action: other] PASSED                         [ 33%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor_fail[wazuh-manager-uninstall-other-Unsupported method: other] PASSED                      [ 35%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_constructor_fail[indexer-uninstall-assistant-Assistant actions is only supported for Wazuh components.] PASSED [ 37%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_get_templates_path[wazuh-manager-package-install] PASSED                                              [ 39%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_get_templates_path[wazuh-manager-assistant-uninstall] PASSED                                          [ 41%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_get_templates_path[indexer-source-install] PASSED                                                     [ 43%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_get_templates_order[wazuh-manager-package-install-expected_list0] PASSED                              [ 45%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_get_templates_order[indexer-source-install-expected_list1] PASSED                                     [ 47%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_get_templates_order[wazuh-manager-assistant-uninstall-expected_list2] PASSED                          [ 49%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_get_templates_order_fail PASSED                                                                       [ 50%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_generate_dict[wazuh-manager-package-install] PASSED                                                   [ 52%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_generate_dict[wazuh-manager-assistant-uninstall] PASSED                                               [ 54%]
deployability/modules/provision/tests/test_handler.py::test_provision_handler_generate_dict[indexer-source-install] PASSED                                                          [ 56%]
deployability/modules/provision/tests/test_models.py::test_input_payload_constructor_components[True] PASSED                                                                        [ 58%]
deployability/modules/provision/tests/test_models.py::test_input_payload_constructor_components[False] PASSED                                                                       [ 60%]
deployability/modules/provision/tests/test_models.py::test_input_payload_constructor_dependencies[None] PASSED                                                                      [ 62%]
deployability/modules/provision/tests/test_models.py::test_input_payload_constructor_dependencies[dependencies1] PASSED                                                             [ 64%]
deployability/modules/provision/tests/test_models.py::test_input_payload_constructor_dependencies[[{'manager': 'path/to/inventory.yaml', 'agent': 'path/to/inventory.yaml'}]] PASSED [ 66%]
deployability/modules/provision/tests/test_models.py::test_input_payload_constructor_fail PASSED                                                                                    [ 68%]
deployability/modules/provision/tests/test_provision.py::test_provision_constructor PASSED                                                                                          [ 70%]
deployability/modules/provision/tests/test_provision.py::test_provision_run[logger_mock0-provision_mock0-stats0] PASSED                                                             [ 72%]
deployability/modules/provision/tests/test_provision.py::test_provision_run_fail[logger_mock0-provision_mock0] PASSED                                                               [ 74%]
deployability/modules/provision/tests/test_provision.py::test_provision_get_components[provision_mock0-True] PASSED                                                                 [ 76%]
deployability/modules/provision/tests/test_provision.py::test_provision_get_components[provision_mock1-False] PASSED                                                                [ 78%]
deployability/modules/provision/tests/test_provision.py::test_provision_update_status[provision_mock0] PASSED                                                                       [ 80%]
deployability/modules/provision/tests/test_provision.py::test_provision_provision[provision_mock0] PASSED                                                                           [ 82%]
deployability/modules/provision/tests/test_provision.py::test_provision_load_ansible_data[provision_mock0] PASSED                                                                   [ 84%]
deployability/modules/provision/tests/test_provision.py::test_provision_load_ansible_data_fail[logger_mock0-provision_mock0-Exception] PASSED                                       [ 86%]
deployability/modules/provision/tests/test_provision.py::test_provision_load_ansible_data_fail[logger_mock1-provision_mock1-FileNotFoundError] PASSED                               [ 88%]
deployability/modules/provision/tests/test_provision.py::test_provision_get_deps_ips[provision_mock0-True] PASSED                                                                   [ 90%]
deployability/modules/provision/tests/test_provision.py::test_provision_get_deps_ips[provision_mock1-False] PASSED                                                                  [ 92%]
deployability/modules/provision/tests/test_provision.py::test_provision_get_deps_ips_fail[logger_mock0-provision_mock0] PASSED                                                      [ 94%]
deployability/modules/provision/tests/test_provision.py::test_provision_validate_component_deps[logger_mock0-provision_mock0-wazuh-agent-dependencies0] PASSED                      [ 96%]
deployability/modules/provision/tests/test_provision.py::test_provision_validate_component_deps[logger_mock1-provision_mock1-wazuh-manager-dependencies1] PASSED                    [ 98%]
deployability/modules/provision/tests/test_provision.py::test_provision_validate_component_deps_fail[provision_mock0] PASSED                                                        [100%]

==================================================================================== warnings summary =====================================================================================
deployability/modules/provision/models.py:36
  /home/marcelo/wazuh/wazuh-qa/deployability/modules/provision/models.py:36: PydanticDeprecatedSince20: Pydantic V1 style `@validator` validators are deprecated. You should migrate to Pydantic V2 style `@field_validator` validators, see the migration guide for more details. Deprecated in Pydantic V2.0 to be removed in V3.0. See Pydantic V2 Migration Guide at https://errors.pydantic.dev/2.5/migration/
    @validator('dependencies', pre=True)

deployability/modules/provision/models.py:64
  /home/marcelo/wazuh/wazuh-qa/deployability/modules/provision/models.py:64: PydanticDeprecatedSince20: Pydantic V1 style `@validator` validators are deprecated. You should migrate to Pydantic V2 style `@field_validator` validators, see the migration guide for more details. Deprecated in Pydantic V2.0 to be removed in V3.0. See Pydantic V2 Migration Guide at https://errors.pydantic.dev/2.5/migration/
    @validator('install', 'uninstall', pre=True)

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
============================================================================= 51 passed, 2 warnings in 0.16s ==============================================================================
```

The `.github/jobflow/provision-unit-tests.yaml` automatically runs the unit tests in the GitHub environment.
The run results are shown in the `checks` tab or your GitHub pull request.

## Relevant Files
- `tests/test_[test name].py`: all the unit test files start with a `test_` prefix. There is one unit test file for
  each tested class.
- `tests/conftest.py`: contains the fixtures used throughout the unit tests.

## Unit test development guidelines and recommendations
- Use Python coding style standards and recommendations to develop unit tests: snake case for all variable and function
  names, maximum line length of 120 characters, two empty lines must separate each function, typing all your functions
  and return values, create Docstring for each function or method with numpy style.
- Develop unit tests for each function or method of the module.
- Error flows are usually created in a second unit test with the suffix `_fail`. For example, the
  `test_provision_handler_constructor` found in the `deployability/modules/provision/tests/test_handler.py` is the
  unit test normal flow for the `ProvisionHandler` class constructor method. The
  `test_provision_handler_constructor_fail` unit test implements the error flow.
- Use the pytest's decorator `@pytest.mark.parametrize` to implement test cases for the same unit test.
- Mock the object instance and functions used by your tested function using the `unitest.mock.patch` and
  `unitest.mock.patch.object` functions or decorators.
- Try to factorize your testing code using `pytest.fixtures`. The shared fixtures are in the `conftest.py` file. In
  many unit tests of this project, the fixtures implement a `request` object that receives parameters from the
  `pytest.mark.parametrize`.
