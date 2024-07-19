# JobFlow engine Unit Testing using Pytest

The jobflow module includes pytest unit tests.

## Requirements

- Make sure you have Python installed on your system. You can download it from 
    [python.org](https://www.python.org/downloads/).
- Clone the wazuh-qa repository in your local environment.
- Install the necessary dependencies by running:
```bash
git clone https://github.com/wazuh/wazuh-qa.git -b [your-branch]
cd wazuh-qa
pip install -r deployability/modules/jobflow/requirements-dev.txt
```
- Configure the `PYTHONPATH` variable with the full path to the directory `deployability/modules`, for example if you've
cloned the `wazuh-qa` repository into `/wazuh/wazuh-qa`, configure the `PYTHONPATH` in this way:
```bash
> pwd
/wazuh/wazuh-qa
> export PYTHONPATH=$PYTHONPATH:$PWD/deployability/modules
> echo $PYTHONPATH
/wazuh/wazuh-qa/deployability/modules
```

## Test Structure
The directory `deployability/modules/jobflow/tests/` contains the unit test files for the `jobflow`
module.

## Running Tests
To run the tests, make sure that your system meets the requirements by executing the following command from the project 
root:

```bash
pytest -vv deployability/modules/jobflow
```
This command will run all tests in the `tests/` directory.  Using additional arguments, You can also run specific tests 
or directories. The output of this command looks like this:
```bash
pytest -vv deployability/modules/jobflow
============================================================================================== test session starts ==============================================================================================
platform linux -- Python 3.10.13, pytest-7.1.2, pluggy-1.3.0 -- /usr/local/bin/python3
cachedir: .pytest_cache
metadata: {'Python': '3.10.13', 'Platform': 'Linux-5.15.146.1-microsoft-standard-WSL2-x86_64-with-glibc2.31', 'Packages': {'pytest': '7.1.2', 'pluggy': '1.3.0'}, 'Plugins': {'anyio': '4.2.0', 'testinfra': '5.0.0', 'metadata': '3.0.0', 'html': '3.1.1'}}
rootdir: /home/marcelo/wazuh/wazuh-qa/deployability/modules
plugins: anyio-4.2.0, testinfra-5.0.0, metadata-3.0.0, html-3.1.1
collected 92 items

deployability/modules/jobflow/tests/test_dag.py::test_dag_constructor[True] PASSED                                                                                                                [  1%]
deployability/modules/jobflow/tests/test_dag.py::test_dag_constructor[False] PASSED                                                                                                               [  2%]
deployability/modules/jobflow/tests/test_dag.py::test_dag_is_active[True-dag0] PASSED                                                                                                             [  3%]
deployability/modules/jobflow/tests/test_dag.py::test_dag_is_active[True-dag1] PASSED                                                                                                             [  4%]
deployability/modules/jobflow/tests/test_dag.py::test_dag_is_active[False-dag0] PASSED                                                                                                            [  5%]
deployability/modules/jobflow/tests/test_dag.py::test_dag_is_active[False-dag1] PASSED                                                                                                            [  6%]
deployability/modules/jobflow/tests/test_dag.py::test_get_execution_plan[dag0] PASSED                                                                                                             [  7%]
deployability/modules/jobflow/tests/test_dag.py::test_set_status[task1-failed-dag0] PASSED                                                                                                        [  8%]
deployability/modules/jobflow/tests/test_dag.py::test_set_status[task1-canceled-dag0] PASSED                                                                                                      [  9%]
deployability/modules/jobflow/tests/test_dag.py::test_set_status[task1-successful-dag0] PASSED                                                                                                    [ 10%]
deployability/modules/jobflow/tests/test_dag.py::test_set_status[task1-non_existing_status-dag0] FAILED                                                                                           [ 11%]
deployability/modules/jobflow/tests/test_dag.py::test_set_status[non_existing_task-successful-dag0] PASSED                                                                                        [ 13%]
deployability/modules/jobflow/tests/test_dag.py::test_set_status[non_existing_task-non_existing_status-dag0] FAILED                                                                               [ 14%]
deployability/modules/jobflow/tests/test_dag.py::test_should_be_canceled[True-dag0] PASSED                                                                                                        [ 15%]
deployability/modules/jobflow/tests/test_dag.py::test_should_be_canceled[False-dag0] PASSED                                                                                                       [ 16%]
deployability/modules/jobflow/tests/test_dag.py::test_build_dag[dag0] PASSED                                                                                                                      [ 17%]
deployability/modules/jobflow/tests/test_dag.py::test_build_dag[dag1] PASSED                                                                                                                      [ 18%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task1-abort-all-to_be_canceled0-dag0] PASSED                                                                         [ 19%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task1-abort-all-to_be_canceled0-dag1] PASSED                                                                         [ 20%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task1-abort-related-flows-to_be_canceled1-dag0] FAILED                                                               [ 21%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task1-abort-related-flows-to_be_canceled1-dag1] FAILED                                                               [ 22%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task1-continue-to_be_canceled2-dag0] FAILED                                                                          [ 23%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task1-continue-to_be_canceled2-dag1] FAILED                                                                          [ 25%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task2-abort-all-to_be_canceled3-dag0] FAILED                                                                         [ 26%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task2-abort-all-to_be_canceled3-dag1] FAILED                                                                         [ 27%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task2-abort-related-flows-to_be_canceled4-dag0] FAILED                                                               [ 28%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task2-abort-related-flows-to_be_canceled4-dag1] FAILED                                                               [ 29%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task2-continue-to_be_canceled5-dag0] FAILED                                                                          [ 30%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task2-continue-to_be_canceled5-dag1] FAILED                                                                          [ 31%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task5-abort-all-to_be_canceled6-dag0] PASSED                                                                         [ 32%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task5-abort-all-to_be_canceled6-dag1] PASSED                                                                         [ 33%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task5-abort-related-flows-to_be_canceled7-dag0] PASSED                                                               [ 34%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task5-abort-related-flows-to_be_canceled7-dag1] PASSED                                                               [ 35%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task5-continue-to_be_canceled8-dag0] FAILED                                                                          [ 36%]
deployability/modules/jobflow/tests/test_dag.py::test_cancel_dependant_tasks[task5-continue-to_be_canceled8-dag1] FAILED                                                                          [ 38%]
deployability/modules/jobflow/tests/test_dag.py::test_create_execution_plan[dag0-exec_plan0] PASSED                                                                                               [ 39%]
deployability/modules/jobflow/tests/test_dag.py::test_create_execution_plan[dag1-exec_plan1] PASSED                                                                                               [ 40%]
deployability/modules/jobflow/tests/test_schema_validator.py::test_schema_validator_constructor[logger_mock0] PASSED                                                                              [ 41%]
deployability/modules/jobflow/tests/test_schema_validator.py::test_schema_validator_constructor_ko PASSED                                                                                         [ 42%]
deployability/modules/jobflow/tests/test_schema_validator.py::test_preprocess_data PASSED                                                                                                         [ 43%]
deployability/modules/jobflow/tests/test_schema_validator.py::test_preprocess_data_ko[wf-ko-no-path-on-do.yaml-Missing required properties in 'with' for task: {'task': 'run-agent-tests-{agent}'] PASSED [ 44%]
deployability/modules/jobflow/tests/test_schema_validator.py::test_preprocess_data_ko[wf-ko-no-path-on-cleanup.yaml-Missing required properties in 'with' for task: {'task': 'allocate-manager'] PASSED [ 45%]
deployability/modules/jobflow/tests/test_schema_validator.py::test_validate_schema PASSED                                                                                                         [ 46%]
deployability/modules/jobflow/tests/test_schema_validator.py::test_validate_schema_ko[logger_mock0] PASSED                                                                                        [ 47%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_constructor[task0] PASSED                                                                                                     [ 48%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_execute[task0] PASSED                                                                                                         [ 50%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_execute[task1] PASSED                                                                                                         [ 51%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_execute[task2] PASSED                                                                                                         [ 52%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_execute[task3] PASSED                                                                                                         [ 53%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_execute[task4] PASSED                                                                                                         [ 54%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_execute_ko[subproc_run_exc0-1-task0] PASSED                                                                                   [ 55%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_execute_ko[subproc_run_exc0-0-task0] PASSED                                                                                   [ 56%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_execute_ko[subproc_run_exc1-1-task0] PASSED                                                                                   [ 57%]
deployability/modules/jobflow/tests/test_task.py::test_process_task_execute_ko[subproc_run_exc1-0-task0] PASSED                                                                                   [ 58%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_constructor PASSED                                                                                                  [ 59%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_validate_schema[logger_mock0] PASSED                                                                                [ 60%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_validate_schema_ko[logger_mock0] PASSED                                                                             [ 61%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_load_jobflow[logger_mock0] PASSED                                                                                  [ 63%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_load_jobflow_ko[logger_mock0] PASSED                                                                               [ 64%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_process_jobflow[logger_mock0] PASSED                                                                               [ 65%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_process_jobflow_ok[logger_mock0] PASSED                                                                            [ 66%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_replace_placeholder[element0-values0-return_value0] PASSED                                                          [ 67%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_replace_placeholder[element1-values1-return_value1] PASSED                                                          [ 68%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_replace_placeholder[string_element {value}-values2-string_element value] PASSED                                     [ 69%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_replace_placeholder[element3-None-return_value3] PASSED                                                             [ 70%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_expand_task[task0-return_value0-variables0] PASSED                                                                  [ 71%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_expand_task[task1-return_value1-variables1] PASSED                                                                  [ 72%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_static_jobflow_validation PASSED                                                                                   [ 73%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_static_jobflow_validation_ko[task_collection0-Duplicated task names: task 1] PASSED                                [ 75%]
deployability/modules/jobflow/tests/test_jobflow_file.py::test_jobflow_file_static_jobflow_validation_ko[task_collection1-Tasks do not exist: task 3, task 4] PASSED                           [ 76%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_jobflow_processor_constructor[jobflow.yaml-False-1-info-schema.yaml] PASSED                                                [ 77%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_jobflow_processor_constructor[jobflow.yaml-True-1-debug-schema.yaml] PASSED                                                [ 78%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_jobflow_processor_constructor[jobflow.yaml-True-1-debug-None] PASSED                                                       [ 79%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_task[logger_mock0-w_processor0-dag0-custom_action-True] PASSED                                                       [ 80%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_task[logger_mock1-w_processor1-dag1-custom_action-False] PASSED                                                      [ 81%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_task_ko[logger_mock0-w_processor0-dag0-KeyboardInterrupt-None] PASSED                                                [ 82%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_task_ko[logger_mock0-w_processor0-dag0-KeyboardInterrupt-abort-all] PASSED                                           [ 83%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_task_ko[logger_mock1-w_processor1-dag1-Exception-None] PASSED                                                        [ 84%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_task_ko[logger_mock1-w_processor1-dag1-Exception-abort-all] PASSED                                                   [ 85%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_create_task_object[w_processor0-process] PASSED                                                                              [ 86%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_create_task_object[w_processor0-dummy] PASSED                                                                                [ 88%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_create_task_object[w_processor0-dummy-random] PASSED                                                                         [ 89%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_create_task_object_ko[w_processor0] PASSED                                                                                   [ 90%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_tasks_parallel[logger_mock0-w_processor0-dag0-False] PASSED                                                          [ 91%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_tasks_parallel[logger_mock0-w_processor0-dag0-True] PASSED                                                           [ 92%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_tasks_parallel_ko[logger_mock0-w_processor0-dag0-False] PASSED                                                       [ 93%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_execute_tasks_parallel_ko[logger_mock0-w_processor0-dag0-True] PASSED                                                        [ 94%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_generate_futures[w_processor0] PASSED                                                                                        [ 95%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_generate_futures_reverse[w_processor0] PASSED                                                                                [ 96%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_run[logger_mock0-w_processor0-False] PASSED                                                                                  [ 97%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_run[logger_mock0-w_processor0-True] PASSED                                                                                   [ 98%]
deployability/modules/jobflow/tests/test_jobflow_processor.py::test_handle_interrupt[logger_mock0-w_processor0] PASSED                                                                           [100%]

=================================================================================================== FAILURES ====================================================================================================
```

The `.github/jobflow/jobflow-engine-unit-tests.yaml` automatically runs the unit tests in the GitHub environment. 
The run results are in the `checks` tab or your GitHub pull request.

## Relevant Files
- `tests/test_[test name].py`: all the unit test files start with a `test_` prefix. There is one unit test file for 
  each tested class. 
- `tests/conftest.py`: contains the fixtures used throughout the unit tests.

## Unit test development guidelines and recommendations
- Use Python coding style standards and recommendations to develop unit tests: snake case for all variable and function 
  names, maximum line length of 120 characters, two empty lines must separate each function, typing all your functions 
  and return values, create Docstring for all functions with numpy style.
- Develop unit tests for each function or method of the module.
- Error flows are usually created in a second unit test with the suffix `_ko`. For example, the 
  `test_process_task_execute` found in the `deployability/modules/jobflow/tests/test_jobflow_processor` is the 
  unit test normal flow for the `JobFlowProcessor.process_task_execute` method. The 
  `JobFlowProcessor.process_task_execute_ko` unit test implements the error flow.
- Use the pytest's decorator `@pytest.mark.parametrize` to implement test cases for the same unit test.
- Mock the object instance and functions used by your tested function using the `unitest.mock.patch` and 
  `unitest.mock.patch.object` functions or decorators.
- Try to factorize your testing code using `pytest.fixtures`. The shared fixtures are in the `conftest.py` file. In
  many unit tests of this project, the fixtures implement a `request` object that receives parameters from the 
  `pytest.mark.parametrize`.
