# Workflow engine Unit Testing using Pytest

The workflow_engine module includes pytest unit tests.

## Requirements

- Make sure you have Python installed on your system. You can download it from 
    [python.org](https://www.python.org/downloads/).
- Clone the wazuh-qa repository in your local environment.
- Install the necessary dependencies by running:
```bash
pip install -r deployability/modules/workflow_engine/requirements-dev.txt
```
- Configure the `PYTHONPATH` variable to include the directory `deployability/modules`.

## Test Structure
The directory `deployability/modules/workflow_engine/tests/` contains the unit test files for the 
`workflow_engine` module.

## Running Tests
To run the tests, make sure that your system meets the requirements by executing the following command from the project root:

```bash
pytest deployability/modules/workflow_engine
```
This command will run all tests in the `tests/` directory. You can also run specific tests or directories using additional arguments.

The `.github/workflow/workflow-engine-unit-tests.yml` automatically runs the unit tests in the GitHub environment. The run results are in the `cheks` tab or your GitHub pull request.

## Relevant Files
- `tests/test_[test name].py`: all the unit test files start with a `test_` prefix. There is one unit test file for each tested class. 
- `tests/conftest.py`: contains the fixtures used throughout the unit tests.

## Unit test development guidelines and recommendations
- Use Python coding style standards and recommendations to develop unit tests: snake case for all variable and function names, maximum line length of 120 characters, two empty lines must separate each function, typing all your functions and return values, create Docstring for all functions with numpy style.
- Develop unit tests for each function or method of the module.
- Error flows are usually created in a second unit test with the suffix `_ko`. For example, the `test_process_task_execute` found in the `deployability/modules/workflow_engine/tests/test_workflow_processor` is the unit test normal flow for the `WorkflowProcessor.process_task_execute` method. The `WorkflowProcessor.process_task_execute_ko` unit test implements the error flow.
- Use the pytest's decorator `@pytest.mark.parametrize` to implement test cases for the same unit test.
- Mock the object instance and functions used by your tested function using the `unitest.mock.patch` and `unitest.mock.patch.object` functions or decorators.
- Try to factorize your testing code using `pytest.fixtures`. The shared fixtures are in the `conftest.py` file. In many unit tests of this project, the fixtures implement a `request` object that receives parameters from the `pytest.mark.parametrize`.
