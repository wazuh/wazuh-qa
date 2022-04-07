from abc import ABC, abstractmethod


class Test(ABC):
    """Abstract class to be extended by Pytest and used by TestLauncher.

    Attributes:
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        tests_result_path(str): Path to the directory where the reports will be stored in the local machine
        result (TestResult): Result of the test. It is set when the test has been finished.
        modules (list(str)): List of wazuh modules to which the test belongs.
        component (str): Test target (manager, agent).
        system (str): System where the test will be launched.

    Args:
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        tests_result_path(str): Path to the directory where the reports will be stored in the local machine
    """

    def __init__(self, tests_path, tests_run_dir, tests_result_path, modules=None, component=None, system='linux'):
        self.tests_path = tests_path
        self.tests_run_dir = tests_run_dir
        self.tests_result_path = tests_result_path
        self.modules = modules
        self.component = component
        self.system = system

    @abstractmethod
    def run(self):
        pass
