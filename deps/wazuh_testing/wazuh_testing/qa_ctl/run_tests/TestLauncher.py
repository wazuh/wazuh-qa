class TestLauncher:
    """ The class encapsulates the execution of a list of tests previously built and passed as a parameter.

    Attributes:
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        ansible_inventory_path (str): Path to the ansible inventory file
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        html_report_dir_path (str, None): Local directory path where the html report will be stored
        test_output_dir_path (str, None):  Local directory path where the plain report will be stored
        qa_framework_path (str, None): Remote directory path where the qa repository will be download to

    Args:
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        ansible_inventory_path (str): Path to the ansible inventory file
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        html_report_dir_path (str, None): Local directory path where the html report will be stored
        test_output_dir_path (str, None):  Local directory path where the plain report will be stored
        qa_framework_path (str, None): Remote directory path where the qa repository will be download to

    """
    def __init__(self, ansible_inventory_path, tests,
                 qa_framework_path="/tmp/wazuh-qa/"):
        self.qa_framework_path = qa_framework_path
        self.ansible_inventory_path = ansible_inventory_path
        self.tests = tests

    def run(self):
        """ Function to iterate over a list of a set of ests and execute them one by one. """
        for test in self.tests:
            test.run(self.ansible_inventory_path)
