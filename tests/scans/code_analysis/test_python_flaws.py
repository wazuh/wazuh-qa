import json
import os

from wazuh_testing.tools.scans.code_analysis import (
    get_new_flaws,
    run_bandit_multiple_directories,
    update_known_flaws_in_file,
)

ACTUAL_PATH = os.getcwd()
TEST_PYTHON_CODE_PATH = os.path.dirname(__file__)
KNOWN_FLAWS_DIRECTORY = os.path.join(TEST_PYTHON_CODE_PATH, 'known_flaws')

DEFAULT_DIRECTORIES_TO_CHECK = 'framework/,api/,wodles/'


def test_check_security_flaws(clone_wazuh_repository, get_test_parameters):
    """Test whether the directory to check has python files with possible vulnerabilities or not.

    The test passes if there are no new vulnerabilities. The test fails in other case and generates a report.

    In case there is at least one vulnerability, a json file will be generated with the report. If we consider this
    result or results are false positives, we will move the json object containing each specific result to the
    `known_flaws/known_flaws_{framework|api|wodles}.json` file.

    Args:
        clone_wazuh_repository (fixture): Pytest fixture returning the path of the temporary directory path the
            repository cloned. This directory is removed at the end of the pytest session.
        get_test_parameters (fixture): Pytest fixture returning the a dictionary with all the test parameters.
            These parameters are the directories to check, directories to exclude, the minimum confidence level, the
            minimum severity level and the repository name.
    """
    # Wazuh is cloned from GitHub using the clone_wazuh_repository fixture
    assert clone_wazuh_repository, "Error while cloning the Wazuh repository from GitHub, " \
                                   "please check the Wazuh branch set in the parameter."
    # Change to the cloned Wazuh repository directory
    os.chdir(clone_wazuh_repository)

    directories_to_check = get_test_parameters['directories_to_check']
    bandit_output_list = \
        run_bandit_multiple_directories(directories_to_check,
                                        get_test_parameters['directories_to_exclude'],
                                        get_test_parameters['min_severity_level'],
                                        get_test_parameters['min_confidence_level'])

    flaws_already_found = {}
    for bandit_output, directory in zip(bandit_output_list, directories_to_check):
        assert not bandit_output['errors'], \
            f"\nBandit returned errors when trying to get possible vulnerabilities in the directory " \
            f"{directory}:\n{bandit_output['errors']}"

        bandit_result = bandit_output['results']

        directories = directory.replace('/', '') in DEFAULT_DIRECTORIES_TO_CHECK.replace('/', '').split(',')
        known_flaws = update_known_flaws_in_file(known_flaws_directory=KNOWN_FLAWS_DIRECTORY,
                                                 directory=directory,
                                                 is_default_check_dir=directories,
                                                 bandit_results=bandit_result)

        flaws_already_found = get_new_flaws(bandit_results=bandit_result,
                                            known_flaws=known_flaws,
                                            directory=directory,
                                            flaws_already_found=flaws_already_found,
                                            new_flaws_output_dir=TEST_PYTHON_CODE_PATH)

    vulnerabilities_found = json.dumps(flaws_already_found, indent=4, sort_keys=True)
    assert not any(
        flaws_already_found.get(directory, None) for directory in directories_to_check
    ), f"\nThe following possible vulnerabilities were found: {vulnerabilities_found}"

    # Change again to the path where we first executed the test
    os.chdir(ACTUAL_PATH)
