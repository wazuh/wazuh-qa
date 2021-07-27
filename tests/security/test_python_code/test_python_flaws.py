import copy
import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest

DIRECTORIES_TO_EXCLUDE = ['tests', 'test']
DIRECTORIES_TO_CHECK = ['wodles', 'framework', 'api']
FORMAT = "json"
TEST_PYTHON_CODE_PATH = os.path.dirname(__file__)
KNOWN_FLAWS_DIRECTORY = os.path.join(TEST_PYTHON_CODE_PATH, 'known_flaws')
WAZUH_BRANCH_FILE = os.path.join(TEST_PYTHON_CODE_PATH, 'wazuh_branch')


@pytest.fixture(scope='session', autouse=True)
def clone_wazuh_repository():
    # Get Wazuh branch
    with open(WAZUH_BRANCH_FILE, mode='r') as f:
        branch = f.read()

    # Create temporary dir
    t = tempfile.mkdtemp()

    try:
        # Clone into temporary dir
        current_process = subprocess.Popen(["git", "clone", "https://github.com/wazuh/wazuh.git", f"{t}"])
        current_process.wait()

        # Checkout to given branch
        current_working_dir = os.getcwd()
        os.chdir(t)
        current_process = subprocess.Popen(["git", "checkout", f"{branch}"])
        current_process.wait()
        os.chdir(current_working_dir)

        yield t
    except:
        yield None

    # Remove the temporary directory when the test ends
    shutil.rmtree(t)


@pytest.mark.parametrize("directory_to_check", DIRECTORIES_TO_CHECK)
def test_check_security_flaws(clone_wazuh_repository, directory_to_check):
    # Wazuh is cloned from GitHub using the clone_wazuh_repository fixture
    assert clone_wazuh_repository, f"Error while cloning the Wazuh repository from GitHub, " \
                                   f"please check the wazuh branch in the {WAZUH_BRANCH_FILE} file"

    # run Bandit to check possible security flaws
    bandit_output = json.loads(
        os.popen(f"bandit -q -r {clone_wazuh_repository}/{directory_to_check} "
                 f"-ii -f {FORMAT} -x {','.join(DIRECTORIES_TO_EXCLUDE)}").read())

    assert not bandit_output['errors'], \
        f"\nBandit returned errors when trying to get possible vulnerabilities:\n{bandit_output['errors']}"

    # We save the results obtained in the report as the rest of information is redundant or not used
    original_results = bandit_output['results']

    # Delete filenames to make it persistent with tmp directories
    for result in original_results:
        result['filename'] = "/".join(result['filename'].split('/')[3:])

    results = copy.deepcopy(original_results)

    # Delete line numbers in code to make it persistent with updates
    for result in results:
        code = result['code'].split("\n")[:-1]
        for i in range(len(code)):
            code[i] = re.sub(r"^\d+", "*", code[i])
        # Join the modified code as it was done before splitting
        result['code'] = '\n'.join(code)

    # Compare the flaws obtained in results with the known flaws
    with open(f"{KNOWN_FLAWS_DIRECTORY}/known_flaws_{directory_to_check}.txt", mode="r") as f:
        file_content = f.read().split("\n")
        known_flaws = []
        for line in file_content:
            try:
                known_flaws.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    # There are security flaws if there are new possible vulnerabilities detected
    new_flaws = [flaw for flaw in results if flaw not in known_flaws]
    if new_flaws:
        # Change new_flaws to the original flaws reported (with line numbers)
        for i in range(len(new_flaws)):
            new_flaws[i] = original_results[results.index(new_flaws[i])]

        # Write new flaws in a temporal file to analyze them
        new_flaws_path = os.path.join(TEST_PYTHON_CODE_PATH, f"new_flaws_{directory_to_check}.txt")
        with open(new_flaws_path, mode="w") as f:
            for flaw in new_flaws:
                f.write(json.dumps(flaw, indent=4, sort_keys=True))
                f.write("\n")
        files_with_flaws = ', '.join(list(dict.fromkeys([res['filename'] for res in new_flaws])))
        assert False, f"\nVulnerabilities found in files:\n{files_with_flaws}" \
                      f"\nCheck them in {new_flaws_path}"
