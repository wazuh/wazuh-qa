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


def update_known_flaws(known_flaws, results):
    updated_known_flaws = {k: None for k in known_flaws.keys()}
    for key in known_flaws.keys():
        for i in range(len(known_flaws[key])):
            next_flaw = next((flaw for flaw in results
                              if (flaw['code'] == known_flaws[key][i]['code']
                                  and flaw['filename'] == known_flaws[key][i]['filename']
                                  and flaw['test_id'] == known_flaws[key][i]['test_id'])), {})
            if next_flaw:
                known_flaws[key][i] = next_flaw
            else:
                known_flaws[key][i] = None
        updated_known_flaws[key] = [flaw for flaw in known_flaws[key] if flaw]

    return updated_known_flaws


@pytest.fixture(scope='session', autouse=True)
def clone_wazuh_repository(pytestconfig):
    # Get Wazuh branch
    branch = pytestconfig.getoption('branch')

    # Create temporary dir
    t = tempfile.mkdtemp()

    try:
        # Clone into temporary dir
        current_process = subprocess.Popen(["git", "clone", "https://github.com/wazuh/wazuh.git", f"{t}"])
        current_process.wait()
        if current_process.returncode == 0:
            # Checkout to given branch
            current_working_dir = os.getcwd()
            os.chdir(t)
            current_process = subprocess.Popen(["git", "checkout", f"{branch}"])
            current_process.wait()
            if current_process.returncode == 0:
                os.chdir(current_working_dir)
                yield t
            else:
                yield None
        else:
            yield None
    except:
        yield None

    # Remove the temporary directory when the test ends
    shutil.rmtree(t)


@pytest.mark.parametrize("directory_to_check", DIRECTORIES_TO_CHECK)
def test_check_security_flaws(clone_wazuh_repository, directory_to_check):
    # Wazuh is cloned from GitHub using the clone_wazuh_repository fixture
    assert clone_wazuh_repository, "Error while cloning the Wazuh repository from GitHub, " \
                                   "please check the Wazuh branch set in the parameter."

    # Run Bandit to check possible security flaws
    # b_conf = b_config.BanditConfig()
    # agg_type = _log_option_source(
    #     args.agg_type,
    #     ini_options.get('aggregate'),
    #     'aggregate output type')
    # b_mgr = b_manager.BanditManager(b_conf, agg_type,
    #                                 quiet=True,)

    bandit_output = json.loads(
        os.popen(f"bandit -q -r {clone_wazuh_repository}/{directory_to_check} "
                 f"-ii -f {FORMAT} -x {','.join(DIRECTORIES_TO_EXCLUDE)}").read())

    assert not bandit_output['errors'], \
        f"\nBandit returned errors when trying to get possible vulnerabilities:\n{bandit_output['errors']}"

    # We save the results obtained in the report as the rest of information is redundant or not used
    results = bandit_output['results']

    # Delete filenames to make it persistent with tmp directories
    for result in results:
        result['filename'] = "/".join(result['filename'].split('/')[3:])

    # Delete line numbers in code to make it persistent with updates
    for result in results:
        result['code'] = re.sub(r"^\d+", "", result['code'])  # Delete first line number
        result['code'] = re.sub(r"\n\d+", "\n", result['code'], re.M)  # Delete line numbers after newline

    # Compare the flaws obtained in results with the known flaws
    try:
        with open(f"{KNOWN_FLAWS_DIRECTORY}/known_flaws_{directory_to_check}.json", mode="r") as f:
            known_flaws = json.load(f)
    except json.decoder.JSONDecodeError:
        known_flaws = {'false_positives': [], 'to_fix': []}

    # There are security flaws if there are new possible vulnerabilities detected
    # To compare them, we cannot compare the whole dictionaries containing the flaws as the values of keys like
    # line_number and line_range will change
    # Update known flaws with the ones detected in this Bandit run, remove them if they were fixed
    known_flaws = update_known_flaws(known_flaws, results)
    with open(f"{KNOWN_FLAWS_DIRECTORY}/known_flaws_{directory_to_check}.json", mode="w") as f:
        f.write(json.dumps(known_flaws, indent=4, sort_keys=True))

    new_flaws = [flaw for flaw in results if
                 flaw not in known_flaws['to_fix'] and flaw not in known_flaws['false_positives']]
    if new_flaws:
        # Write new flaws in a temporal file to analyze them
        new_flaws_path = os.path.join(TEST_PYTHON_CODE_PATH, f"new_flaws_{directory_to_check}.json")
        with open(new_flaws_path, mode="w") as f:
            f.write(json.dumps({'new_flaws': new_flaws}, indent=4, sort_keys=True))
        files_with_flaws = ', '.join(list(dict.fromkeys([res['filename'] for res in new_flaws])))
        assert False, f"\nVulnerabilities found in files:\n{files_with_flaws}" \
                      f"\nCheck them in {new_flaws_path}"
