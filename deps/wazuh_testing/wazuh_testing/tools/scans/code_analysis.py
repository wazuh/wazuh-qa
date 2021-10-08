import json
import os
import re
import tempfile

from bandit.core import config as b_config, manager as b_manager


def run_bandit_scan(directory_to_check, directories_to_exclude, severity_level, confidence_level):
    """Run a Bandit scan in a specified directory. The directories to exclude, minimum severity and confidence level
    must also be specified.

    Args:
        directory_to_check (str): Directory where Bandit will run the scan (relative path to repo, recursive scan).
        directories_to_exclude (str): String containing the directories that will be excluded in the Bandit
            scan, separated by comma.
        severity_level (str): Minimum severity level taken into account in the Bandit scan.
        confidence_level (str): Minimum confidence level taken into account in the Bandit scan.

    Returns:
        dict: Dictionary with the Bandit scan output.
    """
    # Run Bandit to check possible security flaws
    bandit_manager = b_manager.BanditManager(b_config.BanditConfig(),  # default config options object
                                             None)  # aggregation type
    bandit_manager.discover_files([directory_to_check],  # list of targets
                                  True,  # recursive
                                  directories_to_exclude)  # excluded paths
    bandit_manager.run_tests()

    # Trigger output of results by Bandit Manager
    _, filename = tempfile.mkstemp(suffix='.json')
    bandit_manager.output_results(None,  # context lines
                                  severity_level,  # minimum severity level
                                  confidence_level,  # minimum confidence level
                                  open(filename, mode='w'),  # output file object
                                  'json',  # output format
                                  None)  # msg template

    # Read the temporary file with the Bandit result and remove it
    with open(filename, mode="r") as f:
        bandit_output = json.load(f)
    os.remove(filename)

    return bandit_output


def run_bandit_multiple_directories(directories_to_check, directories_to_exclude, min_severity_level,
                                    min_confidence_level):
    """Run a Bandit scan in a list of specified directories. The directories to exclude, minimum severity and confidence
     level must also be specified.

    Args:
        directories_to_check (list): List of directories where Bandit will run the scan (relative path to repo,
            recursive scan in each one).
        directories_to_exclude (str): String containing the directories that will be excluded in the Bandit
            scan, separated by comma.
        min_severity_level (str): Minimum severity level taken into account in the Bandit scan.
        min_confidence_level (str): Minimum confidence level taken into account in the Bandit scan.

    Returns:
        dict: Dictionary with the Bandit scan output.
    """
    bandit_output_list = []

    # Run Bandit scan for each directory
    for directory_to_check in directories_to_check:
        bandit_output = run_bandit_scan(directory_to_check, directories_to_exclude, min_severity_level,
                                        min_confidence_level)
        bandit_output_list.append(bandit_output)

        # Continue with the next iteration if there are errors
        if bandit_output['errors']:
            continue

        # Delete line numbers in code to make it persistent with updates and change range to interval
        for result in bandit_output['results']:
            result['code'] = re.sub(r"^\d+", "", result['code'])  # Delete first line number
            result['code'] = re.sub(r"\n\d+", "\n", result['code'], re.M)  # Delete line numbers after newline
            first_line = result['line_range'][0]
            last_line = result['line_range'][-1]
            result['line_range'] = \
                [first_line, last_line] if first_line != last_line else [first_line]  # Change line_range to interval

    return bandit_output_list


def update_known_flaws(known_flaws, results):
    """Compare the Bandit results of the run with the already known flaws. Update the known flaws with the new line
    numbers and remove the known flaws that don't appear in the run results (were fixed).

    Args:
        known_flaws (dict): Dictionary containing already known vulnerabilities or false positives detected by Bandit.
        results (list): List containing all the possible flaws obtained in the Bandit run.

    Returns:
        dict: Updated known flaws.
    """
    # There are security flaws if there are new possible vulnerabilities detected
    # To compare them, we cannot compare the whole dictionaries containing the flaws as the values of keys like
    # line_number and line_range will vary
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


def update_known_flaws_in_file(known_flaws_directory, directory, is_default_check_dir, bandit_results):
    """Compare the flaws obtained in the Bandit results with the already known flaws in the directory. Update the known
    flaws in the file.

    Args:
        known_flaws_directory (str): Directory where the known flaws are stored.
        directory (str): Directory where we are passing the Bandit scan.
        is_default_check_dir (bool): Boolean indicating if the directory is one of the default directories to check.
        bandit_results (list): List containing all the possible flaws obtained in the Bandit run.

    Returns:
        dict: Updated known flaws.
    """
    # Read known flaws
    if is_default_check_dir:
        try:
            with open(f"{known_flaws_directory}/known_flaws_{directory.replace('/', '')}.json",
                      mode="r") as f:
                known_flaws = json.load(f)
        except json.decoder.JSONDecodeError or FileNotFoundError:
            known_flaws = {'false_positives': [], 'to_fix': []}
    else:
        known_flaws = {'false_positives': [], 'to_fix': []}

    # Update known flaws with the ones detected in this Bandit run, remove them if they were fixed
    known_flaws = update_known_flaws(known_flaws, bandit_results)
    if is_default_check_dir:
        with open(f"{known_flaws_directory}/known_flaws_{directory.replace('/', '')}.json",
                  mode="w") as f:
            f.write(f"{json.dumps(known_flaws, indent=4, sort_keys=True)}\n")
    else:
        # if the directory to check is not one of the default list, we will create a new known_flaws file outside
        # the directory known_flaws, to avoid overwriting
        with open(f"known_flaws_{directory.replace('/', '')}.json", mode="w") as f:
            f.write(f"{json.dumps(known_flaws, indent=4, sort_keys=True)}\n")

    return known_flaws


def get_new_flaws(bandit_results, known_flaws, directory, flaws_already_found, new_flaws_output_dir):
    """Get the flaws appearing in the Bandit results that are not in the known flaws.

    Args:
        bandit_results (str): Bandit results for the current directory.
        known_flaws (dict): Known flaws got from the known flaws file and updated with the new flaws.
        directory (str): Directory where we are passing the Bandit scan.
        flaws_already_found (dict): Dictionary containing directories as keys and their flaws as values.
        new_flaws_output_dir (str): Path where the new flaws are going to be stored.

    Returns:
        dict: Dictionary containing directories as keys and their flaws as values.
    """
    new_flaws = [flaw for flaw in bandit_results if
                 flaw not in known_flaws['to_fix'] and flaw not in known_flaws['false_positives']]
    if new_flaws:
        # Write new flaws in a JSON file to analyze them
        new_flaws_path = os.path.join(new_flaws_output_dir,
                                      f"new_flaws_{directory.replace('/', '')}.json")
        with open(new_flaws_path, mode="w+") as f:
            f.write(f"{json.dumps({'new_flaws': new_flaws}, indent=4, sort_keys=True)}\n")
        files_with_flaws = ', '.join(list(dict.fromkeys([res['filename'] for res in new_flaws])))
        flaws_already_found[directory] = f"Vulnerabilities found in files: {files_with_flaws}," \
                                         f" check them in {new_flaws_path}"
    return flaws_already_found
