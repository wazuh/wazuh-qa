import json
import os


def generate_result(scenario, host, action, passed, expected_alerts_num,
                    received_alerts_num, missing_paths, output_path):
                    # host_os, host_arch):

    """
    Generates a JSON file with the related testing info for each scenario
    and for each agent host. If the file already exists, then it load it
    into a dictionary, modify it and re-write it. If not, then it creates it.

    :param str scenario: Scenario name.
    :param str host: Agent target host.
    :param str action: Action name. 'added', 'deleted' or 'modified'
    :param str passed: Test passed. 'FAILED' or 'SUCCESS'.
    :param int expected_alerts_num: Expected number of alerts to be received.
    :param int received_alerts_num: Number of the received alerts.
    :param list missing_paths: List of the missing paths.
    :param str output_path: Path of the output file.
    :param str host_os: Agent host operating system.
    :param str host_arch: Agent host architecture.

    """
    # Setting passed variables to True by default.
    scenario_passed = True
    action_passed = True

    if not passed:  # In case of negative 'passed'
        print("sdasda")
        scenario_passed = False
        action_passed = False

    data = {}  # Initialize data as empty dictionary.

    scenario_vars = {
            'passed': scenario_passed,
            action: {
                'passed': action_passed,
                'hosts': {},
            }
    }

    host_vars = {
            'passed': passed,
            'expected_alerts': expected_alerts_num,
            'received_alerts': received_alerts_num,
            'missing_alerts': (expected_alerts_num - received_alerts_num),
            'missing_paths': missing_paths,
    }

    # file_exists registers if output_path exists or not
    file_exists = os.path.exists(output_path)

    if file_exists:  # In case output_path exists, then load it in a dic.
        try:
            with open(output_path) as f:
                data = json.load(f)
        except:
            logging.error("Failed when reading the result file.")

        # setting the global 'passed' result
        if not passed:
            data['json_verification']['passed'] = False

    else:  # output_path does not exist.
        data['json_verification'] = {
            'passed': passed,
            'scenarios': {}
        }

    # In case 'scenario' already exists
    if scenario in data['json_verification']['scenarios']:

        if not passed:
            data['json_verification']['scenarios'][scenario]['passed'] = False

        if action in data['json_verification']['scenarios'][scenario] :
            if not passed:
                (data['json_verification']['scenarios']
                    [scenario][action]['passed']) = False
        else:
            (data['json_verification']['scenarios']
                [scenario][action]) = { 'passed' : action_passed }

        (data['json_verification']['scenarios']
            [scenario][action]['hosts']) = { host: host_vars }

    else:  # In case the scenario does not exist.
        (data['json_verification']['scenarios']
            [scenario]) = scenario_vars
        (data['json_verification']['scenarios']
            [scenario][action]['passed']) = action_passed
        (data['json_verification']['scenarios']
            [scenario][action]['hosts'][host]) = host_vars

    try:
        with open(output_path, 'w') as outfile:  # save data to 'output_path'
            json.dump(data, outfile)

        
        logging.info("Done! The result file is generated correctly. Path: {}".format(output_path))
    except:
        logging.error("Failed when generating the result file in {}".format(output_path))
