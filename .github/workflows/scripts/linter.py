
'''Run a code format analysis for the specified files, indicated by a data file passed to this script.

The analyses performed are as follows:

- Python: pycodestyle
- YAML: yamllint
'''
import os
import sys
import re
import subprocess
import argparse


def get_script_parameters():
    """Process the script parameters.

    Returns:
        ArgumentParser: Parameters and their values.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--file', '-f', type=str, action='store', required=True, dest='file',
                        help='Path with file changes in CSV format')

    parser.add_argument('--config-path', '-c', type=str, action='store', required=True, dest='config_path',
                        help='Path with the linter config files')

    script_parameters = parser.parse_args()

    return script_parameters


def get_update_files(data_file):
    """Read the file data and parse it to get the updated files.

    Args:
        data_file (str): Data file path that contains the updated files data in CSV format.

    Returns:
        list(str): Updated files list.
    """
    # Check if the specified file exists
    if not os.path.exists(data_file):
        raise Exception(f"Could not find the {data_file} data file")

    # Read the file content
    with open(data_file) as opened_file:
        data_file_content = opened_file.read()

    # Check if the file content is empty
    if data_file_content == '':
        raise Exception(f"{data_file} is empty")

    return data_file_content.replace('\n', '').split(',')


def get_python_files(updated_files):
    """Parse the updated files list and get only the python ones.

    Args:
        updated_files (list(str)): Updated files list.

    Returns:
        list(str): Updated python files list.
    """
    return [python_file for python_file in updated_files if '.py' in python_file]


def get_yaml_files(updated_files):
    """Parse the updated files list and get only the yaml ones.

    Args:
        updated_files (list(str)): Updated files list.

    Returns:
        list(str): Updated yaml files list.
    """
    print([yaml_file for yaml_file in updated_files if '.yaml' in yaml_file or '.yml' in yaml_file])
    return [yaml_file for yaml_file in updated_files if '.yaml' in yaml_file or '.yml' in yaml_file]


def run_python_linter(python_files):
    """Run the python linter process.

    Args:
        python_files (list(str)): Python files list to process.

    Returns:
        int: Status code result of python linting.
    """
    if len(python_files) == 0:
        print('No python files were found. Skipping python linter analysis')
        return 0

    # Set the linter parameters
    parameters = ['pycodestyle', '--max-line-length=120']
    parameters.extend(python_files)

    return subprocess.run(parameters).returncode


def run_yaml_linter(yaml_files, config_files_path):
    """Run the yaml linter process.

    Args:
        yaml_files (list(str)): Yaml files list to process.

    Returns:
        int: Status code result of yaml linting.
    """
    def _parse_yaml_linter_output(linter_output):
        """Parse the linter output to remove github annotations (It difficults the debugging process).

            Args:
                linter_output (str): Linter process output.

            Returns:
                str: Parsed and custom output.
        """
        output = linter_output

        # Remove github annotations
        output = output.replace('::error', '').replace('file=', '').replace(',line=', ":") \
                       .replace(',col=', ":").replace('::warning', '').strip()

        # Remove labels
        output = re.sub(r'::\[\S+\]', '', output)

        # Remove all initial whitespaces for each line
        output = ''.join([f"{line.strip()}\n" for line in output.splitlines()])

        return output

    if len(yaml_files) == 0:
        print('No yaml files were found. Skipping yaml linter analysis')
        return 0

    # Set the linter parameters
    yaml_linter_config = 'yaml_linter_config_sca.yaml'
    parameters = ['yamllint', '-c', f"{config_files_path}/{yaml_linter_config}"]
    parameters.extend(yaml_files)
    # parameters.extend([f"> {config_files_path}/out.txt"])

    # Run the linter process and capture the output
    result = subprocess.run(parameters, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return_code = result.returncode

    # Parse the output to remove github annotations
    output = _parse_yaml_linter_output(result.stdout.decode())


    # Print the formatted output
    print(output)

    print(result.stderr.decode())

    return return_code


def main():
    script_parameters = get_script_parameters()

    # Get updated files
    updated_files = get_update_files(script_parameters.file)

    # Get python files
    python_files = get_python_files(updated_files)

    # Get the yaml files
    yaml_files = get_yaml_files(updated_files)

    # Run the python linter analysis process
    python_linter_status = run_python_linter(python_files)

    # Run the yaml linter analysis process
    yaml_linter_status = run_yaml_linter(yaml_files, script_parameters.config_path)

    # Return failure code if some check has not passed
    if python_linter_status != 0 or yaml_linter_status != 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
