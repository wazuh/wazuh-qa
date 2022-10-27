import argparse
import logging
import sys
import re
import subprocess
import time
import xml.etree.ElementTree as ET


"""
Description: Install and configure a wazuh environment
Version: 1.0
"""

LOGGER = logging.getLogger('wazuh-container')
SUPPORTED_TARGETS = ['manager', 'agent']
SUPPORTED_OS = ['ubuntu', 'centos']
OSSEC_CONFIG = '/var/ossec/etc/ossec.conf'
OSSEC_LOG = '/var/ossec/logs/ossec.log'


def set_logging(debug=False):
    """Configure the script logging.

    Args:
        debug (boolean): True for DEBUG level, False otherwise
    """
    LOGGER.setLevel(logging.DEBUG if debug else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(message)s"))
    LOGGER.addHandler(handler)


def get_parameters():
    """Get and process script parameters.

    Returns:
        argparse.Namespace: Script parameters.
    """
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t', '--target', metavar='<target>', type=str, help='Wazuh component target',
                            required=True, dest='target', choices=SUPPORTED_TARGETS)

    arg_parser.add_argument('-v', '--version', metavar='<version>', type=str, help='Wazuh install version',
                            dest='version')

    arg_parser.add_argument('-p', '--package-url', metavar='<package_url>', type=str,
                            help='Custom package URL to install', dest='custom_package_url')

    arg_parser.add_argument('-m', '---manager-registration-ip', metavar='<manager_registration_ip>', type=str,
                            help='Manager registration IP. Specify it only if your target is agent',
                            dest='manager_registration_ip')

    arg_parser.add_argument('-o', '--os', metavar='<os>', type=str, help='Container OS distribution', dest='os',
                            choices=SUPPORTED_OS, default='ubuntu')

    arg_parser.add_argument('--debug', action='store_true', help='Activate debug logging')

    return arg_parser.parse_args()


def raise_error(message):
    """Raise a custom error

    Args:
        message (str): Error message
    """
    LOGGER.error(f"\033[1;31;40m{message}\033[0m")
    sys.exit(1)


def _debug(message):
    """Log debug message.

    Args:
        message (str): message
    """
    LOGGER.debug(f"\033[1;31;96m{message}\033[0m")


def _info(message):
    """Log debug message.

    Args:
        message (str): message
    """
    LOGGER.info(f"\033[1;31;94m{message}\033[0m")


def _warning(message):
    """Log debug message.

    Args:
        message (str): message
    """
    LOGGER.warning(f"\033[1;31;93m{message}\033[0m")


def run_command(command):
    """Run a local bash command

    Args:
        command (str): Command ro run.

    Returns:
        str: Command stdout.
    """
    run = subprocess.Popen(['/bin/bash', '-c', command], stdout=subprocess.PIPE)
    return run.stdout.read().decode()


def read_file(file_path):
    """Read data from file

    Args:
        file_path (str): File path.

    Returns:
        str: File data.
    """
    with open(file_path) as file:
        data = file.read()
    return data


def get_package_url(target, version, os):
    """Get the wazuh package URL.

    Args:
        target (str): Wazuh component target.
        version (str): Wazuh version.
        os (str): Package OS.

    Returns:
        str: Wazuh package URL.
    """
    system = 'DEB' if os in ['ubuntu', 'debian'] else ('RPM' if os in ['centos'] else None)

    if system is None:
        raise_error(f"The specified OS: {os} is not supported")

    major = version.split('.')[0]
    package_url = None

    if system == 'DEB':
        package_url = f"https://packages.wazuh.com/{major}.x/apt/pool/main/w/wazuh-{target}/wazuh-{target}_{version}" \
                      '-1_amd64.deb'
    elif system == 'RPM':
        package_url = f"https://packages.wazuh.com/{major}.x/yum/wazuh-{target}-{version}-1.x86_64.rpm"

    if package_url is None:
        raise_error(f"Could not get the package_url for system: {system}, version: {version} and target: {target}")

    return package_url


def validate_parameters(parameters):
    """Validate the input parameters

    Args:
        parameters (argparse.Namespace): Script parameters.
    """
    # Check that version or package URL parameter has been specified
    if parameters.version is None and parameters.custom_package_url is None:
        raise_error('You have to specify version or package_url parameter')

    # Check that version and package_url parameters have not been specified jointly
    if parameters.version and parameters.custom_package_url:
        raise_error('You have to specify only one of the following parameters: version or package_url. The version '
                    'will be used to download a production package, and package_url will be used to install a custom '
                    'package of any version.')

    # Check that the manager registration IP has been specified if the target is an agent
    if parameters.target == 'agent' and parameters.manager_registration_ip is None:
        raise_error('You have to add the manager registration ip parameter when your target is an agent')

    # If manager registration ip, check that IP has valid format
    if parameters.manager_registration_ip and not bool(re.match(r"^\d+\.\d+\.\d+\.\d+$",
                                                       parameters.manager_registration_ip)):
        raise_error(f"The manager registration IP: {parameters.manager_registration_ip} has not valid format")

    # If version, check that version has the correct format
    if parameters.version and not bool(re.match(r"^\d+.\d+.\d+$", parameters.version)):
        raise_error('Version must have format: x.y.z, being x, y and z numbers')

    # Check that the version or package_url is valid (there is an available package to install)
    package_url = get_package_url(parameters.target, parameters.version, parameters.os) if parameters.version else \
        parameters.custom_package_url
    command = f"if curl --head --silent --fail --output /dev/null {package_url}; then echo 0; else echo 1; fi"
    result_code = run_command(command).replace('\n', '')
    if int(result_code) != 0:
        if parameters.version:
            raise_error(f"Could not find an available package for {parameters.version} version. Please, check if that "
                        'version has been released')
        else:
            raise_error(f"Your custom package URL {parameters.custom_package_url} is not valid")


def set_wazuh_environment(parameters):
    """Set the wazuh environment, Downloading the package, installing, configuring and performing health-check.

    Args:
        parameters (argparse.Namespace): Script parameters.
    """
    def disable_module(root, xpath, value):
        """Disable configuration module."""
        try:
            root.find(xpath).text = value
        except AttributeError:
            pass

    _info(f"Starting wazuh-{parameters.target} installation...")

    # Download package
    package_url = get_package_url(parameters.target, parameters.version, parameters.os) if parameters.version else \
        parameters.custom_package_url
    _debug(f"Downloading {package_url} ...")
    run_command(f"curl -L {package_url} -o /tmp/wazuh_package  2> /dev/null")

    # Install package
    _debug(f"Installing wazuh-{parameters.target} package...")
    system = 'DEB' if parameters.os in ['ubuntu', 'debian'] else ('RPM' if parameters.os in ['centos'] else None)
    if system == 'DEB':
        run_command('dpkg -i /tmp/wazuh_package')
    elif system == 'RPM':
        run_command('rpm -i /tmp/wazuh_package')

    # Remove the installer
    run_command('rm -rf /tmp/wazuh_package')

    _info(f"The wazuh-{parameters.target} installation has been finished")
    _info(f"Starting wazuh-{parameters.target} configuration...")

    # Remove second '<ossec_config> block if exists to make the XML code standard and parseable
    ossec_config = read_file(OSSEC_CONFIG)
    blocks = [match.start() for match in re.finditer('<ossec_config>', ossec_config)]
    if len(blocks) > 1:
        new_ossec_config = ossec_config[:blocks[1]]

    # Disable all modules
    root = ET.fromstring(new_ossec_config)
    disable_module(root, './/rootcheck//disabled', 'yes')
    disable_module(root, ".//wodle[@name='cis-cat']//disabled", 'yes')
    disable_module(root, ".//wodle[@name='osquery']//disabled", 'yes')
    disable_module(root, ".//wodle[@name='syscollector']//disabled", 'yes')
    disable_module(root, ".//sca//enabled", 'no')
    disable_module(root, ".//vulnerability-detector//enabled", 'no')
    disable_module(root, ".//syscheck//disabled", 'yes')

    # Remove all logcollector blocks
    for localfile in root.findall(".//localfile"):
        root.remove(localfile)

    # If agent, add the manager address IP for auto enrollment
    if parameters.target == 'agent':
        root.find(".//client//server//address").text = parameters.manager_registration_ip

    _info(f"The wazuh-{parameters.target} configuration has been finished")

    # Write the new ossec config file
    tree = ET.ElementTree(root)
    tree.write(OSSEC_CONFIG)

    # Remove the installer

    _info(f"Starting the wazuh-{parameters.target}...")
    run_command('/var/ossec/bin/wazuh-control start')
    _info(f"The wazuh-{parameters.target} has been started")

    # Healthcheck
    _info(f"Running healthcheck for wazuh-{parameters.target}...")
    time.sleep(15)  # Wait for logs
    errors = int(run_command(f"grep -i error {OSSEC_LOG} | wc -l"))

    # Check that there are no errors in log
    if errors > 0:
        _warning(f"Some errors ({errors}) were found in {OSSEC_LOG}. Check the environment because may not be "
                 'functioning properly')

    # Check that the expected daemons are running
    running_daemons = int(run_command('/var/ossec/bin/wazuh-control status | grep "is running" | wc -l'))
    if parameters.target == 'manager' and running_daemons != 10:
        _warning('Not all the expected demons are running. Please check that everything is OK')

    # In case of agent, check that it is connected to the wazuh-manager
    if parameters.target == 'agent':
        check_connection = int(run_command(f"grep 'Connected to the server' {OSSEC_LOG} | wc -l"))
        if check_connection == 0:
            _warning('No connection log found between agent and manager. Please verify that everything is OK')

    _info('Installation, configuration and healthcheck have been completed.')


def main():
    parameters = get_parameters()
    set_logging(parameters.debug)
    validate_parameters(parameters)
    set_wazuh_environment(parameters)
    # Block so that the container does not die after the installation is completed
    run_command('tail -f /dev/null')


if __name__ == '__main__':
    main()
