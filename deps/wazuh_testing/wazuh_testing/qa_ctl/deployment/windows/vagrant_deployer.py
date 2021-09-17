import yaml
import vagrant
import argparse
import os
import json
import logging
import threading

import requests

from tempfile import gettempdir
from datetime import datetime


LOGGER = logging.getLogger('vagrant_deployer')
TMP_FILES_PATH = os.path.join(gettempdir(), 'vagrant_deployer')
VAGRANTFILE_TEMPLATE_URL = 'https://raw.githubusercontent.com/wazuh/wazuh-qa/1900-qa-ctl-windows/deps/wazuh_testing/' \
                           'wazuh_testing/qa_ctl/deployment/vagrantfile_template.txt'


class ThreadExecutor(threading.Thread):
    """Class which allows us to upload the thread exception to the parent process.

    This is useful to cause the pytest test to fail in the event of an exception or failure in any of the threads.

    Args:
        function (callable): Function to run in the thread.
        parameters (dict): Function parameters. Used as kwargs in the callable function.

    Attributes:
        function (callable): Function to run in the thread.
        parameters (dict): Function parameters. Used as kwargs in the callable function.
        exception (Exception): Thread exception in case it has occurred.
    """
    def __init__(self, function, parameters={}):
        super().__init__()
        self.function = function
        self.exception = None
        self.parameters = parameters
        self._return = None

    def _run(self):
        """Run the target function with its parameters in the thread"""
        self._return = self.function(**self.parameters)

    def run(self):
        """Overwrite run function of threading Thread module.

        Launch the target function and catch the exception in case it occurs.
        """
        self.exc = None
        try:
            self._run()
        except Exception as e:
            self.exception = e

    def join(self):
        """Overwrite join function of threading Thread module.

        Raises the exception to the parent in case it was raised when executing the target function.

        Raises:
            Exception: Target function exception if ocurrs
        """
        super(ThreadExecutor, self).join()
        if self.exception:
            raise self.exception

        return self._return


def read_parameters():
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--config', type=str, action='store', required=True, dest='config',
                        help='Path to the configuration file.')

    parser.add_argument('-d', '--debug', action='store_true',
                        help='Persistent instance mode. Do not destroy the instances once the process has finished.')

    parameters = parser.parse_args()

    return parameters


def set_logging(debug_mode=False):
    logging_level = logging.DEBUG if debug_mode else logging.INFO

    LOGGER.setLevel(logging_level)

    handler = logging.StreamHandler()
    handler.setLevel(logging_level)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    LOGGER.addHandler(handler)


def process_config_file(configuration_file_path, debug_mode=False):
    def _read_configuration_data(configuration_file_path):
        with open(configuration_file_path) as config_file_fd:
            configuration_data = yaml.safe_load(config_file_fd)

        return configuration_data

    LOGGER.debug(f"Processing {configuration_file_path} configuration file")

    instance_list = _read_configuration_data(configuration_file_path)['deployment']
    instances_data = []

    for host in instance_list:
        for provider in instance_list[host]['provider']:
            data = instance_list[host]['provider'][provider]
            if not data['enabled']:
                continue

        if provider == 'vagrant':
            vm_name = data['vm_name'].replace('_', '-')
            instances_data.append({'vagrantfile_path': data['vagrantfile_path'], 'box': data['vagrant_box'],
                                   'label': data['label'], 'name': vm_name, 'cpus': data['vm_cpu'],
                                   'memory': data['vm_memory'], 'system': data['vm_system'],
                                   'ip': data['vm_ip'], 'quiet_out': not debug_mode})
        else:
            raise ValueError("This tool can only deploy vagrant machines")

    LOGGER.debug(f"The {configuration_file_path} configuration file has been processed successfully")

    return instances_data


def download_vagrantfile_template(vagrantfile_template_file_path):
    if not os.path.exists(vagrantfile_template_file_path):
        LOGGER.debug(f"Downloading Vagrantfile template file from {vagrantfile_template_file_path}")

        with open(vagrantfile_template_file_path, 'w') as f:
            f.write((requests.get(VAGRANTFILE_TEMPLATE_URL)).text)

        LOGGER.debug(f"The Vagrantfile template has been downloaded successfully")


def create_vagrantfile(instance_data, vagrantfile_template_file_path):
    def _get_box_url(box_name):
        box_mapping = {
            'qactl/ubuntu_20_04': 'https://s3.amazonaws.com/ci.wazuh.com/qa/boxes/QACTL_ubuntu20_04.box',
            'qactl/centos_8': 'https://s3.amazonaws.com/ci.wazuh.com/qa/boxes/QACTL_centos_8.box'
        }

        return box_mapping[box_name]

    def _read_vagrantfile_template(vagrantfile_template_file_path):
        with open(vagrantfile_template_file_path, 'r') as template_fd:
            return template_fd.readlines()

    def _parse_instance_data(instance_data):
        return json.dumps({
            instance_data['name']: {
                'box_image': instance_data['box'],
                'box_url': _get_box_url(instance_data['box']),
                'vm_label': instance_data['label'],
                'cpus': instance_data['cpus'],
                'memory': instance_data['memory'],
                'system': instance_data['system'],
                'private_ip': instance_data['ip']
            }
        })

    def _write_vagrantfile(instance_data, vagrantfile_file_path, vagrantfile_template_file_path):
        LOGGER.debug(f"Writing Vagrantfile for {instance_data['name']} instance in {vagrantfile_file_path} path")

        REPLACE_PATTERN = 'json_box = {}\n'
        read_lines = _read_vagrantfile_template(vagrantfile_template_file_path)
        replace_line = read_lines.index(REPLACE_PATTERN)
        read_lines[replace_line] = REPLACE_PATTERN.format(f"'{_parse_instance_data(instance_data)}'")

        with open(vagrantfile_file_path, 'w') as vagrantfile_fd:
            vagrantfile_fd.writelines(read_lines)

        LOGGER.debug(f"Vagrantfile for {instance_data['name']} instance has been written sucessfully")

    vagrantfile_path = os.path.join(TMP_FILES_PATH, instance_data['name'])

    if not os.path.exists(vagrantfile_path):
        os.makedirs(vagrantfile_path)
        LOGGER.debug(f"{vagrantfile_path} path has been created")

    _write_vagrantfile(instance_data, os.path.join(vagrantfile_path, 'Vagrantfile'), vagrantfile_template_file_path)


def deploy(instances_data, vagrantfile_template_file_path):
    def __threads_runner(threads):
        for runner_thread in threads:
            runner_thread.start()

        for runner_thread in threads:
            runner_thread.join()

    def _deploy_instance(instance_data, vagrantfile_template_file_path):
        LOGGER.debug(f"Deploying {instance_data['name']} instance")

        create_vagrantfile(instance_data, vagrantfile_template_file_path)
        vagrantfile_path = os.path.join(TMP_FILES_PATH, instance_data['name'])
        vagrant_instance = vagrant.Vagrant(root=vagrantfile_path, quiet_stdout=instance_data['quiet_out'],
                                           quiet_stderr=False)
        vagrant_instance.up()

        LOGGER.debug(f"The {instance_data['name']} instance has been deployed successfully")

    LOGGER.info(f"Deploying {len(instances_data)} instances")

    __threads_runner(
        [ThreadExecutor(_deploy_instance, {'instance_data': instance,
                                           'vagrantfile_template_file_path': vagrantfile_template_file_path})
            for instance in instances_data])

    LOGGER.info(f"The {len(instances_data)} instances has been deployed sucessfully")


def main():
    parameters = read_parameters()

    set_logging(True if parameters.debug else False)

    instances_data = process_config_file(parameters.config)

    if not os.path.exists(TMP_FILES_PATH):
        os.makedirs(TMP_FILES_PATH)
        LOGGER.debug(f"{TMP_FILES_PATH} path has been created")

    vagrantfile_template_file_path = os.path.join(TMP_FILES_PATH, 'vagrantfile_template.txt')

    download_vagrantfile_template(vagrantfile_template_file_path)

    deploy(instances_data, vagrantfile_template_file_path)


if __name__ == '__main__':
    main()
