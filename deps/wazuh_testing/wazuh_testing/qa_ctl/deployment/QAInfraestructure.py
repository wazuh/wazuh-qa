# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import ipaddress
import docker

from wazuh_testing.qa_ctl.deployment.DockerWrapper import DockerWrapper
from wazuh_testing.qa_ctl.deployment.VagrantWrapper import VagrantWrapper
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError

class QAInfraestructure:
    """Class to handle multiples instances objects.

    Args:
        instance_list (dict): Dictionary with the information of the instances. Must follow the format of the yaml
        template.

    Class Attributes:
        DOCKER_NETWORK_NAME (str): Name of the docker network where the containers will be connected.
        LOGGER (Logging): Logger object.

    Instance Attributes:
        instances (list): List with the instances to handle.
        docker_client (Docker Client): Client to communicate with the docker daemon.
        docker_network (Docker Network): Network object to handle container's static IP address.
        network_address (IPNetwork): Docker network address.
    """
    DOCKER_NETWORK_NAME = 'wazuh_net'
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, instance_list):
        self.instances = []
        self.docker_client = None
        self.docker_network = None
        self.network_address = None

        QAInfraestructure.LOGGER.debug('Processing deployment configuration...')
        for host in instance_list:
            for provider in instance_list[host]['provider']:
                data = instance_list[host]['provider'][provider]
                if not data['enabled']:
                    continue

                if provider == 'vagrant':
                    QAInfraestructure.LOGGER.debug(f"Setting {data['vm_name']} vagrant instance for deployment...")
                    quiet_out = True if 'quiet_out' not in data else data['quiet_out']
                    vagrant_instance = VagrantWrapper(data['vagrantfile_path'], data['vagrant_box'], data['label'],
                                                      data['vm_name'], data['vm_cpu'], data['vm_memory'],
                                                      data['vm_system'], data['vm_ip'], quiet_out)
                    self.instances.append(vagrant_instance)

                elif provider == 'docker':
                    QAInfraestructure.LOGGER.debug(f"Setting {data['name']} docker instance for deployment...")
                    if not self.docker_client:
                        self.docker_client = docker.from_env()

                    _ports = None if 'ports' not in data else data['ports']
                    _detach = True if 'detach' not in data else data['detach']
                    _stdout = False if 'stdout' not in data else data['stdout']
                    _stderr = False if 'stderr' not in data else data['stderr']
                    _remove = False if 'remove' not in data else data['remove']
                    _ip = None if 'ip' not in data else data['ip']

                    if _ip:
                        network = ipaddress.ip_network(f'{_ip}/24', strict=False)

                        if not self.network_address:
                            self.network_address = network

                        if network != self.network_address:
                            exception_message = 'Two different networks where found for docker containers when only ' \
                                                f"one network is allowed: {network} != {self.network_address}"
                            raise QAValueError(exception_message, QAInfraestructure.LOGGER.critical)

                        if not self.docker_network:
                            # Try to get the DOCKER_NETWORK_NAME network, if it fails, try to create it.
                            try:
                                self.docker_network = self.docker_client.networks.get(self.DOCKER_NETWORK_NAME)
                            except docker.errors.NotFound:
                                QAInfraestructure.LOGGER.debug(f"Docker network {self.network_address} not found."
                                                               'Creating it...')
                                ipam_pool = docker.types.IPAMPool(subnet=str(self.network_address),
                                                                  gateway=str(self.network_address[-2]))

                                ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
                                self.docker_network = self.docker_client.networks.create(self.DOCKER_NETWORK_NAME,
                                                                                         driver='bridge',
                                                                                         ipam=ipam_config)

                    docker_instance = DockerWrapper(self.docker_client, data['dockerfile_path'], data['name'], _remove,
                                                    _ports, _detach, _stdout, _stderr, ip=_ip,
                                                    network_name=self.DOCKER_NETWORK_NAME)
                    self.instances.append(docker_instance)

    def __threads_runner(self, threads):
        """Auxiliary function to start and wait for threads

        Args:
            threads (list(ThreadExecutor)): Thread executors
        """
        for runner_thread in threads:
            runner_thread.start()

        for runner_thread in threads:
            runner_thread.join()

    def run(self):
        """Execute the run method on every configured instance."""
        QAInfraestructure.LOGGER.info(f"Running {len(self.instances)} instances deployment...")
        self.__threads_runner([ThreadExecutor(instance.run) for instance in self.instances])

    def halt(self):
        """Execute the 'halt' method on every configured instance."""
        QAInfraestructure.LOGGER.info(f"Stopping {len(self.instances)} instances...")
        self.__threads_runner([ThreadExecutor(instance.halt) for instance in self.instances])

    def restart(self):
        """Execute the 'restart' method on every configured instance."""
        QAInfraestructure.LOGGER.info(f"Restarting {len(self.instances)} instances...")
        self.__threads_runner([ThreadExecutor(instance.restart) for instance in self.instances])

    def destroy(self):
        """Execute the 'destroy' method on every configured instance."""
        QAInfraestructure.LOGGER.info(f"Destroying {len(self.instances)} instances...")
        self.__threads_runner([ThreadExecutor(instance.destroy) for instance in self.instances])

        if self.docker_network:
            QAInfraestructure.LOGGER.debug('Removing docker network...')
            try:
                self.docker_network.remove()
            except docker.errors.NotFound:
                QAInfraestructure.LOGGER.error('Could not remove docker network')
                pass

    def status(self):
        """Execute the 'status' method on every configured instance.

        Returns:
            (dict): Contains the status for each configured instance.
        """
        status = {}
        QAInfraestructure.LOGGER.debug('Getting instances status...')
        for instance in self.instances:
            status[instance.get_name()] = instance.status()

        return status

    def get_instances_info(self):
        """Get information about for all the configured instances.

        Returns:
            (dict): Dictionary with the information for each configured instance.
        """
        info = {}
        QAInfraestructure.LOGGER.debug('Getting instances info...')
        for instance in self.instances:
            info[instance.get_name()] = instance.get_instance_info()

        return info
