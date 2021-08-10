# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh_testing.qa_ctl.deployment.DockerWrapper import DockerWrapper
from wazuh_testing.qa_ctl.deployment.VagrantWrapper import VagrantWrapper
import ipaddress
import docker


class QAInfraestructure:
    """Class to handle multiples instances objects.
    Attributes:
        instances (list): List with the instances to handle.
    Args:
        vm_list (dict): Dictionary with the information of the instances. Must follow the format of the yaml template.
    """
    instances = []
    DOCKER_NETWORK_NAME = 'wazuh_net'

    def __init__(self, vm_list):
        self.docker_client = docker.from_env()
        self.docker_network = None
        self.network_address = None
        for host in vm_list:
            for provider in vm_list[host]['provider']:
                data = vm_list[host]['provider'][provider]
                if not data['enabled']:
                    continue

                if provider == 'vagrant':
                    quiet_out = True if 'quiet_out' not in data else data['quiet_out']
                    vagrant_instance = VagrantWrapper(data['vagrantfile_path'], data['vagrant_box'], data['label'],
                                                      data['vm_name'], data['vm_cpu'], data['vm_memory'],
                                                      data['vm_system'], data['vm_ip'], quiet_out)
                    self.instances.append(vagrant_instance)

                elif provider == 'docker':
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

                        assert network == self.network_address, 'Two different networks where found for docker '\
                                                                'containers when only one network is allowed: '\
                                                                f'{network} != {self.network_address}'

                        if not self.docker_network:
                            # Try to get the DOCKER_NETWORK_NAME network, if it fails, try to create it.
                            try:
                                self.docker_network = self.docker_client.networks.get(self.DOCKER_NETWORK_NAME)
                            except docker.errors.NotFound:
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

    def run(self):
        """Executes the run method on every configured instance."""
        for instance in self.instances:
            instance.run()

    def halt(self):
        """Executes the 'halt' method on every configured instance."""
        for instance in self.instances:
            instance.halt()

    def restart(self):
        """Executes the 'restart' method on every configured instance."""
        for instance in self.instances:
            instance.restart()

    def destroy(self):
        """Executes the 'destroy' method on every configured instance."""
        for instance in self.instances:
            instance.destroy()

        if self.docker_network:
            try:
                self.docker_network.remove()
            except docker.errors.NotFound:
                pass

    def status(self):
        """Executes the 'status' method on every configured instance.

        Returns:
            Dictionary: Contains the status for each configured instance.
        """
        status = {}
        for instance in self.instances:
            status[instance.get_name()] = instance.status()

        return status

    def get_instances_info(self):
        """Get information about the information for all the configured instances.
           Returns:
            Dictionary: Dictionary with the information for each configured instance.
        """
        info = {}
        for instance in self.instances:
            info[instance.get_name()] = instance.get_instance_info()

        return info
