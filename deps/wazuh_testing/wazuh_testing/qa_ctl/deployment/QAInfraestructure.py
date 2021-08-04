# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh_testing.qa_ctl.deployment.DockerWrapper import DockerWrapper
from wazuh_testing.qa_ctl.deployment.VagrantWrapper import VagrantWrapper


class QAInfraestructure:
    """Class to handle multiples instances objects.
    Attributes:
        instances (list): List with the instances to handle.
    Args:
        vm_list (dict): Dictionary with the information of the instances. Must follow the format of the yaml template.
    """
    instances = []

    def __init__(self, vm_list):
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

                    docker_instance = DockerWrapper(data['dockerfile_path'], data['name'], data['remove'],
                                                    _ports, _detach, _stdout, _stderr)
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
