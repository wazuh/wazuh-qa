# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys
from shutil import rmtree

import wazuh_testing.qa_ctl.deployment.vagrantfile as vfile
from wazuh_testing.qa_ctl.deployment.instance import Instance
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.qa_ctl.provisioning.local_actions import run_local_command_returning_output

if 'RUNNING_ON_DOCKER_CONTAINER' not in os.environ:
    import vagrant


class VagrantWrapper(Instance):
    """Class to handle Vagrant operations. The class will use the Vagrantfile class to create a vagrantfile in
       runtime.

    Args:
        vagrant_root_folder (str): Root folder where the vagrant environment will be created.
        vm_box (str): Name or link to the Vagrant box
        vm_name (str): Name that will be assigned to the VM
        vm_label (str): Label used in the vagrantfile.
        vm_cpus (int): Number of CPUs assigned to the VM.
        vm_memory (int): Number of RAM bytes assigned to the VM.
        vm_system (str): System of the VM (Linux, Windows, Solaris, etc)
        vm_ip (str): IP assigned to the VM.
        quiet_out (Boolean): Flag to ignore the vagrant output. Defaults to True.

    Attributes:
        vagrantfile (Vagrantfile): Vagrantfile object containing the vagrantfile information.
        vagrant (Vagrant): Vagrant object to handle vagrant operations
        vm_name (String): Name that will be assigned to the VM
        vm_box (String): Name or link to the Vagrant box
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, vagrant_root_folder, vm_box, vm_label, vm_name, vm_cpus, vm_memory, vm_system, vm_ip,
                 quiet_out=True):
        self.box_folder = os.path.join(vagrant_root_folder, vm_name)
        self.vm_name = vm_name
        self.vm_box = vm_box
        os.makedirs(self.box_folder, exist_ok=True)

        self.vagrantfile = vfile.Vagrantfile(self.box_folder, vm_box, vm_label, vm_name, vm_cpus, vm_memory,
                                             vm_system, vm_ip)

        self.vagrant = vagrant.Vagrant(root=self.box_folder, quiet_stdout=quiet_out, quiet_stderr=False)
        self.vagrantfile.write_vagrantfile()

    def run(self):
        """Write the vagrantfile and starts the VM specified in the vagrantfile."""
        VagrantWrapper.LOGGER.debug(f"Running {self.vm_name} vagrant up")

        filter_command = 'findstr' if sys.platform == 'win32' else 'grep'
        if len(run_local_command_returning_output(f"vagrant box list | {filter_command} {self.vm_box}")) == 0:
            VagrantWrapper.LOGGER.info(f"{self.vm_box} vagrant box not found in local repository. Downloading and "
                                       'running')
        self.vagrant.up()
        VagrantWrapper.LOGGER.debug(f"Instance {self.vm_name} has been created successfully")

    def halt(self):
        """Stop the VM specified in the vagrantfile."""
        VagrantWrapper.LOGGER.debug(f"Running {self.vm_name} vagrant halt")
        self.vagrant.halt()
        VagrantWrapper.LOGGER.debug(f"Instance {self.vm_name} has been off successfully")

    def restart(self):
        """Restart the VM specified in the vagrantfile."""
        VagrantWrapper.LOGGER.debug(f"Running {self.vm_name} vagrant restart")
        self.vagrant.restart()
        VagrantWrapper.LOGGER.debug(f"Instance {self.vm_name} has been restarted successfully")

    def destroy(self):
        """Destroy the VM specified in the vagrantfile and remove the vagrantfile."""
        VagrantWrapper.LOGGER.debug(f"Running {self.vm_name} vagrant destroy")
        self.vagrant.destroy()
        VagrantWrapper.LOGGER.debug(f"{self.vm_name} instance has been destroyed successfully")
        self.vagrantfile.remove_vagrantfile()
        rmtree(self.box_folder)

    def suspend(self):
        """Suspend the VM specified in the vagrantfile."""
        self.vagrant.suspend()

    def resume(self):
        """Resume the VM specified in the vagrantfile."""
        self.vagrant.resume()

    def get_vagrant_version(self):
        """Get the vagrant version of the host.

        Returns:
            (str): Vagrant version.
        """
        return self.vagrant.version()

    def status(self):
        """Get the status of the VM specified in the vagrantfile.
            The vagrant module returns a list of namedtuples like the following
            `[Status(name='ubuntu', state='not_created', provider='virtualbox')]`
            but we are only interested in the `state` field.

        Returns:
            (dict): Status of the VM.
        """
        return self.vagrant.status()[0].state

    def get_ssh_config(self):
        """Get the config of the VM specified in the vagrantfile.

        Returns:
            (dict): Dictionary with the configuration of the VM.
        """
        return self.vagrant.conf()

    def get_instance_info(self):
        """Get the instance info.

        Returns:
            (dict): Dictionary with the parameters of the VM.
        """
        return str(self.vagrantfile)

    def get_name(self):
        """Get the name of the VM.

        Returns:
            (str): Name of the VM.
        """
        return self.vagrantfile.vm_name
