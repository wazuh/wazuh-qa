# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import Vagrantfile as vfile
import vagrant
import os
from Instance import Instance


class VagrantWrapper(Instance):
    """Class to handle Vagrant operations. The class will use the Vagrantfile class to create a vagrantfile in
       runtime. The vagrantfile will be dumped to disk only if the up method is executed.

    Attributes:
        vagrantfile (Vagrantfile): Vagrantfile object containing the vagrantfile information.
        vagrant (Vagrant): Vagrant object to handle vagrant operations
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
    """

    def __init__(self, vagrant_root_folder, vm_box, vm_label, vm_name, vm_cpus, vm_memory, vm_system, vm_ip,
                 quiet_out=True):

        box_folder = os.path.join(vagrant_root_folder, vm_name)
        os.makedirs(box_folder, exist_ok=True)

        self.vagrantfile = vfile.Vagrantfile(box_folder, vm_box, vm_label, vm_name, vm_cpus, vm_memory,
                                             vm_system, vm_ip)

        self.vagrant = vagrant.Vagrant(root=box_folder, quiet_stdout=quiet_out, quiet_stderr=False)
        self.vagrantfile.write_vagrantfile()

    def run(self):
        """Writes the vagrantfile and starts the VM specified in the vagrantfile."""
        self.vagrant.up()

    def halt(self):
        """Stops the VM specified in the vagrantfile."""
        self.vagrant.halt()

    def restart(self):
        """Restarts the VM specified in the vagrantfile."""
        self.vagrant.restart()

    def destroy(self):
        """Destroys the VM specified in the vagrantfile and remove the vagrantfile."""
        self.vagrant.destroy()
        self.vagrantfile.remove_vagrantfile()

    def suspend(self):
        """Suspends the VM specified in the vagrantfile."""
        self.vagrant.suspend()

    def resume(self):
        """Resumes the VM specified in the vagrantfile."""
        self.vagrant.resume()

    def get_vagrant_version(self):
        """Gets the vagrant version of the host.
        Returns:
            String: Vagrant version
        """
        return self.vagrant.version()

    def status(self):
        """Gets the status of the VM specified in the vagrantfile.
        The vagrant module returns a list of namedtuples like the following
        `[Status(name='ubuntu', state='not_created', provider='virtualbox')]`
        but we are only interested in the `state` field.
        Returns:
            Dictionary: Status of the VM.
        """
        return self.vagrant.status()[0].state

    def get_ssh_config(self):
        """Gets the config of the VM specified in the vagrantfile.
        Returns:
            Dictionary: Dictionary with the configuration of the VM.
        """
        return self.vagrant.conf()

    def get_instance_info(self):
        """Gets the instance info.
        Returns:
            Dictionary: Dictionary with the parameters of the VM.
        """
        return str(self.vagrantfile)

    def get_name(self):
        """Gets the name of the VM.
        Returns:
            String: Name of the VM.
        """
        return self.vagrantfile.vm_name
