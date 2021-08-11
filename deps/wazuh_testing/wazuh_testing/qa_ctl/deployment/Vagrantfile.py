# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from pathlib import Path
import os
import json


class Vagrantfile():
    """Class to handle Vagrantfile creation in runtime. This class will use a template (specified in TEMPLATE_FILE
       constant) to fill the `json_box` variable. This variable will have all the needed vagrant parameters in a JSON
       format.
    Attributes:
        TEMPLATE_FILE (str): Path where the vagrantfile_template is stored.
        REPLACE_PATTERN(str): Pattern to replace inside the vagrantfile_template.
        file_path (str): Path where the vagrantfile will be stored.
        vm_name (str): Name of the VM.
        file_path (str): Path where the vagrantfile will be stored.
        box_image (str): URL for the box image or Vagrant Box.
        vm_label (str): Label for the VM
        vm_name (str): Name of the VM.
        cpus (int): Number of CPU cores for the VM.
        memory (int): Memory assigned to the VM (in MB).
        system (str): Type of system (Linux, Windows, Solaris....).
    Args:
        file_path (str): Path where the vagrantfile will be stored.
        box_image (str): URL for the box image or Vagrant Box.
        vm_label (str): Label for the VM
        vm_name (str): Name of the VM.
        cpus (int): Number of CPU cores for the VM.
        memory (int): Memory assigned to the VM (in MB).
        system (str): Type of system (Linux, Windows, Solaris....).
        private_ip (str): IP of the VM.
    """
    TEMPLATE_FILE = os.path.join(
        Path(__file__).parent, 'vagrantfile_template.txt')
    REPLACE_PATTERN = 'json_box = {}\n'

    def __init__(self, file_path, box_image, vm_label, vm_name, cpus, memory, system, private_ip):
        self.file_path = os.path.join(file_path, 'vagrantfile')
        self.vm_name = vm_name
        self.box_image = box_image
        self.vm_label = vm_label
        self.cpus = cpus
        self.memory = memory
        self.system = f'/{system}'
        self.private_ip = private_ip

    def __str__(self):
        """Get the parameters in JSON format.
        Returns:
            str: String in JSON format with the class parameters.
        """
        parameters = {
            'box_image': self.box_image,
            'vm_label': self.vm_label,
            'cpus': self.cpus,
            'memory': self.memory,
            'system': self.system,
            'private_ip': self.private_ip
        }
        return json.dumps({self.vm_name: parameters})

    def read_vagrantfile_template(self):
        """Read the vagrantfile template located in self.TEMPLATEFILE constant

        Returns:
            List: List with the content of the template vagrant template."""
        with open(self.TEMPLATE_FILE, 'r') as template_fd:
            return template_fd.readlines()

    def write_vagrantfile(self):
        """Replace the self.REPLACE_PATTERN line with a string with the parameters in JSON format and write the new
           contents in self.file_path file.
        """
        read_lines = self.read_vagrantfile_template()
        replace_line = read_lines.index(self.REPLACE_PATTERN)
        read_lines[replace_line] = self.REPLACE_PATTERN.format(
            f"'{self.__str__()}'")

        with open(self.file_path, 'w') as vagrantfile_fd:
            vagrantfile_fd.writelines(read_lines)

    def remove_vagrantfile(self):
        """Removes the file self.file_path if it exists."""
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
