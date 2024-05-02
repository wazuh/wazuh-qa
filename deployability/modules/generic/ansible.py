# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import ansible_runner
import jinja2
import yaml

from pathlib import Path
from pydantic import BaseModel, IPvAnyAddress
from typing import Optional

from modules.generic.utils import Utils
from modules.generic.logger import Logger


class Inventory(BaseModel):
    ansible_host: str | IPvAnyAddress
    ansible_user: str
    ansible_port: int
    ansible_ssh_private_key_file: Optional[str] = None
    ansible_password: Optional[str] = None


class Ansible:
    def __init__(self, ansible_data: dict | Inventory, logger: Logger, playbooks_path: str | Path = None):
        self.playbooks_path = playbooks_path
        self.ansible_data = Inventory(**dict(ansible_data))
        self.inventory = self.generate_inventory()
        self.logger = logger

    def render_playbooks(self, rendering_variables: dict) -> list[str]:
        """
        Render the playbooks with Jinja.

        Args:
            rendering_variables (dict): Extra variables to render the playbooks.
        """
        tasks = []
        path_to_render_playbooks = rendering_variables.get("templates_path")
        template_loader = jinja2.FileSystemLoader(searchpath=path_to_render_playbooks)
        template_env = jinja2.Environment(loader=template_loader)

        list_template_tasks = Utils.get_template_list(
            path_to_render_playbooks, rendering_variables.get("templates_order"))
        self.logger.debug(f"Templates found: {list_template_tasks}")
        if list_template_tasks:
            for template in list_template_tasks:
                loaded_template = template_env.get_template(template)
                self.logger.debug(f"Rendering template {template}")
                rendered = yaml.safe_load(loaded_template.render(host=self.ansible_data, **rendering_variables))

                if not rendered:
                    self.logger.warn(f"Template {template} not rendered")
                    continue

                tasks += rendered
        else:
            self.logger.error(
                f"No templates found in {path_to_render_playbooks}")
        self.logger.debug(tasks)
        return tasks

    def render_playbook(self, playbook: str | Path, rendering_variables: dict = {}) -> str | None:
        """
        Render one playbook with Jinja.

        Args:
            playbook (str, Path): The playbook to render.
            rendering_variables (dict): Extra variables to render the playbooks.
        """
        playbook = Path(playbook)
        if not playbook.exists():
            self.logger.error(f"Error: Playbook {playbook} not found")
            return None
        _env = jinja2.Environment(loader=jinja2.FileSystemLoader(playbook.parent))
        template = _env.get_template(playbook.name)
        self.logger.debug(f"Rendering template {playbook}")
        rendered = template.render(host=self.ansible_data, **rendering_variables)

        return yaml.safe_load(rendered)

    def run_playbook(self, playbook: str | Path, extravars: dict = None, verbosity: int = 1, env_vars: dict = {}) -> ansible_runner.Runner:
        """
        Run the playbook with ansible_runner.

        Args:
            playbook (str, Path): The playbook to run.
            extravars (dict): Extra variables to pass to the playbook.
            verbosity (int): Verbosity level for the playbook.
            env_vars (dict): Environment variables to pass to the playbook.
        """
        # Set the callback to yaml to env_vars
        env_vars['ANSIBLE_STDOUT_CALLBACK'] = 'community.general.yaml'

        if self.playbooks_path and (isinstance(playbook, str) or isinstance(playbook, Path)):
            playbook = Path(self.playbooks_path) / playbook

        self.logger.debug(f"Using inventory: {self.inventory}")
        self.logger.debug(f"Running playbook: {playbook}")
        result = ansible_runner.run(
            inventory=self.inventory,
            playbook=playbook,
            verbosity=verbosity,
            extravars=extravars,
            envvars=env_vars,
        )
        self.logger.debug(f"Playbook {playbook} finished with status {result.stats}")
        return result

    def generate_inventory(self) -> dict:
        """
        Generate the inventory for ansible.

        Returns:
            dict: Inventory for ansible.
        """
        inventory_data = {
            'all': {
                'hosts': {
                    self.ansible_data.ansible_host: {
                        'ansible_port': self.ansible_data.ansible_port,
                        'ansible_user': self.ansible_data.ansible_user,
                        **({'ansible_ssh_private_key_file': self.ansible_data.ansible_ssh_private_key_file}
                        if hasattr(self.ansible_data, 'ansible_ssh_private_key_file')
                        else {'ansible_password': self.ansible_data.ansible_password})
                    }
                }
            }
        }


        return inventory_data
