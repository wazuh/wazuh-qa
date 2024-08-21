# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import getpass

from modules.generic import Ansible, Inventory
from modules.generic.utils import Utils
from pathlib import Path
from .models import InputPayload, ExtraVars
from modules.testing.utils import logger


class Tester:
    _playbooks_dir = Path(__file__).parent / 'playbooks'
    _setup_playbook = _playbooks_dir / 'setup.yml'
    _cleanup_playbook = _playbooks_dir / 'cleanup.yml'
    _test_template = _playbooks_dir / 'test.yml'

    @classmethod
    def run(cls, payload: InputPayload) -> None:
        """
        Run the tests based on the payload.

        Args:
            payload (InputPayload): The payload containing the test parameters.
        """
        payload = InputPayload(**dict(payload))
        extra_vars = cls._get_extra_vars(payload).model_dump()

        targets = {}
        dependencies = {}
        extra_vars['hosts_ip'] = []

        # Process targets and dependencies
        for path_type, paths_list in [("targets", payload.targets), ("dependencies", payload.dependencies)]:
            for path in paths_list:
                dictionary = eval(path)
                inventory = Inventory(**Utils.load_from_yaml(', '.join(dictionary.values())))
                extra_vars['hosts_ip'].extend([inventory.ansible_host] if path_type == "targets" else [])
                logger.info(f"Running tests for {(inventory.ansible_host)}") if path_type == "targets" else logger.info(f"Dependencies {inventory.ansible_host}")
                if path_type == "targets":
                    targets.update(dictionary)
                else:
                    dependencies.update(dictionary)

        extra_vars['targets'] = json.dumps(targets).replace('"', "")
        extra_vars['dependencies'] = json.dumps(dependencies).replace('"', "")

        # Set extra vars
        extra_vars['local_host_path'] = str(Path(__file__).parent.parent.parent)
        extra_vars['current_user'] = getpass.getuser()

        logger.debug(f"Using extra vars: {extra_vars}")

        # Setup and run tests
        target_inventory = Inventory(**Utils.load_from_yaml(str(list(eval(payload.targets[0]).values())[0])))
        ansible = Ansible(ansible_data=target_inventory.model_dump(), logger=logger)
        cls._setup(ansible, extra_vars)
        cls._run_tests(payload.tests, ansible, extra_vars)

        # Clean up if required
        if payload.cleanup:
            for target_path in payload.targets:
                target_value = eval(target_path).values()
                target_inventory = Inventory(**Utils.load_from_yaml(str(list(target_value)[0])))
                logger.info("Cleaning up")
                cls._cleanup(ansible, extra_vars['working_dir'])

    @classmethod
    def _get_extra_vars(cls, payload: InputPayload) -> ExtraVars:
        """
        Get the extra vars for the tests.

        Args:
            payload (InputPayload): The payload containing the test parameters.

        Returns:
            ExtraVars: The extra vars for the tests.
        """

        return ExtraVars(**payload.model_dump())

    @classmethod
    def _run_tests(cls, test_list: list[str], ansible: Ansible, extra_vars: ExtraVars) -> None:
        """
        Execute the playbooks that runs the tests.

        Args:
            test_list (list[str]): The list of tests to run.
            ansible (Ansible): The Ansible object to run the tests.
            extra_vars (ExtraVars): The extra vars for the tests.
        """
        for test in test_list:
            rendering_var = {**extra_vars, 'test': test}
            template = str(cls._test_template)
            result = ansible.run_playbook(template, rendering_var)
            for event in result.events:
                logger.info(f"{event['stdout']}")
            if result.stats["failures"]:
                for event in result.events:
                    if "fatal" in event['stdout']:
                        raise Exception(f"Test {test} failed with error")


    @classmethod
    def _setup(cls, ansible: Ansible, extra_vars: ExtraVars) -> None:
        """
        Setup the environment for the tests.

        Args:
            ansible (Ansible): The Ansible object to run the setup.
            extra_vars (str): The extra vars for the setup.
        """
        template = str(cls._setup_playbook)
        result = ansible.run_playbook(template, extra_vars)
        if result.stats["failures"]:
            for event in result.events:
                if "fatal" in event['stdout']:
                    raise Exception(f"Setup {template} failed with error: {event['stdout']}")


    @classmethod
    def _cleanup(cls, ansible: Ansible, remote_working_dir: str = '/tmp') -> None:
        """
        Cleanup the environment after the tests.

        Args:
            ansible (Ansible): The Ansible object to run the cleanup.
            remote_working_dir (str): The remote working directory.
        """
        extra_vars = {'working_dir': remote_working_dir}
        playbook = str(cls._cleanup_playbook)
        ansible.run_playbook(playbook, extra_vars)
