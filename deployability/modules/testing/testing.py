import ast

from pathlib import Path

from modules.generic import Ansible, Inventory
from modules.generic.utils import Utils
from .models import InputPayload, ExtraVars
from .utils import logger
import os
import json
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
        targets_paths = payload.targets
        for target_path in targets_paths:
            path = ', '.join(list(eval(target_path).values()))
            target = Inventory(**Utils.load_from_yaml((path)))
            logger.info(f"Running tests for {target.ansible_host}")  
        targets = {}
        for item in targets_paths:
            dictionary = eval(item)
            targets.update(dictionary)
        target_string = json.dumps(targets)
        extra_vars['targets'] = target_string.replace('"',"")
        dependencies_paths = payload.dependencies
        for dependency_path in dependencies_paths:
            path = ', '.join(list(eval(dependency_path).values()))
            dependency = Inventory(**Utils.load_from_yaml((path)))
            logger.info(f"Dependencies {dependency.ansible_host}")  
        dependencies = {}
        for item in targets_paths:
            dictionary = eval(item)
            dependencies.update(dictionary)
        target_string = json.dumps(dependencies)
        extra_vars['dependencies'] = target_string.replace('"',"")
        extra_vars['local_host_path'] = str(Path(__file__).parent.parent.parent)
        extra_vars['current_user'] = os.getlogin()
        logger.debug(f"Using extra vars: {extra_vars}")
        for target in targets_paths:
            target_value = eval(target).values()
            target_inventory = Inventory(**Utils.load_from_yaml(str(list(target_value)[0])))
            ansible = Ansible(ansible_data=target_inventory.model_dump())
            cls._setup(ansible, extra_vars['working_dir'])

        target_inventory = Inventory(**Utils.load_from_yaml(str(list(eval(targets_paths[0]).values())[0])))
        ansible = Ansible(ansible_data=target_inventory.model_dump())
        cls._run_tests(payload.tests, ansible, extra_vars)

        for target in targets_paths:
            target_value = eval(target).values()
            target_inventory = Inventory(**Utils.load_from_yaml(str(list(target_value)[0])))
            if payload.cleanup:
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
            playbook = ansible.render_playbook(template, rendering_var)
            if not playbook:
                logger.warning(f"Test {test} not found. Skipped.")
                continue
            ansible.run_playbook(playbook, extra_vars)

    @classmethod
    def _setup(cls, ansible: Ansible, remote_working_dir: str = '/tmp') -> None:
        """
        Setup the environment for the tests.

        Args:
            ansible (Ansible): The Ansible object to run the setup.
            remote_working_dir (str): The remote working directory.
        """
        extra_vars = {'local_path': str(Path(__file__).parent / 'tests'),
                      'working_dir': remote_working_dir}
        playbook = str(cls._setup_playbook)
        ansible.run_playbook(playbook, extra_vars)

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