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
        targets_paths = payload.targets # lista con 2 items
        for target_path in targets_paths:
            path = ', '.join(list(eval(target_path).values()))
            target = Inventory(**Utils.load_from_yaml((path)))
            logger.info(f"Running tests for {target.ansible_host}")  

        print(targets_paths)
        
        for i in targets_paths:
            assert isinstance(eval(i), dict)

        resultado = {}
        for item in targets_paths:
            diccionario = eval(item)
            resultado.update(diccionario)

        # Convertir el resultado a string JSON
        resultado_json = json.dumps(resultado)
        print(type(resultado_json))

        """
        for target_path in json_targets_paths.values():
            target = Inventory(**Utils.load_from_yaml((target_path)))
                 


        dependencies_paths = payload.dependencies
        json_dependencies_paths = eval(dependencies_paths)
        for dependency_path in json_dependencies_paths.values():
            dependency = Inventory(**Utils.load_from_yaml((dependency_path)))
            logger.info(f"Dependencies: {dependency.ansible_host}")            
        extra_vars['dependencies'] = dependencies_paths.replace('"',"")

        extra_vars['local_host_path'] = str(Path(__file__).parent.parent.parent)
        extra_vars['current_user'] = os.getlogin()
        logger.debug(f"Using extra vars: {extra_vars}")

        for target in payload.targets.values():
            target_inventory = Inventory(**Utils.load_from_yaml(target))
            ansible = Ansible(ansible_data=target_inventory.model_dump())
            cls._setup(ansible, extra_vars['working_dir'])

        cls._run_tests(payload.tests, ansible, extra_vars)

        for target in payload.targets.values():
            target_inventory = Inventory(**Utils.load_from_yaml(target))
            if payload.cleanup:
                logger.info("Cleaning up")
                cls._cleanup(ansible, extra_vars['working_dir']) """


    @classmethod
    def _get_extra_vars(cls, payload: InputPayload) -> ExtraVars:
        """
        Get the extra vars for the tests.

        Args:
            payload (InputPayload): The payload containing the test parameters.

        Returns:
            ExtraVars: The extra vars for the tests.
        """
        #if not payload.dependencies:
        #    logger.debug("No dependencies received in payload")
        #    return ExtraVars(**payload.model_dump())
        #
        #dependencies_paths = []
        #logger.debug("Dependencies found. Parsing...")
        #for dependency in range(len(payload.dependencies)):
        #    dicts = eval(payload.dependencies[dependency])
        #    for key, value in dicts.items():
        #        #dep_inventory = Inventory(**Utils.load_from_yaml(value))
        #        #dicts[key] = dep_inventory.ansible_host
        #        dicts[key] = value           
        #        dependencies_paths.append(str(dicts))

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