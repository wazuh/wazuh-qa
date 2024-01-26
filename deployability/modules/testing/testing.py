from pathlib import Path
import ast
from modules.generic import Ansible, Inventory
from modules.generic.utils import Utils
from .models import InputPayload, ExtraVars

class Tester:
    _playbooks_dir = Path('tests')
    _setup_playbook = _playbooks_dir / 'setup.yml'
    _cleanup_playbook = _playbooks_dir / 'cleanup.yml'
    _test_template = _playbooks_dir / 'test.yml'

    @classmethod
    def run(cls, payload: InputPayload) -> None:
        payload = InputPayload(**dict(payload))
        inventory = Inventory(**Utils.load_from_yaml(payload.inventory))
        extra_vars = cls._get_extra_vars(payload).model_dump()
        dependencies_dict = {}
        for dependency in extra_vars['dependencies']:
            dependency = ast.literal_eval(dependency)
            dependencies_dict.update(dependency)
        extra_vars['dependencies'] = dependencies_dict
        ansible = Ansible(ansible_data=inventory.model_dump())
        cls._setup(ansible, extra_vars['working_dir'])
        cls._run_tests(payload.tests, ansible, extra_vars)
        if payload.cleanup:
            cls._cleanup(ansible, extra_vars['working_dir'])

    @classmethod
    def _get_extra_vars(cls, payload: InputPayload) -> ExtraVars:
        if not payload.dependencies:
            return ExtraVars(**payload.model_dump())
        
        dependencies_ip = []
        for dependency in range(len(payload.dependencies)):
            dicts = eval(payload.dependencies[dependency])
            for key, value in dicts.items():
                dep_inventory = Inventory(**Utils.load_from_yaml(value))
                dicts[key] = dep_inventory.ansible_host         
                dependencies_ip.append(str(dicts))

        return ExtraVars(**payload.model_dump(exclude={'dependencies'}), dependencies=dependencies_ip)

    @classmethod
    def _run_tests(cls, test_list: list[str], ansible: Ansible, extra_vars: ExtraVars) -> None:
        for test in test_list:
            rendering_var = {**extra_vars, 'test': test}
            template = str(ansible.playbooks_path / cls._test_template)
            playbook = ansible.render_playbook(template, rendering_var)
            if not playbook:
                print(f'ERROR: Playbook for test "{test}" not found')
                continue
            ansible.run_playbook(playbook, extra_vars)

    @classmethod
    def _setup(cls, ansible: Ansible, remote_working_dir: str = '/tmp') -> None:
        extra_vars = {'local_path': str(Path(__file__).parent / 'tests'),
                      'working_dir': remote_working_dir}
        playbook = str(ansible.playbooks_path / cls._setup_playbook)
        ansible.run_playbook(playbook, extra_vars)

    @classmethod
    def _cleanup(cls, ansible: Ansible, remote_working_dir: str = '/tmp') -> None:
        extra_vars = {'working_dir': remote_working_dir}
        playbook = str(ansible.playbooks_path / cls._cleanup_playbook)
        ansible.run_playbook(playbook, extra_vars)
