from pathlib import Path

from modules.generic import Playbook, Ansible, Inventory
from modules.generic.utils import Utils

from .models import InputPayload, ExtraVars


class Tester:
    _playbooks_dir = Playbook.PLAYBOOKS_PATH / 'tests'
    _test_playbook = str(_playbooks_dir / 'test.yml')
    _setup_playbook = str(_playbooks_dir / 'setup.yml')
    _cleanup_playbook = str(_playbooks_dir / 'cleanup.yml')

    @classmethod
    def run(cls, payload: InputPayload) -> None:
        payload = InputPayload(**dict(payload))
        inventory = Inventory(**Utils.load_from_yaml(payload.inventory))
        extra_vars = cls._get_extra_vars(payload)
        ansible = Ansible(ansible_data=inventory.model_dump())
        cls._setup(ansible, extra_vars.working_dir)
        cls._run_tests(payload.tests, ansible, extra_vars)
        if payload.cleanup:
            cls._cleanup(ansible, extra_vars.working_dir)

    @classmethod
    def _get_extra_vars(cls, payload: InputPayload) -> ExtraVars:
        if not payload.dependency:
            return ExtraVars(**payload.model_dump())

        dep_inventory = Inventory(**Utils.load_from_yaml(payload.dependency))
        dep_ip = dep_inventory.ansible_host
        return ExtraVars(**payload.model_dump(exclude={'dependency'}), dependency=dep_ip)

    @classmethod
    def _run_tests(cls, test_list: list[str], ansible: Ansible, extra_vars: ExtraVars) -> None:
        # Run tests playbooks
        for test in test_list:
            rendering_vars = {**dict(extra_vars), 'test': test}
            playbook = ansible.render_playbook(cls._test_playbook, rendering_vars)
            if not playbook:
                print(f'ERROR: Playbook for test "{test}" not found')
                continue
            ansible.run_playbook(playbook)

    @classmethod
    def _setup(cls, ansible: Ansible, remote_working_dir: str = '/tmp') -> None:
        extra_vars = {'local_path': str(Path(__file__).parent / 'tests'),
                      'working_dir': remote_working_dir}
        ansible.run_playbook(cls._setup_playbook, extra_vars)

    @classmethod
    def _cleanup(cls, ansible: Ansible, remote_working_dir: str = '/tmp') -> None:
        extra_vars = {'working_dir': remote_working_dir}
        ansible.run_playbook(cls._cleanup_playbook, extra_vars)
