from pathlib import Path

from modules.generic import Playbook, Ansible, AnsibleInventory
from modules.generic.utils import Utils

from .models import InputPayload, ExtraVars


class Tester:
    _playbooks_dir = Playbook.PLAYBOOKS_PATH / 'tests'

    @classmethod
    def run(cls, payload: InputPayload) -> None:

        payload = InputPayload(**dict(payload))
        playbooks = cls._get_playbooks()
        cls._run_playbooks(payload, playbooks)
        if not payload.cleanup:
            return
        # cls._cleanup(payload)

    @classmethod
    def _get_playbooks(cls) -> list[Path]:
        # This will be replaced with the templates rendering from Playbook
        variables_rendering = {}
        variables_rendering['templates_path'] = str(cls._playbooks_dir)
        return [f for f in cls._playbooks_dir.iterdir() if str(f).endswith('.yml')]

    @classmethod
    def _run_playbooks(cls, payload: InputPayload, playbooks: list[Path]) -> None:
        ansible_data = AnsibleInventory(**Utils.load_from_yaml(payload.inventory))
        manager_ip = Utils.load_from_yaml(payload.dependency, map_keys={'ansible_host': 'ansible_host'}, specific_key="ansible_host")
        extra_vars = ExtraVars(**payload.model_dump(exclude={'dependency'}), dependency=manager_ip)
        # self.install_list = payload.install
        # print(ansible_data.model_dump())
        ansible = Ansible(ansible_data=ansible_data.model_dump())
        # self.ansible.render_playbooks(self.component_information)
        # playbook = {
        #   'hosts': self.ansible.ansible_host,
        #   'become': True,
        #   'tasks': tasks
        # }

        # status = self.ansible.run_playbook(playbook)

        # ansible = Ansible(payload.inventory)
        variables_rendering = extra_vars.model_dump()
        variables_rendering['base_path'] = '/tmp/wazuh-qa/tests/'
        variables_rendering['templates_path'] = cls._playbooks_dir / f'test_{payload.component}'
        
        for test in payload.tests:
            playbook = next((str(p) for p in playbooks if test in str(p)), None)
            print("\nTEST:", test)
            playbook = ansible.render_playbooks({**variables_rendering, 'test': test })
            if not playbook:
                raise ValueError(f'Playbook for test "{test}" not found')
            print(playbook)
            ansible.run_playbook(playbook, extra_vars.model_dump())

    @classmethod
    def _cleanup(cls, payload: InputPayload) -> None:
        ansible = Ansible(payload.inventory)
        ansible.run_playbook(Playbook.PLAYBOOKS_PATH / 'clear.yml')
