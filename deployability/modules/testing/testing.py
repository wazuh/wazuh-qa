from pathlib import Path

from modules.generic import Playbook, Ansible

from .models import InputPayload, ExtraVars


class Tester:
    _playbooks_dir = Playbook.PLAYBOOKS_PATH / 'tests'

    @classmethod
    def run(cls, payload: InputPayload) -> None:
        payload = InputPayload(**dict(payload))
        extra_vars = ExtraVars(**payload.model_dump())
        playbooks = cls._get_playbooks()
        cls._run_playbooks(payload, playbooks, extra_vars)
        if not payload.cleanup:
            return
        cls._cleanup(payload)

    @classmethod
    def _get_playbooks(cls) -> list[Path]:
        # This will be replaced with the templates rendering from Playbook
        return [f for f in cls._playbooks_dir.iterdir() if str(f).endswith('.yml')]

    @classmethod
    def _run_playbooks(cls, payload: InputPayload, playbooks: list[Path], extra_vars: ExtraVars) -> None:
        ansible = Ansible(payload.inventory, cls._playbooks_dir)
        for test in payload.tests:
            playbook = next(p for p in playbooks if test in str(p))
            if not playbook:
                raise ValueError(f'Playbook for test "{test}" not found')
            ansible.run_playbook(playbook, extra_vars.model_dump())

    @classmethod
    def _cleanup(cls, payload: InputPayload) -> None:
        ansible = Ansible(payload.inventory, cls._playbooks_dir)
        ansible.run_playbook('clear.yml')
