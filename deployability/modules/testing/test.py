from pathlib import Path
from modules.generic.playbook import Playbook


class Test:
    PLAYBOOKS_PATH = Playbook.PLAYBOOKS_PATH / "tests"

    def __init__(self):
        self.playbooks = self.get_playbooks()

    def get_playbooks(self) -> list[Path]:
        return [f for f in self.PLAYBOOKS_PATH.iterdir() if str(f).endswith(".yml")]
