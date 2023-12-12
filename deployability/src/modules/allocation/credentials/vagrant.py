from .base import Credentials


class VagrantCredential(Credentials):
    def __init__(self, name, path):
        self.name = name
        self.path = path
        super().__init__()
