import yaml
import json

from wazuh_testing.tools.file import read_file


class AnsibleOutput:
    """Represent the result of an execution of ansible.

    Args:
        ansible_runner (Runner): Ansible instances that will be defined in the ansible inventory.

    Attributes:
        rc (int): Result status code.
        status (string): Status of the ansible run <unstarted|successful|failed>.
        stdout_file (string): Path to stdout result data.
        stderr_file (string): Path to stderr result data.
        stats (dict): Ansible run result stats (ok, changed, failures, ignored ...).
        stdout (string): Stdout string of the ansible run.
        stderr (string): Stderr string of the ansible run.
    """
    def __init__(self, ansible_runner):
        self.rc = ansible_runner.rc
        self.status = ansible_runner.status
        self.stdout_file = ansible_runner.stdout.name
        self.stderr_file = ansible_runner.stderr.name
        self.stats = ansible_runner.stats
        self.stdout = read_file(self.stdout_file)
        self.stderr = read_file(self.stderr_file)

    def __str__(self):
        """Define how the class object is to be displayed."""
        return yaml.dump({'rc': self.rc, 'status': self.status, 'stats': self.stats, 'stdout_file': self.stdout_file,
                          'stderr_file': self.stderr_file, 'stdout': self.stdout, 'stderr': self.stderr
                          }, allow_unicode=True, sort_keys=False)

    def __repr__(self):
        """Representation of the object of the class in string format"""
        return json.dumps({'rc': self.rc, 'status': self.status, 'stats': self.stats, 'stdout_file': self.stdout_file,
                          'stderr_file': self.stderr_file, 'stdout': self.stdout, 'stderr': self.stderr
                           })
