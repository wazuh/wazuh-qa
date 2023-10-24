import pytest
import os
import stat

repo_gpg_file = "/usr/share/keyrings/wazuh.gpg"
repo_gpg_permissions = "644"
repo_wazuh_file = "/etc/apt/sources.list.d/wazuh.list"
repo_wazuh_permissions = "644"

def test_gpg_file():
    assert os.path.exists(repo_gpg_file) == True

def test_gpg_permissions():
    st = oct(os.stat(repo_gpg_file).st_mode)[-3:]
    assert st == repo_gpg_permissions

def test_wazuh_repo_file():
    assert os.path.exists(repo_wazuh_file) == True

def test_wazuh_permissions():
    st = oct(os.stat(repo_wazuh_file).st_mode)[-3:]
    assert st == repo_wazuh_permissions