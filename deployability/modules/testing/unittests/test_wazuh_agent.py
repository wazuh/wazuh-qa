# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import pytest
from mock import patch, MagicMock, call

from modules.testing.tests.helpers.agent import WazuhAgent


@pytest.mark.parametrize('os_type, architecture, distribution', [('linux', 'x86_64', 'rpm'),
                                                                 ('linux', 'aarch64', 'rpm'),
                                                                 ('linux', 'x86_64', 'deb'),
                                                                 ('linux', 'aarch64', 'deb'),
                                                                 ('windows', None, None), 
                                                                 ('macos', 'intel', None),
                                                                 ('macos', 'apple', None),])
@pytest.mark.parametrize('live', [True, False])
@pytest.mark.parametrize('logger_mock', [{'logger_to_patch': 'modules.testing.tests.helpers.agent.logger'}],
                         indirect=True)
@patch('modules.testing.tests.helpers.agent.Executor.execute_commands')
@patch('modules.testing.tests.helpers.agent.HostInformation')
def test_install_agent(hostInfo: MagicMock,  execute_command_mock: MagicMock, logger_mock: MagicMock,
                                     os_type: str, architecture: str, distribution: str, live: bool):
    wazuh_version = 'x.x.x'
    inventory_path = '/inventory_path'
    agent_name = 'agent_name'
    if live:
        s3_url = 'packages'
        release = wazuh_version[0:3]
    else:
        s3_url = 'packages-dev'
        release = 'pre-release'
    commands = []
    if 'linux' in os_type:
        if distribution == 'rpm' and 'x86_64' in architecture:
            commands.extend([
                f"curl -o wazuh-agent-{wazuh_version}-1.x86_64.rpm https://{s3_url}.wazuh.com/{release}/yum/wazuh-"
                f"agent-{wazuh_version}-1.x86_64.rpm && sudo WAZUH_MANAGER='MANAGER_IP' WAZUH_AGENT_NAME="
                f"'{agent_name}' rpm -ihv wazuh-agent-{wazuh_version}-1.x86_64.rpm"
            ])
        elif distribution == 'rpm' and 'aarch64' in architecture:
            commands.extend([
                f"curl -o wazuh-agent-{wazuh_version}-1aarch64.rpm https://{s3_url}.wazuh.com/{release}/yum/"
                f"wazuh-agent-{wazuh_version}-1.aarch64.rpm && sudo WAZUH_MANAGER='MANAGER_IP' WAZUH_AGENT_NAME='"
                f"{agent_name}' rpm -ihv wazuh-agent-{wazuh_version}-1.aarch64.rpm"
            ])
        elif distribution == 'deb' and 'x86_64' in architecture:
            commands.extend([
                f"wget https://{s3_url}.wazuh.com/{release}/apt/pool/main/w/wazuh-agent/wazuh-agent_{wazuh_version}"
                f"-1_amd64.deb && sudo WAZUH_MANAGER='MANAGER_IP' WAZUH_AGENT_NAME='{agent_name}' "
                f"dpkg -i ./wazuh-agent_{wazuh_version}-1_amd64.deb"
            ])
        elif distribution == 'deb' and 'aarch64' in architecture:
            commands.extend([
                f"wget https://{s3_url}.wazuh.com/{release}/apt/pool/main/w/wazuh-agent/wazuh-agent_"
                f"{wazuh_version}-1_arm64.deb && sudo WAZUH_MANAGER='MANAGER_IP' WAZUH_AGENT_NAME='{agent_name}' "
                f"dpkg -i ./wazuh-agent_{wazuh_version}-1arm64.deb"
            ])
        system_commands = [
                "systemctl daemon-reload",
                "systemctl enable wazuh-agent",
                "systemctl start wazuh-agent",
                "systemctl status wazuh-agent"
        ]

        commands.extend(system_commands)
    elif 'windows' in os_type :
        commands.extend([
            f"Invoke-WebRequest -Uri https://packages.wazuh.com/{release}/windows/wazuh-agent-{wazuh_version}-1.msi"
            "-OutFile ${env.tmp}\\wazuh-agent;"
            "msiexec.exe /i ${env.tmp}\\wazuh-agent /q"
            f"WAZUH_MANAGER='MANAGER_IP'"
            f"WAZUH_AGENT_NAME='{agent_name}'"
            f"WAZUH_REGISTRATION_SERVER='MANAGER_IP'",
            "NET START WazuhSvc",
            "NET STATUS WazuhSvc"
            ])
    elif 'macos' in os_type:
        if 'intel' in architecture:
            commands.extend([
                f'curl -so wazuh-agent.pkg https://{s3_url}.wazuh.com/{release}/macos/wazuh-agent-{wazuh_version}-'
                '1.intel64.pkg && echo "WAZUH_MANAGER=\'MANAGER_IP\' && WAZUH_AGENT_NAME=\'{agent_name}\'" > "'
                '/tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /'
            ])
        elif 'apple' in architecture:
            commands.extend([
                f'curl -so wazuh-agent.pkg https://{s3_url}.wazuh.com/{release}/macos/wazuh-agent-{wazuh_version}'
                '-1.arm64.pkg && echo "WAZUH_MANAGER=\'MANAGER_IP\' && WAZUH_AGENT_NAME=\'{agent_name}\'" > '
                '/tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /'
            ])
        system_commands = [
                '/Library/Ossec/bin/wazuh-control start',
                '/Library/Ossec/bin/wazuh-control status'
        ]

    with patch.object(hostInfo, 'get_os_type', return_value=os_type) as get_os_type_mock, \
         patch.object(hostInfo, 'get_linux_distribution', return_value=distribution) as get_linux_distro_mock, \
         patch.object(hostInfo, 'get_architecture', return_value=architecture) as get_architecture_mock, \
         patch.object(hostInfo, 'get_os_name_and_version_from_inventory',
                      return_value=f"{os_type}-x.x.x") as get_name_and_version_mock:
        WazuhAgent.install_agent(inventory_path, agent_name, wazuh_version, None, live)
    
    get_os_type_mock.assert_called_once_with(inventory_path)
    get_name_and_version_mock.assert_called_once_with(inventory_path)
    if os_type == 'linux':
        get_linux_distro_mock.assert_called_once_with(inventory_path)
        get_architecture_mock.assert_called_once_with(inventory_path)
    logger_mock.info.assert_called_once_with(f'Installing Agent in {os_type}-x.x.x')
    execute_command_mock.assert_called_once_with(inventory_path, commands)


def test_install_agents():
    inventory_paths = ['/inventory_path_1', '/inventory_path_2']
    wazuh_versions = ['x.y.z', 'j.q.k']
    agent_names = ['agent_1', 'agent_2']
    wazuh_revisions = ['rev_1', 'rev_2']
    live = [True, False]
    with patch('modules.testing.tests.helpers.agent.WazuhAgent.install_agent') as install_mock:
        WazuhAgent.install_agents(inventories_paths=inventory_paths, wazuh_revisions=wazuh_revisions,
                                  wazuh_versions=wazuh_versions, agent_names=agent_names, live=live)
    install_mock.assert_has_calls([
        call(inventory_paths[0], wazuh_versions[0], wazuh_revisions[0], agent_names[0], live[0]),
        call(inventory_paths[1], wazuh_versions[1], wazuh_revisions[1], agent_names[1], live[1]),
    ])
    
