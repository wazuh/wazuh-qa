# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import requests
import socket

from .constants import CLUSTER_CONTROL, AGENT_CONTROL, WAZUH_CONF, WAZUH_ROOT
from .executor import Executor, WazuhAPI
from .generic import HostInformation, CheckFiles
from modules.testing.utils import logger
from .utils import Utils


class WazuhCentralComponents:

    @staticmethod
    def install_aio(inventory_path, wazuh_version) -> None:
        """
        Installs Wazuh central components (AIO) in the host

        Args:
            inventory_path (str): host's inventory path
            wazuh_version (str): major.minor.patch

        """
        wazuh_version = '.'.join(wazuh_version.split('.')[:2])
        os_name = HostInformation.get_os_name_from_inventory(inventory_path)

        if 'curl' in Executor.execute_command(inventory_path, 'which curl'):
            commands = [
                f"curl -sO https://packages.wazuh.com/{wazuh_version}/wazuh-install.sh && sudo bash ./wazuh-install.sh -a --ignore-check"
            ]
        else:
            commands = [
                f"wget https://packages.wazuh.com/{wazuh_version}/wazuh-install.sh && sudo bash ./wazuh-install.sh -a --ignore-check"
            ]


        logger.info(f'Installing Wazuh AIO in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def uninstall_aio(inventory_path) -> None:
        """
        Uninstall Wazuh Central Components AIO in the host

        Args:
            inventory_paths (str): hosts' inventory path
        """

        commands = ['bash wazuh-install.sh --uninstall --ignore-check']

        logger.info(f'Uninstalling Wazuh AIO in {HostInformation.get_os_name_and_version_from_inventory(inventory_path)}')
        Executor.execute_commands(inventory_path, commands)


    @staticmethod
    def _install_aio_callback(wazuh_params, host_params):
        WazuhCentralComponents.install_aio(host_params, wazuh_params['wazuh_version'])


    @staticmethod
    def _uninstall_aio_callback(host_params):
        WazuhCentralComponents.uninstall_aio(host_params)


    @staticmethod
    def perform_action_and_scan(host_params, action_callback) -> dict:
        """
        Takes scans using filters, the callback action and compares the result

        Args:
            host_params (str): host parameters
            callback (cb): callback (action)

        Returns:
            result (dict): comparison brief

        """
        result = CheckFiles.perform_action_and_scan(host_params, action_callback)
        os_name = HostInformation.get_os_name_from_inventory(host_params)
        logger.info(f'Applying filters in checkfiles in {HostInformation.get_os_name_and_version_from_inventory(host_params)}')

        if 'debian' in os_name:
            filter_data = {
                '/boot': {'added': [], 'removed': [], 'modified': ['grubenv']},
                '/usr/bin': {
                    'added': [
                        'unattended-upgrade', 'gapplication', 'add-apt-repository', 'gpg-wks-server', 'pkexec', 'gpgsplit',
                        'watchgnupg', 'pinentry-curses', 'gpg-zip', 'gsettings', 'gpg-agent', 'gresource', 'gdbus',
                        'gpg-connect-agent', 'gpgconf', 'gpgparsemail', 'lspgpot', 'pkaction', 'pkttyagent', 'pkmon',
                        'dirmngr', 'kbxutil', 'migrate-pubring-from-classic-gpg', 'gpgcompose', 'pkcheck', 'gpgsm', 'gio',
                        'pkcon', 'gpgtar', 'dirmngr-client', 'gpg', 'filebeat', 'gawk', 'curl', 'update-mime-database',
                        'dh_installxmlcatalogs', 'appstreamcli', 'lspgpot', 'symcryptrun'
                    ],
                    'removed': ['filebeat'],
                    'modified': []
                },
                '/root': {'added': ['trustdb.gpg', 'lesshst', 'ssh'], 'removed': ['filebeat'], 'modified': []},
                '/usr/sbin': {
                    'added': [
                        'update-catalog', 'applygnupgdefaults', 'addgnupghome', 'install-sgmlcatalog', 'update-xmlcatalog'
                    ],
                    'removed': [],
                    'modified': []
                }
            }
        else:
            filter_data = {
                '/boot': {
                    'added': ['grub2', 'loader', 'vmlinuz', 'System.map', 'config-', 'initramfs'],
                    'removed': [],
                    'modified': ['grubenv']
                },
                '/usr/bin': {'added': ['filebeat'], 'removed': ['filebeat'], 'modified': []},
                '/root': {'added': ['trustdb.gpg', 'lesshst'], 'removed': [], 'modified': ['.rnd']},
                '/usr/sbin': {'added': [], 'removed': [], 'modified': []}
            }

        # Use of filters
        for directory, changes in result.items():
            if directory in filter_data:
                for change, files in changes.items():
                    if change in filter_data[directory]:
                        result[directory][change] = [file for file in files if file.split('/')[-1] not in filter_data[directory][change]]

        return result

    @staticmethod
    def perform_install_and_scan_for_aio(host_params, wazuh_params) -> None:
        """
        Coordinates the action of install the Wazuh AIO and compares the checkfiles

        Args:
            host_params (str): host parameters
            wazuh_params (str): wazuh parameters

        """
        action_callback = lambda: WazuhCentralComponents._install_aio_callback(wazuh_params, host_params)
        result = WazuhCentralComponents.perform_action_and_scan(host_params, action_callback)
        logger.info(f'Pre and post install checkfile comparison in {HostInformation.get_os_name_and_version_from_inventory(host_params)}: {result}')
        WazuhCentralComponents.assert_results(result)


    @staticmethod
    def perform_uninstall_and_scan_for_aio(host_params) -> None:
        """
        Coordinates the action of uninstall the Wazuh AIO and compares the checkfiles

        Args:
            host_params (str): host parameters
            wazuh_params (str): wazuh parameters

        """
        action_callback = lambda: WazuhCentralComponents._uninstall_aio_callback(host_params)
        result = WazuhCentralComponents.perform_action_and_scan(host_params, action_callback)
        logger.info(f'Pre and post uninstall checkfile comparison in {HostInformation.get_os_name_and_version_from_inventory(host_params)}: {result}')
        WazuhCentralComponents.assert_results(result)


    @staticmethod
    def assert_results(result) -> None:
        """
        Gets the status of an agent given its name.

        Args:
            result (dict): result of comparison between pre and post action scan

        """
        categories = ['/root', '/usr/bin', '/usr/sbin', '/boot']
        actions = ['added', 'modified', 'removed']
        # Testing the results
        for category in categories:
            for action in actions:
                assert result[category][action] == [], logger.error(f'{result[category][action]} was found in: {category} {action}')
