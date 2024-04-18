# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import yaml
import paramiko, logging, time
import winrm

from pathlib import Path

from .aws.provider import AWSProvider, AWSConfig
from .generic import Instance, Provider, models
from .generic.utils import logger
from .vagrant.provider import VagrantProvider, VagrantConfig


PROVIDERS = {'vagrant': VagrantProvider, 'aws': AWSProvider}
CONFIGS = {'vagrant': VagrantConfig, 'aws': AWSConfig}


class Allocator:
    """
    Allocator class to manage instances based on the payload action.
    """
    @classmethod
    def run(cls, payload: models.InputPayload) -> None:
        """
        Executes the appropriate method based on the payload action.

        Args:
            payload (InputPayload): The payload containing the action parameters.
        """
        payload = models.InputPayload(**dict(payload))
        # Detect the action and call the appropriate method.
        if payload.action == 'create':
            logger.info(f"Creating instance at {payload.working_dir}")
            return cls.__create(payload)
        elif payload.action == 'delete':
            logger.info(f"Deleting instance from trackfile {payload.track_output}")
            return cls.__delete(payload)

    # Internal methods

    @classmethod
    def __create(cls, payload: models.CreationPayload):
        """
        Creates an instance and generates the inventory and track files.

        Args:
            payload (CreationPayload): The payload containing the parameters
                                        for instance creation.
        """
        instance_params = models.CreationPayload(**dict(payload))
        provider: Provider = PROVIDERS[payload.provider]()
        config = cls.___get_custom_config(payload)
        instance = provider.create_instance(
            payload.working_dir, instance_params, config, payload.ssh_key)
        logger.info(f"Instance {instance.identifier} created.")
        # Start the instance.
        instance.start()
        logger.info(f"Instance {instance.identifier} started.")
        # Generate the inventory and track files.
        inventory = cls.__generate_inventory(instance, payload.inventory_output)
        # Validate connection
        check_connection = cls.__check_connection(inventory)
        track_file = cls.__generate_track_file(instance, payload.provider, payload.track_output)
        if check_connection is False:
            if payload.rollback:
                logger.warning(f"Rolling back instance creation.")
                track_payload = {'track_output': track_file}
                cls.__delete(track_payload)
                logger.info(f"Instance {instance.identifier} deleted.")
            else:
                logger.warning(f'The VM will not be automatically removed. Please remove it executing Allocation module with --action delete.')

    @classmethod
    def __delete(cls, payload: models.InstancePayload) -> None:
        """
        Deletes an instance based on the data from the track file.

        Args:
            payload (InstancePayload): The payload containing the parameters
                                        for instance deletion.
        """
        payload = models.TrackPayload(**dict(payload))
        # Read the data from the track file.
        with open(payload.track_output, 'r') as f:
            track = models.TrackOutput(**yaml.safe_load(f))
        provider = PROVIDERS[track.provider]()
        provider.destroy_instance(models.InstancePayload(**dict(track)))
        logger.info(f"Instance {track.identifier} deleted.")

    @staticmethod
    def ___get_custom_config(payload: models.CreationPayload) -> models.ProviderConfig | None:
        """
        Gets the custom configuration from a file.

        Args:
            payload (CreationPayload): The payload containing the parameters
                                        for instance creation.

        Returns:
            ProviderConfig: The configuration object.
        """
        config = payload.custom_provider_config
        if not config:
            return None
        # Read the custom config file and validate it.
        config_model: models.ProviderConfig = CONFIGS[payload.provider]
        with open(config, 'r') as f:
            logger.info(f"Using custom provider config from {config}")
            config = config_model(**yaml.safe_load(f))
        return config

    @staticmethod
    def __generate_inventory(instance: Instance, inventory_path: Path) -> None:
        """
        Generates an inventory file.

        Args:
            instance (Instance): The instance for which the inventory file is generated.
            inventory_path (Path): The path where the inventory file will be generated.
        """
        if inventory_path is None:
            inventory_path = Path(instance.path, 'inventory.yml')
        if not str(inventory_path).endswith('.yml') and not str(inventory_path).endswith('.yaml'):
            inventory_path = Path(inventory_path, 'inventory.yml')
        if not inventory_path.parent.exists():
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
        ssh_config = instance.ssh_connection_info()
        if instance.platform == 'windows':
            inventory = models.InventoryOutput(ansible_host=ssh_config.hostname,
                                                ansible_user=ssh_config.user,
                                                ansible_port=ssh_config.port,
                                                ansible_password=ssh_config.password,
                                                ansible_connection='winrm',
                                                ansible_winrm_server_cert_validation='ignore')
        elif not ssh_config.private_key:
            inventory = models.InventoryOutput(ansible_host=ssh_config.hostname,
                                                ansible_user=ssh_config.user,
                                                ansible_port=ssh_config.port,
                                                ansible_connection='ssh',
                                                ansible_password=ssh_config.password,
                                                ansible_ssh_common_args='-o StrictHostKeyChecking=no')
        else:
            inventory = models.InventoryOutput(ansible_host=ssh_config.hostname,
                                                ansible_user=ssh_config.user,
                                                ansible_port=ssh_config.port,
                                                ansible_connection='ssh',
                                                ansible_ssh_private_key_file=str(ssh_config.private_key),
                                                ansible_ssh_common_args='-o StrictHostKeyChecking=no')
        with open(inventory_path, 'w') as f:
            yaml.dump(inventory.model_dump(exclude_none=True), f)
        logger.info(f"Inventory file generated at {inventory_path}")
        return inventory

    @staticmethod
    def __generate_track_file(instance: Instance, provider_name: str,  track_path: Path) -> None:
        """
        Generates a track file.

        Args:
            instance (Instance): The instance for which the track file is to be generated.
            provider_name (str): The name of the provider.
            track_path (Path): The path where the track file will be generated.
        """
        if track_path is None:
            track_path = Path(instance.path, 'track.yml')
        if not str(track_path).endswith('.yml') and not str(track_path).endswith('.yaml'):
            track_path = Path(track_path, 'track.yml')
        if not track_path.parent.exists():
            track_path.parent.mkdir(parents=True, exist_ok=True)
        ssh_config = instance.ssh_connection_info()
        track = models.TrackOutput(identifier=instance.identifier,
                                    provider=provider_name,
                                    instance_dir=str(instance.path),
                                    key_path=str(instance.credentials.key_path),
                                    host_identifier=str(instance.host_identifier),
                                    host_instance_dir=str(instance.host_instance_dir),
                                    ssh_port=ssh_config.port,
                                    platform=instance.platform,
                                    arch=instance.arch)
        with open(track_path, 'w') as f:
            yaml.dump(track.model_dump(), f)
        if Path(str(instance.path) + "/port.txt").exists():
            Path(str(instance.path) + "/port.txt").unlink()
        if Path(str(instance.path) + "/ppc-key").exists():
            Path(str(instance.path) + "/ppc-key").unlink()
        logger.info(f"Track file generated at {track_path}")
        return track_path

    @staticmethod
    def __check_connection(inventory: models.InventoryOutput, attempts=30, sleep=30) -> None:
        """
        Checks if the ssh connection is successful.

        Args:
            inventory (InventoryOutput): The inventory object.
            attempts (int): The number of attempts to try the connection.
            sleep (int): The time to wait between attempts.

        """

        for attempt in range(1, attempts + 1):
            if inventory.ansible_connection == 'winrm':
                if inventory.ansible_port == 5986:
                    protocol = 'https'
                else:
                    protocol = 'http'
                endpoint_url = f'{protocol}://{inventory.ansible_host}:{inventory.ansible_port}'
                try:
                    session = winrm.Session(endpoint_url, auth=(inventory.ansible_user, inventory.ansible_password),transport='ntlm', server_cert_validation='ignore')
                    cmd = session.run_cmd('ipconfig')
                    if cmd.status_code == 0:
                        logger.info("WinRM connection successful.")
                        return True
                    else:
                        logger.error(f'WinRM connection failed. Check the credentials in the inventory file.')
                        return False
                except Exception as e:
                    logger.warning(f'Error on attempt {attempt} of {attempts}: {e}')
                time.sleep(sleep)
            else:
                ssh = paramiko.SSHClient()
                paramiko.util.get_logger("paramiko").setLevel(logging.WARNING)
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if inventory.ansible_ssh_private_key_file:
                    ssh_parameters = {
                        'hostname': inventory.ansible_host,
                        'port': inventory.ansible_port,
                        'username': inventory.ansible_user,
                        'key_filename': inventory.ansible_ssh_private_key_file
                    }
                else:
                    ssh_parameters = {
                        'hostname': inventory.ansible_host,
                        'port': inventory.ansible_port,
                        'username': inventory.ansible_user,
                        'password': inventory.ansible_password
                    }
                try:
                    ssh.connect(**ssh_parameters)
                    logger.info("SSH connection successful.")
                    ssh.close()
                    return True
                except paramiko.AuthenticationException:
                    logger.error(f'Authentication error. Check the credentials in the inventory file.')
                    return False
                except Exception as e:
                    logger.warning(f'Error on attempt {attempt} of {attempts}: {e}')
                time.sleep(sleep)

        logger.error(f'Connection attempts failed after {attempts} tries. Connection timeout.')
        return False
