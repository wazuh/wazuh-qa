# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import time
import os
from pathlib import Path

import yaml
import paramiko
import logging
import winrm

from .aws.provider import AWSProvider, AWSConfig
from .generic import Instance, Provider, models
from .generic.utils import logger, logger_with_instance_name
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

        global logger
        logger = logger_with_instance_name(instance)
        logger.info(f"Instance {instance.identifier} created.")
        # Start the instance.
        instance.start()
        logger.info(f"Instance {instance.identifier} started.")
        # Generate the inventory and track files.
        inventory = cls.__generate_inventory(instance, instance_params.composite_name)
        track_file = cls.__generate_track_file(instance, payload.provider)
        cls.__check_auxiliar_files_path(cls, instance_params.inventory_output, instance, 'inventory')
        track_file = cls.__check_auxiliar_files_path(cls, instance_params.track_output, instance, 'track')
        # Validate connection
        check_connection = cls.__check_connection(inventory)
        if check_connection is False:
            if payload.rollback:
                logger.warning(f"Rolling back instance creation.")
                track_payload = {'track_output': track_file}
                cls.__delete(track_payload)
            else:
                logger.warning(f'The VM will not be automatically removed. Please remove it executing Allocation module with --action delete.')
        else:
            logger.info(f"Instance {instance.identifier} created successfully.")

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

        global logger
        logger = logger_with_instance_name(track)
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
    def __generate_inventory(instance: Instance, composite_name: str) -> None:
        """
        Generates an inventory file.

        Args:
            instance (Instance): The instance for which the inventory file is generated.
            composite_name (str): Composite name of the instance to be provisioned.
        """
        ssh_config = instance.ssh_connection_info()
        if instance.platform == 'windows':
            if str(composite_name.split("-")[1]) == 'sign':
                inventory = models.InventoryOutput(ansible_host=ssh_config.hostname,
                                                    ansible_user=ssh_config.user,
                                                    ansible_port=2200,
                                                    ansible_connection='ssh',
                                                    ansible_password=ssh_config.password,
                                                    ansible_ssh_common_args='-o StrictHostKeyChecking=no')
            else:
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
        inventory_path = Path(os.path.join(instance.path, 'inventory.yaml'))
        with open(inventory_path, 'w') as f:
            yaml.dump(inventory.model_dump(exclude_none=True), f)
        return inventory

    @staticmethod
    def __generate_track_file(instance: Instance, provider_name: str) -> None:
        """
        Generates a track file.

        Args:
            instance (Instance): The instance for which the track file is to be generated.
            provider_name (str): The name of the provider.
        """
        inventory_path = Path(os.path.join(instance.path, 'inventory.yaml'))
        with open(str(inventory_path), 'r') as f:
            inventory = models.InventoryOutput(**yaml.safe_load(f))
        port = inventory.ansible_port
        track = models.TrackOutput(identifier=instance.identifier,
                                    name=instance.name,
                                    provider=provider_name,
                                    instance_dir=str(instance.path),
                                    key_path=str(instance.credentials.key_path),
                                    host_identifier=str(instance.host_identifier),
                                    host_instance_dir=str(instance.host_instance_dir),
                                    ssh_port=port,
                                    platform=instance.platform,
                                    arch=instance.arch,
                                    virtualizer=str(instance.virtualizer))
        track_path = Path(os.path.join(instance.path, 'track.yaml'))
        with open(track_path, 'w') as f:
            yaml.dump(track.model_dump(), f)
        if Path(str(instance.path) + "/port.txt").exists():
            Path(str(instance.path) + "/port.txt").unlink()
        if Path(str(instance.path) + "/ppc-key").exists():
            Path(str(instance.path) + "/ppc-key").unlink()
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
                except Exception as e:
                    logger.warning(f'Error on attempt {attempt} of {attempts}: {e}')
                time.sleep(sleep)

        logger.error(f'Connection attempts failed after {attempts} tries. Connection timeout.')
        return False

    @staticmethod
    def __check_auxiliar_files_path(cls, path: Path, instance: Instance, file: str) -> Path:
        """
        Check the path of the auxiliar files.

        Args:
            path (Path): The path of the instance.
            instance (Instance): The instance object.
            file (str): The type of file.

        Returns:
            Path: The path of the auxiliar files.
        """
        source = Path(os.path.join(instance.path, file + '.yaml'))
        destination = path
        track_file = Path(os.path.join(instance.path, 'track.yaml'))
        track_payload = {'track_output': track_file}

        if path is None:
            logger.info(f"The {file} file generated at {source}")
            return source

        if not path.suffix.__contains__('.'):
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
            destination = path / (file + '.yaml')
            os.replace(source, destination)
            logger.info(f"The {file} file generated at {destination}")
            return destination

        if str(path).endswith('.yml') or str(path).endswith('.yaml'):
            path.parent.mkdir(parents=True, exist_ok=True)
            if file in os.path.basename(path):
                os.replace(source, destination)
                logger.info(f"The {file} file generated at {destination}")
                return destination
            elif file == 'inventory' and 'track' in os.path.basename(path):
                logger.error(f"Confusing definition in the name of the inventory file, we recommend that it contain the word inventory to facilitate identification of the file type")
                logger.error(f"Rolling back instance creation.")
                cls.__delete(track_payload)
                raise ValueError(f"Confusing definition in the name of the inventory file, we recommend that it contain the word inventory to facilitate identification of the file type")
            elif file == 'track' and 'inventory' in os.path.basename(path):
                logger.error(f"Confusing definition in the name of the track file, we recommend that it contain the word track to facilitate identification of the file type")
                logger.error(f"Rolling back instance creation.")
                cls.__delete(track_payload)
                raise ValueError(f"Confusing definition in the name of the track file, we recommend that it contain the word track to facilitate identification of the file type")
            else:
                base, ext = os.path.splitext(path)
                os.replace(source, Path(f"{base}-{file}{ext}"))
                logger.info(f"The {file} file generated at {base}-{file}{ext}")
                return Path(f"{base}-{file}{ext}")
        else:
            logger.error(f"Rolling back instance creation.")
            cls.__delete(track_payload)
            raise ValueError(f"Invalid path for auxiliary file, must be a yaml file: {path}")
