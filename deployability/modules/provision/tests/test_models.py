# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""modules.provision.models Unit tests."""
from pathlib import Path
import pytest

from modules.provision.models import InputPayload, ComponentInfo


@pytest.mark.parametrize('install', [(True), (False)])
def test_input_payload_constructor_components(install:bool):
    """Test InputPayload constructor install and uninstall parameters.

    Parameters
    ----------
    install : bool
        parameters for install and uninstall InputPayload constructor parameters.
    """
    path = '/my_inventory_path'
    components = [
        "{'component':'component_1', 'type':'component_type_1'}",
        "{'component':'component_2'}",
        "{'component':'linux wazuh-agent'}"]
    payload = InputPayload(inventory=path,
                           install=components if install else [],
                           uninstall=[] if install else components)
    assert payload.inventory == Path(path)
    comp_list = payload.install if install else payload.uninstall
    assert comp_list[0] == ComponentInfo(component='component_1', type='component_type_1')
    assert comp_list[1] == ComponentInfo(component='component_2', type='package')
    assert comp_list[2] == ComponentInfo(component='linux wazuh-agent', type='package')


@pytest.mark.parametrize('dependencies',[
                            (None),
                            (["{'manager': 'path/to/inventory.yaml'}", "{'agent': 'path/to/inventory.yaml'}"]),
                            ("[{'manager': 'path/to/inventory.yaml', 'agent': 'path/to/inventory.yaml'}]")])
def test_input_payload_constructor_dependencies(dependencies:str):
    """Test InputPayload constructor dependencies parameters."""
    path = '/my_inventory_path'
    components = ["{'component':'component_1', 'type':'component_type_1'}"]
    payload = InputPayload(inventory=path, install=components, uninstall=[], dependencies=dependencies)
    if dependencies:
        assert payload.dependencies.get('manager') == 'path/to/inventory.yaml'
        assert payload.dependencies.get('agent') == 'path/to/inventory.yaml'
    else:
        assert not payload.dependencies


def test_input_payload_constructor_fail():
    """Test InputPayload constructor invalid parameters."""
    with pytest.raises(ValueError, match='Invalid action: "install" or "uninstall" must be provided.'):
        InputPayload(inventory='/path', install=[], uninstall=[])
