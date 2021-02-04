# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import itertools
import os
import sys
import xml.etree.ElementTree as ET
from copy import deepcopy
from subprocess import check_call, DEVNULL, check_output
from typing import List, Any, Set

import pytest
import yaml

from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH, GEN_OSSEC, WAZUH_CONF, PREFIX


# customize _serialize_xml to avoid lexicographical order in XML attributes
def _serialize_xml(write, elem, qnames, namespaces,
                   short_empty_elements, **kwargs):
    tag = elem.tag
    text = elem.text
    if tag is ET.Comment:
        write("<!--%s-->" % text)
    elif tag is ET.ProcessingInstruction:
        write("<?%s?>" % text)
    else:
        tag = qnames[tag]
        if tag is None:
            if text:
                write(ET._escape_cdata(text))
            for e in elem:
                _serialize_xml(write, e, qnames, None,
                               short_empty_elements=short_empty_elements)
        else:
            write("<" + tag)
            items = list(elem.items())
            if items or namespaces:
                if namespaces:
                    for v, k in sorted(namespaces.items(),
                                       key=lambda x: x[1]):  # sort on prefix
                        if k:
                            k = ":" + k
                        write(" xmlns%s=\"%s\"" % (
                            k,
                            ET._escape_attrib(v)
                        ))
                for k, v in items:  # avoid lexicographical order for XML attributes
                    if isinstance(k, ET.QName):
                        k = k.text
                    if isinstance(v, ET.QName):
                        v = qnames[v.text]
                    else:
                        v = ET._escape_attrib(v)
                    write(" %s=\"%s\"" % (qnames[k], v))
            if text or len(elem) or not short_empty_elements:
                write(">")
                if text:
                    write(ET._escape_cdata(text))
                for e in elem:
                    _serialize_xml(write, e, qnames, None,
                                   short_empty_elements=short_empty_elements)
                write("</" + tag + ">")
            else:
                write(" />")
    if elem.tail:
        write(ET._escape_cdata(elem.tail))


ET._serialize_xml = _serialize_xml  # override _serialize_xml to avoid lexicographical order in XML attributes


def set_wazuh_conf(wazuh_conf: List[str]):
    """
    Set up Wazuh configuration. Wazuh will be restarted to apply it.

    Parameters
    ----------
    wazuh_conf : ET.ElementTree
        ElementTree with a custom Wazuh configuration.
    """
    write_wazuh_conf(wazuh_conf)
    print("Restarting Wazuh...")
    command = os.path.join(WAZUH_PATH, 'bin/wazuh-control')
    arguments = ['restart']
    check_call([command] + arguments, stdout=DEVNULL, stderr=DEVNULL)


def generate_wazuh_conf(args: List = None) -> ET.ElementTree:
    """
    Generate a configuration file for Wazuh.

    Parameters
    ----------
    args : list, optional
        Arguments to generate ossec.conf (install_type, distribuition, version). Default `None`

    Returns
    -------
    ET.ElementTree
        New Wazuh configuration generated from 'gen_ossec.sh'.
    """
    gen_ossec_args = args if args else ['conf', 'manager', 'rhel', '7']
    wazuh_config = check_output([GEN_OSSEC] + gen_ossec_args).decode(encoding='utf-8', errors='ignore')

    return ET.ElementTree(ET.fromstring(wazuh_config))


def get_wazuh_conf() -> List[str]:
    """
    Get current `ossec.conf` file content.

    Returns
    -------
    List of str
        A list containing all the lines of the `ossec.conf` file.
    """
    with open(WAZUH_CONF) as f:
        lines = f.readlines()
    return lines


def get_api_conf(path) -> dict:
    """Get current `api.yaml` file content.

    Parameters
    ----------
    path : str
        Path of config file.

    Returns
    -------
    current_conf : dict
        A dict containing all content of the `api.yaml` file.
    """
    current_conf = {}

    if os.path.isfile(path):
        with open(path) as f:
            current_conf = yaml.full_load(f)

    return current_conf


def write_wazuh_conf(wazuh_conf: List[str]):
    """
    Write a new configuration in 'ossec.conf' file.

    Parameters
    ----------
    wazuh_conf : List of str
        Lines to be written in the ossec.conf file.
    """
    with open(WAZUH_CONF, 'w') as f:
        f.writelines(wazuh_conf)


def write_api_conf(path: str, api_conf: dict):
    """
    Write a new configuration in 'api.yaml' file.

    Parameters
    ----------
    path : str
        Path of config file.
    api_conf : dict
        Dictionary to be written in the api.yaml file.
    """
    with open(path, 'w+') as f:
        yaml.dump(api_conf, f)


def write_security_conf(path: str, security_conf: dict):
    """
    Write a new configuration in 'security.yaml' file.

    Parameters
    ----------
    path : str
        Path of config file.
    security_conf : dict
        Dictionary to be written in the security.yaml file.
    """
    if not os.path.exists(path):
        from wazuh_testing.tools import OSSEC_UID, OSSEC_GID

        open(path, mode='w').close()
        os.chown(uid=OSSEC_UID, gid=OSSEC_GID, path=path)
    write_api_conf(path, security_conf)


def set_section_wazuh_conf(sections, template=None):
    """
    Set a configuration in a section of Wazuh. It replaces the content if it exists.

    Parameters
    ----------
    sections : list
        list of dicts with section and new elements
        section : str, optional
            Section of Wazuh configuration to replace. Default `'syscheck'`
        new_elements : list, optional
            List with dictionaries for settings elements in the section. Default `None`
    template : list of string, optional
        File content template

    Returns
    -------
    List of str
        List of str with the custom Wazuh configuration.
    """

    def create_elements(section: ET.Element, elements: List):
        """
        Insert new elements in a Wazuh configuration section.

        Parameters
        ----------
        section : ET.Element
            Section where the element will be inserted.
        elements : list
            List with the new elements to be inserted.

        Returns
        -------
        ET.ElementTree
            Modified Wazuh configuration.
        """
        tag = None
        for element in elements:
            for tag_name, properties in element.items():
                tag = ET.SubElement(section, tag_name)
                new_elements = properties.get('elements')
                attributes = properties.get('attributes')
                if attributes is not None:
                    for attribute in attributes:
                        if isinstance(attribute, dict):  # noqa: E501
                            for attr_name, attr_value in attribute.items():
                                tag.attrib[attr_name] = str(attr_value)
                if new_elements:
                    create_elements(tag, new_elements)
                else:
                    tag.text = str(properties.get('value'))
                    attributes = properties.get('attributes')
                    if attributes:
                        for attribute in attributes:
                            if attribute is not None and isinstance(attribute, dict):  # noqa: E501
                                for attr_name, attr_value in attribute.items():
                                    tag.attrib[attr_name] = str(attr_value)
                tag.tail = "\n    "
        tag.tail = "\n  "

    def purge_multiple_root_elements(str_list: List[str], root_delimeter: str = "</ossec_config>") -> List[str]:
        """
        Remove from the list all the lines located after the root element ends.

        This operation is needed before attempting to convert the list to ElementTree because if the ossec.conf had more
        than one `<ossec_config>` element as root the conversion would fail.

        Parameters
        ----------
        str_list : list of str
            The content of the ossec.conf file in a list of str.
        root_delimeter : str, optional
            The expected string to identify when the first root element ends, by default "</ossec_config>"

        Returns
        -------
        list of str
            The first N lines of the specified str_list until the root_delimeter is found. The rest of the list will be
            ignored.
        """
        line_counter = 0
        for line in str_list:
            line_counter += 1
            if root_delimeter in line:
                return str_list[0:line_counter]
        else:
            return str_list

    def to_elementTree(str_list: List[str]) -> ET.ElementTree:
        """
        Turn a list of str into an ElementTree object.

        As ElementTree does not support xml with more than one root element this function will parse the list first with
        `purge_multiple_root_elements` to ensure there is only one root element.

        Parameters
        ----------
        str_list : list of str
            A list of strings with every line of the ossec conf.

        Returns
        -------
        ElementTree
            A ElementTree object with the data of the `str_list`
        """
        str_list = purge_multiple_root_elements(str_list)
        return ET.ElementTree(ET.fromstringlist(str_list))

    def to_str_list(elementTree: ET.ElementTree) -> List[str]:
        """
        Turn an ElementTree object into a list of str.

        Parameters
        ----------
        elementTree : ElementTree
            A ElementTree object with all the data of the ossec.conf.

        Returns
        -------
        list of str
            A list of str containing all the lines of the ossec.conf.
        """
        return ET.tostringlist(elementTree.getroot(), encoding="unicode")

    # Get Wazuh configuration as a list of str
    raw_wazuh_conf = get_wazuh_conf() if template is None else template
    # Generate a ElementTree representation of the previous list to work with its sections
    wazuh_conf = to_elementTree(purge_multiple_root_elements(raw_wazuh_conf))
    for section in sections:
        section_conf = wazuh_conf.find(section['section'])
        # Create section if it does not exist, clean otherwise
        if not section_conf:
            section_conf = ET.SubElement(wazuh_conf.getroot(), section['section'])
            section_conf.text = '\n    '
            section_conf.tail = '\n\n  '
        else:
            prev_text = section_conf.text
            prev_tail = section_conf.tail
            section_conf.clear()
            section_conf.text = prev_text
            section_conf.tail = prev_tail

        # Insert section attributes
        attributes = section.get('attributes')
        if attributes:
            for attribute in attributes:
                if attribute is not None and isinstance(attribute, dict):  # noqa: E501
                    for attr_name, attr_value in attribute.items():
                        section_conf.attrib[attr_name] = str(attr_value)

        # Insert elements
        new_elements = section.get('elements', list())
        if global_parameters.fim_database_memory and section['section'] == 'syscheck':
            new_elements.append({'database': {'value': 'memory'}})
        if new_elements:
            create_elements(section_conf, new_elements)

    return to_str_list(wazuh_conf)


def expand_placeholders(mutable_obj, placeholders=None):
    """
    Search for placeholders and replace them by a value inside mutable_obj.

    Parameters
    ----------
    mutable_obj : mutable object
        Target object where the replacements are performed.
    placeholders : dict
        Each key is a placeholder and its value is the replacement. Default `None`

    Returns
    -------
    Reference
        Reference to `mutable_obj`
    """
    placeholders = {} if placeholders is None else placeholders
    if isinstance(mutable_obj, list):
        for index, value in enumerate(mutable_obj):
            if isinstance(value, (dict, list)):
                expand_placeholders(mutable_obj[index], placeholders=placeholders)
            elif value in placeholders:
                mutable_obj[index] = placeholders[value]

    elif isinstance(mutable_obj, dict):
        for key, value in mutable_obj.items():
            if isinstance(value, (dict, list)):
                expand_placeholders(mutable_obj[key], placeholders=placeholders)
            elif value in placeholders:
                mutable_obj[key] = placeholders[value]

    return mutable_obj


def add_metadata(dikt, metadata=None):
    """
    Create a new key 'metadata' in dikt if not already exists and updates it with metadata content.

    Parameters
    ----------
    dikt : dict
        Target dict to update metadata in.
    metadata : dict, optional
        Dict including the new properties to be saved in the metadata key.
    """
    if metadata is not None:
        new_metadata = dikt['metadata'] if 'metadata' in dikt else {}
        new_metadata.update(metadata)
        dikt['metadata'] = new_metadata


def process_configuration(config, placeholders=None, metadata=None):
    """
    Get a new configuration replacing placeholders and adding metadata.

    Both placeholders and metadata should have equal length.

    Parameters
    ----------
    config : dict
        Config to be enriched.
    placeholders : dict, optional
        Dict with the replacements.
    metadata : list of dict, optional
        List of dicts with the metadata keys to include in config.

    Returns
    -------
    dict
        Dict with enriched configuration.
    """
    new_config = expand_placeholders(deepcopy(config), placeholders=placeholders)
    add_metadata(new_config, metadata=metadata)

    return new_config


def load_wazuh_configurations(yaml_file_path: str, test_name: str, params: list = None, metadata: list = None) -> Any:
    """
    Load different configurations of Wazuh from a YAML file.

    Parameters
    ----------
    yaml_file_path : str
        Full path of the YAML file to be loaded.
    test_name : str
        Name of the file which contains the test that will be executed.
    params : list, optional
        List of dicts where each dict represents a replacement MATCH -> REPLACEMENT. Default `None`
    metadata : list, optional
        Custom metadata to be inserted in the configuration. Default `None`

    Returns
    -------
    Python object with the YAML file content

    Raises
    ------
    ValueError
        If the length of `params` and `metadata` are not equal.
    """
    params = [{}] if params is None else params
    metadata = [{}] if metadata is None else metadata
    if len(params) != len(metadata):
        raise ValueError(f"params and metadata should have the same length {len(params)} != {len(metadata)}")

    with open(yaml_file_path) as stream:
        configurations = yaml.safe_load(stream)

    if sys.platform == 'darwin':
        configurations = set_correct_prefix(configurations, PREFIX)

    return [process_configuration(configuration, placeholders=replacement, metadata=meta)
            for replacement, meta in zip(params, metadata)
            for configuration in configurations
            if test_name in expand_placeholders(configuration.get('apply_to_modules'), placeholders=replacement)]


def set_correct_prefix(configurations, new_prefix):
    """Insert the correct prefix in the paths of each configuration.

    In Mac OS X it is not possible to create files in the / directory.
    Therefore, it is necessary to replace those paths that do not contain a
    suitable prefix.

    This function checks if the path inside directories, ignore, nodiff and restrict sections
    contains a certain prefix, and if it does not contain it, it inserts it.

    Parameters
    ----------
    configurations : list
        List of configurations loaded from the YAML.
    new_prefix : str
        Prefix to be inserted before every path.

    Returns
    -------
    configurations : list
        List of configurations with the correct prefix
        added in the directories and ignore sections.

    """
    def inserter(path):
        """Insert new_prefix inside path, right before the first '/'."""
        result = path
        index = path.find(os.sep)

        if new_prefix not in path and index >= 0:
            result = path[0:index] + new_prefix + path[index:]

        return result

    for config in configurations:
        for section in config['sections']:
            if section['elements']:
                for element in section['elements']:
                    if isinstance(element, dict):
                        # ADD HERE all fields with format sub_element: - value
                        for sub_element in (element.get('directories'), element.get('ignore'), element.get('nodiff')):
                            if sub_element:
                                # Get restrict, directories, ignore and nodiff fields and split them into paths lists
                                restrict_dict = {}
                                attributes = sub_element.get('attributes', [])
                                for attr in attributes:
                                    if isinstance(attr, dict):
                                        if attr.get('restrict'):
                                            restrict_dict = attr
                                restrict_list = restrict_dict['restrict'].split('|') if restrict_dict != {} else []
                                paths_list = sub_element['value'].split(',')
                                modified_restricts = ''
                                modified_paths = ''

                                # Insert the prefix in every path/regex and add a comma if directories.
                                for path in paths_list:
                                    modified_paths += inserter(path)
                                    modified_paths += ',' if (element.get('directories') and modified_paths != '') else ''
                                modified_paths = modified_paths.rstrip(',')

                                # Insert the prefix in every path inside restrict
                                for restrict in restrict_list:
                                    modified_restricts += inserter(restrict)
                                    modified_restricts += '|'
                                modified_restricts = modified_restricts.rstrip('|')

                                # Replace the previous values with the new ones.
                                if modified_paths:
                                    sub_element['value'] = modified_paths
                                if modified_restricts:
                                    for i, sub_sub_element in enumerate(sub_element['attributes']):
                                        if sub_sub_element == restrict_dict:
                                            sub_element['attributes'][i] = {'restrict': modified_restricts}

    return configurations


def check_apply_test(apply_to_tags: Set, tags: List):
    """
    Skip test if intersection between the two parameters is empty.

    Parameters
    ----------
    apply_to_tags : set
        Tags that the tests will run.
    tags : list
        List with the tags that identifies a configuration.
    """
    if not (apply_to_tags.intersection(tags) or
            'all' in apply_to_tags):
        pytest.skip("Does not apply to this config file")


def generate_syscheck_config():
    """Generate all possible syscheck configurations with 'check_*', 'report_changes' and 'tags'.

    Every configuration is ready to be applied in the tag <directories>.
    """
    check_platform = 'check_attrs' if sys.platform == 'win32' else 'check_inode'
    check_names = ['check_all', 'check_sha1sum', 'check_md5sum', 'check_sha256sum', 'check_size', 'check_owner',
                   'check_group', 'check_perm', 'check_mtime', check_platform, 'report_changes']

    values_list = itertools.product(['yes', 'no'], repeat=len(check_names))
    tags = ['tags="Sample"', '']

    for yn_values, tag_value in itertools.product(values_list, tags):
        yn_str = ' '.join([f'{name}="{value}"' for name, value in zip(check_names, yn_values)])
        yield ' '.join([yn_str, tag_value])


def generate_syscheck_registry_config():
    """Generate all possible syscheck configurations with 'check_*', 'report_changes' and 'tags' for Windowsregistries.

    Every configuration is ready to be applied in the tag <directories>.
    """
    check_names = ['check_all', 'check_sha1sum', 'check_md5sum', 'check_sha256sum', 'check_size', 'check_owner',
                   'check_group', 'check_perm', 'check_mtime', 'check_type', 'report_changes']

    values_list = itertools.product(['yes', 'no'], repeat=len(check_names))
    tags = ['tags="Sample"', '']

    for yn_values, tag_value in itertools.product(values_list, tags):
        yn_str = ' '.join([f'{name}="{value}"' for name, value in zip(check_names, yn_values)])
        yield ' '.join([yn_str, tag_value])
