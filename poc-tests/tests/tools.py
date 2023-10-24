from distutils.version import LooseVersion
import json

# /////////////////////////////////////   MODULE VARS  //////////////////////////////////////////////

daemons_path = 'utils/daemons.json'
conffiles_path = 'utils/conffiles.json'
exceptions_path = 'utils/error_exceptions.json'

# ////////////////////////////////////////////////////////////////////////////////////////////////////
"""
    Method to check if a version is within a range of versions

    Parameters:
        - check_version: Version to be tested
        - lower_version: Lower version limit
        - higher_version: Upper version limit

    Return:
        True if check_version belongs to the range, False otherwise
"""

def in_version(check_version, lower_version, higher_version):

    belong = False

    if (LooseVersion(check_version) >= LooseVersion(lower_version)) and (LooseVersion(check_version) <= LooseVersion(higher_version)):
        belong = True

    return belong

# ////////////////////////////////////////////////////////////////////////////////////////////////////

"""
    Method for loading daemons, error_exceptions and conffiles data from a particular version

    Parameters:
        - version: Version to load the data
        - file_path: Path where is located the json file to load.
        - target: [manager, agent, api]

    Return:
        Data structure containing information about description, agent and manager. Example: daemons data

        {
            'description': 'From 3.5.0 to current version',
            'data': [
                {'clusterd': 'wazuh-clusterd not running'},
                {'modulesd': 'wazuh-modulesd is running'},
                {'monitord': 'wazuh-monitord is running'},
                {'logcollector': 'wazuh-logcollector is running'},
                    ...
            ]
        }

    Raise:
        Exception: If path is wrong.
        Exception: If target key is not found.
        Exception: Version is not in any group in json data.
"""

def load_common_files_data(version, file_path, target):

    try:
        json_data = open(file_path)
        template_data = json.load(json_data)
        json_data.close()
    except:
        raise Exception("Path not found: {}".format(file_path))

    try:
        data = template_data[target]
    except:
        raise Exception("{} key was not found in {}".format(target, file_path))

    if version in data['unmatch']:

        position =  None

        for idx, item in enumerate(data['other']['groups']):
            if in_version(version, item[0], item[1]):
                position = idx

        if position == None:
            raise Exception("No group was found for the version {}".format(version))
        else:
            output_data = data['other']['groupData'][position]
    else:
        output_data = data['lastData']

    """
    Up to this point, output_data variable contains the following format information: (Example with a daemons data)
        {
            "description": "From 3.0.0 to 3.0.0",
            "data": [0,1,2,3,4,5,6,7,8]
        }
    """
    # Now the indexes in each list will be replaced by the object containing the referenced information.
    for item in output_data:
        if(isinstance(output_data[item], list)):
            for idx, data_index in enumerate(output_data[item]):
                output_data[item][idx] = dict()
                data_object = template_data['data'][data_index]
                output_data[item][idx][data_object['name']] = data_object['description']

    return output_data

# ////////////////////////////////////////////////////////////////////////////////////////////////////


"""
    Function for obtaining the position of a searched object within a list

     Parameters:
        - data: Object list given in the following format:

            [
                {'modulesd': 'wazuh-modulesd is running'},
                {'logcollector': 'wazuh-logcollector is running'},
                {'syscheckd': 'wazuh-syscheckd is running'},
                {'execd': 'wazuh-execd is running'},
                {'agentd': 'wazuh-agentd is running'}
            ]

        - value_to_find: key name to find

    Return:
       If found: Position of the list where the searched object was found
       Else: None
"""
def get_key_position(data, value_to_find):

    position = None

    for idx in range(len(data)):
        if value_to_find in data[idx]:
            position = idx
            break

    return position

# ////////////////////////////////////////////////////////////////////////////////////////////////////

"""
    Function for obtaining the value of a searched object within a list

     Parameters:
        - data: Object list given in the following format:

            [
                {'modulesd': 'wazuh-modulesd is running'},
                {'logcollector': 'wazuh-logcollector is running'},
                {'syscheckd': 'wazuh-syscheckd is running'},
                {'execd': 'wazuh-execd is running'},
                {'agentd': 'wazuh-agentd is running'}
            ]

        - value_to_find: key name to find

    Return:
       If found: Value of the description data of the searched object
       Else: None
"""

def get_key_value(data, value_to_find):

    value = None

    for idx in range(len(data)):
        if value_to_find in data[idx]:
            value = data[idx][value_to_find]
            break

    return value

# ////////////////////////////////////////////////////////////////////////////////////////////////////

"""
    Function for returning a data list. For now it's used to return a list with the error_exceptions values.

    Parameters:
        - data: data list given in the following format:

            [
                {'modulesd_delete_pid': "wazuh-modulesd: ERROR: Couldn't delete PID file"},
                {'modulesd_unlink_pid': "wazuh-modulesd: ERROR: (1129): Could not unlink file '/var/ossec/var/run/"},
                {'logcollector_unlink_pid': "wazuh-logcollector: ERROR: (1129): Could not unlink file '/var/ossec/var/run/"},
                ...
            ]

    Return: Exceptions description.
        Example:
                [
                    "wazuh-modulesd: ERROR: Couldn't delete PID file",
                    "wazuh-modulesd: ERROR: (1129): Could not unlink file '/var/ossec/var/run/",
                    "wazuh-logcollector: ERROR: (1129): Could not unlink file '/var/ossec/var/run/"
                ]
"""

def get_data_list(data):

    data_list = []

    for idx in range(len(data)):
        item_data = data[idx]
        for object in item_data.values():
            data_list.append(object)

    return data_list

# ////////////////////////////////////////////////////////////////////////////////////////////////////

"""
    Function for returning a data dict from a list. For now it's used to return a dict with the conffiles values.

    Parameters:
        - data: data list given in the following format:

            [
                {'ossec_conf': '/var/ossec/etc/ossec.conf'},
                {'client_keys': 'var/ossec/etc/client.keys'},
                {'local_internal_options': '/var/ossec/etc/local_internal_options.conf'}
            ]

    Return: Exceptions description.
         Example:
            {
                'ossec_conf': '/var/ossec/etc/ossec.conf',
                'client_keys': 'var/ossec/etc/client.keys',
                'local_internal_options': '/var/ossec/etc/local_internal_options.conf'
            }
"""

def get_object_dict(data):

    object_list = dict()

    for idx in range(len(data)):
        for key, value in data[idx].items():
            object_list[key] = value

    return object_list