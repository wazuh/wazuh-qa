# Timeouts
T_10 = 10
T_20 = 20
T_60 = 60

ANALYSISD_PREFIX = r'.*wazuh-analysisd.*'
MAILD_PREFIX = r'.*wazuh-maild.*'
# wazuh-analysisd.state file default update configuration
ANALYSISD_STATE_INTERNAL_DEFAULT = '5'
PERCENTAGE_PROCESS_MSGS = 0.95
QUEUE_SIZE = 16384
# Set logcollector message that the agent sents
LOGCOLLECTOR_MESSAGE = 'Invalid user random_user from 172.17.1.1 port 56550:Message number:'
TIMEFRAME_DEFAULT_VALUE = 10
UPPER_QUEUE_HALF_SIZE_LIMIT = 0.51
LOWER_QUEUE_HALF_SIZE_LIMIT = 0.49


def find_in_file(string_to_search, filename):
    """Find a specific string in a file

    Args:
        string_to_search (str): Word to find in the file
    Returns:
        str: Line that match in file
    """
    with open(filename, 'r') as file:
        for _, line in enumerate(file):
            if string_to_search in line:
                return line
