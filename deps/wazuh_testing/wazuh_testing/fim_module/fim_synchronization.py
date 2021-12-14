def find_value_in_event_list(key_path, value_name, event_list):
    """Function that looks for a key path and value_name in a list of json events.
    Params:
        path (str): Path of the registry key.
        value_name (str): Name of the value
        event_list (list): List containing the events in JSON format.
    Returns:
        The event that matches the specified path. None if no event was found.
    """
    for event in event_list:
        if 'value_name' not in event.keys():
            continue

        if event['path'] == key_path and event['value_name'] == value_name:
            return event

    return None