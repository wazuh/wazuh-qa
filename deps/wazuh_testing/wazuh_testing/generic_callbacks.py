from wazuh_testing.tools import WAZUH_CONF, monitoring

GENERIC_CALLBACK_ERROR_MESSAGE = 'The expected error output has not been produced'

def callback_invalid_value(option, value, prefix, severity='ERROR'):
    """Create a callback to detect invalid values in ossec.conf file.

    Args:
        option (str): Wazuh manager configuration option.
        value (str): Value of the configuration option.
        prefix (str): Daemon that generates the error log.
        severity (str): Severity of the error (WARNING, ERROR or CRITICAL)

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"{severity}: \(\d+\): Invalid value for element '{option}': {value}."
    return monitoring.make_callback(pattern=msg, prefix=prefix)

def callback_invalid_attribute(option, attribute, value, prefix, severity='WARNING'):
    """Create a callback to detect invalid values in ossec.conf file.

    Args:
        option (str): Wazuh manager configuration option.
        attribute (str): Wazuh manager configuration attribute.
        value (str): Value of the configuration option.
        prefix (str): Daemon that generates the error log.
        severity (str): Severity of the error (WARNING, ERROR or CRITICAL)

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"{severity}: \(\d+\): Invalid value '{value}' for attribute '{attribute}' in '{option}' option."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_error_in_configuration(severity, prefix, conf_path=WAZUH_CONF):
    """Create a callback to detect configuration error in ossec.conf file.

    Args:
        severity (str): ERROR or CRITICAL.
        prefix (str): Daemon that generates the error log.
        conf_path (str): Wazuh configuration file path.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"{severity}: \(\d+\): Configuration error at '{conf_path}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_invalid_conf_for_localfile(field, prefix,  severity='ERROR'):
    """Create a callback to detect invalid configuration option value.

    Args:
        field (str): Option field that produces the error.
        prefix (str): Daemon that generates the error log.
        severity (str): ERROR or CRITICAL.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"{severity}: Invalid {field} for localfile"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_error_invalid_value_for(option, prefix):
    """Create a callback to detect invalid values in ossec.conf file.

    Args:
        option (str): Wazuh manager configuration option.
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"WARNING: \(\d+\): Invalid value '.*' in '{option}' option. Default value will be used."
    return monitoring.make_callback(pattern=msg, prefix=prefix)