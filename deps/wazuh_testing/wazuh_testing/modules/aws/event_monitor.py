import re
from typing import Callable, Optional

from .cli_utils import analyze_command_output
from .constants import CLOUD_TRAIL_TYPE, VPC_FLOW_TYPE, CUSTOM_TYPE

PARSER_ERROR = r'.*wm_aws_read\(\): ERROR:.*'
MODULE_ERROR = r'.*wm_aws_run_s3\(\): ERROR: .*'
AWS_EVENT_HEADER = b'1:Wazuh-AWS:'


def make_aws_callback(pattern, prefix=''):
    """Create a callback function from a text pattern.

    Args:
        pattern (str): String to match on the log.
        prefix (str): Regular expression used as prefix before the pattern.

    Returns:
        lambda: Function that returns if there's a match in the file.
    """
    pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line)


def callback_detect_aws_module_called(parameters: list) -> Callable:
    """Detect if aws module was called with correct parameters.

    Args:
        parameters (list): Values to check.

    Returns:
        Callable: Callback to match the line.
    """
    regex = re.compile(fr'.*DEBUG: Launching S3 Command: {" ".join(parameters)}\n*')
    return lambda line: regex.match(line)


def callback_detect_aws_module_start(line: str) -> Optional[str]:
    """Search for start message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it match.
    """
    if re.match(r'.*INFO: Module AWS started*', line):
        return line


def callback_detect_all_aws_err(line) -> Optional[str]:
    """Search for parse or module error message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it match.
    """
    if re.match(PARSER_ERROR, line) or re.match(MODULE_ERROR, line):
        return line


def callback_detect_aws_read_err(line) -> Optional[str]:
    """Search for parser error message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it match.
    """
    if re.match(PARSER_ERROR, line):
        return line


def callback_detect_aws_wmodule_err(line) -> Optional[str]:
    """Search for module error message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it match.
    """
    if re.match(MODULE_ERROR, line):
        return line


def callback_detect_event_processed(line) -> Optional[str]:
    """Search for event processed message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it match.
    """
    if re.match(r'.*Found new log: .*', line):
        return line


def callback_detect_event_processed_or_skipped(pattern: str) -> Callable:
    """Search for event processed or skipped message in the given line.

    Args:
        pattern (str): Pattern to match in line.
    Returns:
        Callable: Callback to match the given line.
    """
    pattern_regex = re.compile(pattern)
    return lambda line: pattern_regex.match(line) or callback_detect_event_processed(line)


def callback_event_sent_to_analysisd(line):
    """Search for module header message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it match.
    """
    if line.startswith(AWS_EVENT_HEADER):
        return line


def check_processed_logs_from_output(command_output: str, expected_results: int = 1):
    """Check for processed messages in the give output.

    Args:
        command_output (str): Output to analyze.
        expected_results (int, optional): Number of results to find. Defaults to 1.
    """
    analyze_command_output(
        command_output=command_output,
        callback=callback_detect_event_processed,
        expected_results=expected_results,
        error_message='The AWS module did not process the expected number of events'
    )


def check_non_processed_logs_from_output(command_output: str, bucket_type: str, expected_results: int = 1):
    """Check for non processed messages in the give output.

    Args:
        command_output (str): Output to analyze.
        bucket_type (str): Bucket type to select the message.
        expected_results (int, optional): Number of results to find. Defaults to 1.
    """
    if bucket_type == VPC_FLOW_TYPE:
        pattern = r'.*DEBUG: \+\+\+ No logs to process for .*'
    elif bucket_type == CUSTOM_TYPE:
        pattern = r'.*DEBUG: \+\+ Skipping previously processed file: '
    else:
        pattern = r'.*DEBUG: \+\+\+ No logs to process in bucket: '

    analyze_command_output(
        command_output,
        callback=make_aws_callback(pattern),
        expected_results=expected_results,
        error_message='Some logs may were processed or the results found are more than expected'
    )


def check_marker_from_output(command_output: str, file_key: str, expected_results: int = 1):
    """Check for marker message in the given output.

    Args:
        command_output (str): Output to analyze.
        file_key (str): Value to check as a marker.
        expected_results (int, optional): Number of results to find. Defaults to 1.
    """
    pattern = fr".*DEBUG: \+\+\+ Marker: {file_key}"

    analyze_command_output(
        command_output,
        callback=make_aws_callback(pattern),
        expected_results=expected_results,
        error_message='The AWS module did not use the correct marker'
    )
