import re
from typing import Callable

from .cli_utils import analyze_command_output
from .constants import CLOUD_TRAIL_TYPE, VPC_FLOW_TYPE

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


def callback_detect_aws_module_start(line):
    if re.match(r'.*INFO: Module AWS started*', line):
        return line


def callback_detect_all_aws_err(line):
    if re.match(PARSER_ERROR, line) or re.match(MODULE_ERROR, line):
        return line


def callback_detect_aws_read_err(line):
    if re.match(PARSER_ERROR, line):
        return line


def callback_detect_aws_wmodule_err(line):
    if re.match(MODULE_ERROR, line):
        return line


def callback_detect_event_processed(line):
    if re.match(r'.*Found new log: .*', line):
        return line


def callback_detect_event_processed_or_skipped(pattern):
    pattern_regex = re.compile(pattern)
    return lambda line: pattern_regex.match(line) or callback_detect_event_processed(line)


def callback_event_sent_to_analysisd(line):
    if line.startswith(AWS_EVENT_HEADER):
        return line


def check_processed_logs_from_output(command_output: str, expected_results: int = 1):
    analyze_command_output(
        command_output=command_output,
        callback=callback_detect_event_processed,
        expected_results=expected_results,
        error_message='The AWS module did not process the expected number of events'
    )


def check_non_processed_logs_from_output(command_output: str, bucket_type: str, expected_results: int = 1):

    if bucket_type == CLOUD_TRAIL_TYPE:
        pattern = r'.*DEBUG: \+\+\+ No logs to process in bucket: '
    elif bucket_type == VPC_FLOW_TYPE:
        pattern = r'.*DEBUG: \+\+\+ No logs to process for .*'
    else:
        pattern = ''

    analyze_command_output(
        command_output,
        callback=make_aws_callback(pattern),
        expected_results=expected_results,
        error_message='Some logs may were processed'
    )


def check_marker_from_output(command_output: str, file_key: str, expected_results: int = 1):
    pattern = fr".*DEBUG: \+\+\+ Marker: {file_key}"

    analyze_command_output(
        command_output,
        callback=make_aws_callback(pattern),
        expected_results=expected_results,
        error_message='The AWS module did not use the correct marker'
    )
