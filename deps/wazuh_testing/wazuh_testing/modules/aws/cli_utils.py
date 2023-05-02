import subprocess
from pathlib import Path

from wazuh_testing import logger
from wazuh_testing.modules.aws import AWS_MODULE_PATH
from wazuh_testing.modules.aws.exceptions import OutputAnalysisError

AWS_BINARY_PATH = Path(AWS_MODULE_PATH, 'aws-s3')


def call_aws_module(*parameters):
    """Given some parameters call the AWS module and return the output.

    Returns:
        str: The command output.
    """
    command = [AWS_BINARY_PATH, *parameters]
    logger.debug("Calling AWS module with: '%s'", command)
    command_result = subprocess.run(command, capture_output=True)

    return command_result.stdout.decode()


def _default_callback(line: str):
    print(line)
    return line


def analyze_command_output(
    command_output, callback=_default_callback, expected_results=1, error_message=''
):
    """Analyze the given command output searching for a pattern.

    Args:
        command_output (str): The output to analyze.
        callback (Callable, optional): A callback to process each line. Defaults to _default_callback.
        expected_results (int, optional): Number of expected results. Defaults to 1.
        error_message (str, optional): Message to show with the exception. Defaults to ''.

    Raises:
        OutputAnalysisError: When the expected results are not correct.
    """

    results = []

    for line in command_output.splitlines():
        logger.debug(line)
        item = callback(line)

        if item is not None:
            results.append(item)

    results_len = len(results)

    if results_len != expected_results:
        if error_message:
            logger.error(error_message)
            logger.error('Results found: %s', results_len)
            logger.error('Results expected: %s', expected_results)
            raise OutputAnalysisError(error_message)
        raise OutputAnalysisError()
