# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


def pytest_addoption(parser):
    """Method to add some options to launch tests.

    Args:
        parser (argparse.ArgumentParser): Parser object to add the options.
    """
    parser.addoption('--log-output', action='store', dest='log_output')
    parser.addoption('--control-output', action='store', dest='control_output')


def pytest_generate_tests(metafunc):
    """Hook which is called when collecting a test function.

    Using the metafunc object, you can call parametrize() to use parameterization.

    Args:
        metafunc (Metafunc): Object with the requesting test context.
    """
    option_value = metafunc.config.option.log_output
    if 'log-output' in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize('--log-output', [option_value])

    option_value = metafunc.config.option.control_output
    if 'control-output' in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize('--control-output', [option_value])
