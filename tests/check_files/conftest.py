# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


def pytest_addoption(parser):
    """Method to add some options to launch tests.

    Args:
        parser (argparse.ArgumentParser): Parser object to add the options.
    """
    parser.addoption('--before-file', action='store', dest='before_file')
    parser.addoption('--after-file', action='store', dest='after_file')
    parser.addoption('--output-path', action='store', dest='output_path')


def pytest_generate_tests(metafunc):
    """Hook which is called when collecting a test function.

    Using the metafunc object, you can call parametrize() to use parameterization.

    Args:
        metafunc (Metafunc): Object with the requesting test context.
    """
    option_value = metafunc.config.option.before_file
    if 'before-file' in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize('--before-file', [option_value])

    option_value = metafunc.config.option.after_file
    if 'after-file' in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize('--after-file', [option_value])

    option_value = metafunc.config.option.output_path
    if 'output-path' in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize('--output-path', [option_value])
