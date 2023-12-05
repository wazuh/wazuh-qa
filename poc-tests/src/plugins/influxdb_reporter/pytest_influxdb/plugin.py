from __future__ import print_function

from . import reporter


def pytest_addoption(parser):
    """
    Add options for the pytest command line.

    Args:
        parser (argparsing.Parser): The parser for command line arguments and ini-file values.
    """
    group = parser.getgroup('influxdb', 'reporting test results to influxdb')
    group.addoption('--influxdb-report', default=False, action='store_true', help='send report to influxdb.')
    group.addoption('--influxdb-url', default="http://localhost:8086", help='Influxdb host url.')
    group.addoption('--influxdb-token', default=None, help='Token to use for influxdb connection.')
    group.addoption('--influxdb-bucket', default=None, help='Influxdb bucket to store the data in.')
    group.addoption('--influxdb-org', default=None, help='Influxdb organization name.')
    group.addoption('--influxdb-config-file', default=None, help='File with the influxdb configuration.')


def pytest_configure(config):
    """
    Allows plugins and conftest files to perform initial configuration.

    This hook is called for every plugin and initial conftest
    file after command line options have been parsed.

    Args:
        config (pytest.Config): The pytest config object.
    """
    if not config.getoption("--influxdb-report"):
        return

    if config_file := config.getoption("--influxdb-config-file"):
        plugin = reporter.InfluxDBReporter(config, config_file)
    else:
        plugin = reporter.InfluxDBReporter(config)

    config._influxdb = plugin
    config.pluginmanager.register(plugin)


def pytest_unconfigure(config):
    """
    Allows plugins and conftest files to perform cleanup activities.

    This hook is called before test process is exited.

    Args:
        config (pytest.Config): The pytest config object.
    """
    plugin = getattr(config, '_influxdb', None)
    if plugin is not None:
        del config._influxdb
        config.pluginmanager.unregister(plugin)
