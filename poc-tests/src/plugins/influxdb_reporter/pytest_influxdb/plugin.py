from __future__ import print_function

from . import reporter


def pytest_addoption(parser):
    group = parser.getgroup('influxdb', 'reporting test results to influxdb')
    group.addoption('--influxdb-report', default=False, action='store_true',
                    help='send report to influxdb.')
    group.addoption('--influxdb-url', default="http://localhost:8086", action='store_true',
                    help='Influxdb host url.')
    group.addoption('--influxdb-token', default=None, action='store_true',
                    help='Token to use for influxdb connection.')
    group.addoption('--influxdb-bucket', default=None, action='store_true',
                    help='Influxdb bucket to store the data in.')


def pytest_configure(config):
    if not config.getoption("--influxdb-report"):
        return
    plugin = reporter.InfluxDBReporter(config)
    config._influxdb = plugin
    config.pluginmanager.register(plugin)


def pytest_unconfigure(config):
    plugin = getattr(config, '_influxdb', None)
    if plugin is not None:
        del config._influxdb
        config.pluginmanager.unregister(plugin)
