from os import path

from setuptools import setup


this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='pytest-influxdb',
    description='A pytest plugin to report test results to influxdb',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=['pytest_influxdb'],
    author='AUTHOR',
    author_email='EMAIL',
    install_requires=[
        'pytest>=3.8.0',
        'influxdb-client>=1.38.0'
    ],
    entry_points={
        'pytest11': [
            'pytest_influxdb = pytest_influxdb.plugin',
        ]
    },
    classifiers=[
        'Development Status :: Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Framework :: Pytest',
    ],
)