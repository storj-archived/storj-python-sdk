#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pip.download

from pip.req import parse_requirements


from setuptools import setup, find_packages


exec(open('storj/metadata.py').read())  # load __version__


def requirements(requirements_file):
    """Return package mentioned in the given file.
    Args:
        requirements_file (str): path to the requirements file to be parsed.
    Returns:
        (list): 3rd-party package dependencies contained in the file.
    """
    return [
        str(package.req) for package in parse_requirements(
            requirements_file, session=pip.download.PipSession())]


setup(
    name='storj',
    version=__version__,  # NOQA
    description='A Python SDK for the Storj API',
    long_description=open('README.rst').read(),
    url='http://storj.io',
    author=__author__,
    author_email=__author_email__,
    license='MIT',
    dependency_links=[],
    # package_data={'storj': ['data/*.json']},
    # include_package_data=True,
    packages=find_packages(
        exclude=('*.tests', '*.tests.*', 'tests.*', 'tests')
    ),
    install_requires=requirements('requirements.txt'),
    test_suite='tests',
    tests_require=requirements('requirements-test.txt'),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP',
    ],
    keywords=', '.join([
        'storj', 'bridge', 'metadisk', 'api', 'client', 'sdk', 'python'
    ]),
    extras_require={
        'cli': requirements('requirements-extra-cli.txt'),
    },
    entry_points={
        'console_scripts': [
            'storj-bucket = storj.cli:bucket',
            'storj-file = storj.cli:file',
            'storj-key = storj.cli:keys',
        ]
    }
)
