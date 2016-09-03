#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pip.download

from pip.req import parse_requirements


from setuptools import setup, find_packages


exec(open('storj/metadata.py').read())  # load __version__


setup(
    name='storj',
    version=__version__,  # NOQA
    description='A Python SDK for the Storj API',
    long_description=open('README.rst').read(),
    url='http://storj.io',
    author=__author__,
    author_email=__authoremail__,
    license='MIT',
    dependency_links=[],
    # package_data={'storj': ['data/*.json']},
    # include_package_data=True,
    packages=find_packages(
        exclude=('*.tests', '*.tests.*', 'tests.*', 'tests')
    ),
    install_requires=[
        str(pkg.req) for pkg in parse_requirements(
            'requirements.txt', session=pip.download.PipSession())
    ],
    test_suite='tests',
    tests_require=[
        str(pkg.req) for pkg in parse_requirements(
            'requirements-test.txt', session=pip.download.PipSession())
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP',
    ],
    keywords=','.join([
        'storj', 'bridge', 'metadisk', 'api', 'client', 'sdk', 'python'
    ]),
)
