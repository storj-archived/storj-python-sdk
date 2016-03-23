#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup


with open('README.md') as readme:
    long_description = readme.read()

setup(
    name='metadisk',
    version='0.1.0',
    description='A Python SDK for the Storj Metadisk API',
    long_description=long_description,
    keywords='metadisk, api, client, sdk, python',
    url='https://github.com/hwkns/metadisk-python-sdk',
    author='Daniel Hawkins',
    author_email='hwkns@alum.mit.edu',
    license='MIT',
    packages=['metadisk'],
    dependency_links=[],
    install_requires=[
        'ecdsa>=0.13',
        'pytz>=2016.2',
        'requests>=2.7.0',
    ],
)
