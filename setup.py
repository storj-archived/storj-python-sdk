#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup


setup(
    name='metadisk',
    version='0.1.3',
    description='A Python SDK for the Storj Metadisk API',
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
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP',
    ],
)
