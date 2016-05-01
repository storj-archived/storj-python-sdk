#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup


setup(
    name='storj',
    version='0.1.4',
    description='A Python SDK for the Storj API',
    keywords='storj, bridge, metadisk, api, client, sdk, python',
    url='https://github.com/hwkns/storj-python-sdk',
    author='Daniel Hawkins',
    author_email='hwkns@alum.mit.edu',
    license='MIT',
    packages=['storj'],
    dependency_links=[],
    install_requires=[
        'ecdsa>=0.13',
        'pytz>=2016.2',
        'requests>=2.7.0',
        'ws4py>=0.3.4',
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
