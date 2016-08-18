#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages


exec(open('storj/version.py').read())  # load __version__


setup(
    name='storj',
    description='A Python SDK for the Storj API',
    long_description=open("README.rst").read(),
    keywords='storj, bridge, metadisk, api, client, sdk, python',
    url='http://storj.io',
    author='Daniel Hawkins',
    author_email='hwkns@alum.mit.edu',
    license='MIT',
    version=__version__,  # NOQA
    test_suite="tests",
    dependency_links=[],
    # package_data={'storj': ['data/*.json']},
    # include_package_data=True,
    install_requires=open("requirements.txt").readlines(),
    tests_require=open("requirements_tests.txt").readlines(),
    packages=find_packages(),
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
)
