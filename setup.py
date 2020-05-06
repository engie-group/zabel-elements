# Copyright (c) 2020 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

# Usage
#
# Local install:
#
#     pip3 install --upgrade .
#     pip3 install -e .
#
# Build and publish (assuming a proper ~/.pypirc)
#
#     python3 setup.py bdist_wheel upload -r artifactory

from setuptools import setup, find_namespace_packages


setup(
    name='zabel-elements',
    version='0.11.0',
    description='The Zabel default clients and services',
    long_description='',
    url='https://github.com/engie-corp/zabel',
    author='Martin Lafaix',
    author_email='martin.lafaix@external.engie.com',
    license='Eclipse Public License 2.0',
    packages=find_namespace_packages(include=['zabel.*']),
    install_requires=['requests>=2.23'],
    # install_requires=['requests>=2.23', 'zabel-commons>=0.10'],
    python_requires='>= 3.6.5',
)
