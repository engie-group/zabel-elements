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
#     rm -r build/ dist/
#     python3 setup.py bdist_wheel [upload -r local]
#     twine upload [--repository testpypi] dist/*

from setuptools import setup, find_namespace_packages


with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
    name='zabel-elements',
    version='1.5.0',
    description='The Zabel default clients and images',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/engie-group/zabel',
    author='Martin Lafaix',
    author_email='martin.lafaix@external.engie.com',
    license='Eclipse Public License 2.0',
    packages=find_namespace_packages(include=['zabel.*']),
    install_requires=['requests>=2.23', 'zabel-commons>=1.4'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries',
    ],
    python_requires='>= 3.6.5',
)
