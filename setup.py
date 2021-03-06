# Copyright 2017 John "LuaMilkshake" Marion
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup

setup(
    name='signify',
    version='0.0.1',
    description='Python implementation of OpenBSD signify',
    url='https://github.com/LuaMilkshake/python-signify',
    author='John Marion',
    author_email='jmariondev@gmail.com',
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: Apache Software License',

        'Topic :: Security',

        'Programming Language :: Python :: 3',
    ],
    packages=['signify'],
    install_requires=[
        'ed25519',
    ],
    keywords='',
)
