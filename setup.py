# Copyright (c) 2019 Siemens AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Author(s): Jonas Plum

from setuptools import setup

setup(
    name='forensicstore',
    version='0.12.2',
    url='https://github.com/forensicanalysis/forensicstore',
    author='Jonas Plum',
    author_email='jonas.plum@siemens.com',
    description='Python library for forensicstore files',
    package_dir={
        'forensicstore': 'pyforensicstore',
        'jsonlite': 'pyjsonlite',
    },
    packages=[
        'forensicstore', "forensicstore.cmd", "forensicstore.schemas",
        "jsonlite"
    ],
    include_package_data=True,
    install_requires=[
        'jsonschema>=3.0.1,<4.0.0',
        'fs>=2.4.5,<3.0.0',
        'flatten_json==0.1.7',
    ],
    entry_points={
        'console_scripts':
        ['pyforensicstore = forensicstore.cmd.__main__:main']
    },
    zip_safe=False,
)
