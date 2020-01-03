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

""" Create hashes of multiple files """
import hashlib


class HashedFile:
    """ A class to generate multiple hashes at once."""

    def __init__(self, path, file_system):
        self.path = path
        self.file_system = file_system
        self.calculate = {"MD5": "md5", "SHA-1": "sha1"}
        self.hashers = {}
        for algo in self.calculate:
            self.hashers[algo] = hashlib.new(self.calculate[algo])
        self.file = self.file_system.open(self.path, 'xb+')

    def write(self, data):
        """
        Write data into file and hash it.

        :param data: Input data
        :type data: bytes or bytearray
        """
        for algo in self.hashers:
            self.hashers[algo].update(data)
        return self.file.write(data)

    def get_hashes(self):
        """ Return all hashes as hex strings

        :return: A dict of hashes.
        :rtype {str: str}:
        """
        hashes = {}
        for algo in self.hashers:
            hashes[algo] = self.hashers[algo].hexdigest()
        return hashes

    def close(self):
        """ Close the file handle """
        self.file.close()
