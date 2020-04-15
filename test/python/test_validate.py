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
import os
import shutil
import tempfile

import forensicstore
import pytest


@pytest.fixture
def out_dir(tmpdir_factory):
    return tempfile.mkdtemp()


@pytest.fixture
def data(tmpdir_factory):
    tmpdir = tempfile.mkdtemp()
    os.makedirs(tmpdir + "/data")
    shutil.copytree("test/forensicstore", tmpdir + "/data/forensicstore/")
    shutil.copytree("test/json", tmpdir + "/data/json/")
    return tmpdir + "/data"


class TestValidate:

    def test_add_invalid_item(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/invalid.forensicstore")

        with pytest.raises(TypeError):
            store.insert({"type": "file", "foo": "bar"})

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_item_with_none_value(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/invalid.forensicstore")

        file_id = store.insert({"type": "file", "name": "foo.txt", "created": None})

        item = store.get(file_id)
        assert "created" not in item

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_item_with_empty_value(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/invalid.forensicstore")

        with pytest.raises(TypeError):
            store.insert({"type": "file", "name": "foo.txt", "created": ""})

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_invalid_json(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/invalid.forensicstore")

        errors, _ = store.validate_item({"type": "file", "foo": "bar"})
        assert len(errors) == 1
        assert "Failed validating" in errors[0]

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_parent_file(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/missing_file.forensicstore")
        store.insert({"type": "foo", "foo_path": "../bar"})

        errors = store.validate()

        assert len(errors) == 1
        assert errors[0] == "'..' in ../bar"

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_missing_file(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/missing_file.forensicstore")
        store.insert({"type": "foo", "foo_path": "bar"})

        errors = store.validate()

        assert len(errors) == 1
        assert errors[0] == "missing files: ('/bar')"

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_additional_file(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/additional_file.forensicstore")
        with store.store_file("bar") as (path, io):
            io.write(b'b')

        errors = store.validate()

        assert len(errors) == 1
        assert errors[0] == "additional files: ('/bar')"

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_wrong_size(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/wrong_size.forensicstore")
        with store.store_file("bar") as (path, io):
            io.write(b'b')
        store.insert({"type": "foo", "foo_path": "bar", "size": 2})

        errors = store.validate()

        assert len(errors) == 1
        assert errors[0] == "wrong size for bar"

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_wrong_hash(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/wrong_hash.forensicstore")
        with store.store_file("bar") as (path, io):
            io.write(b'b')
        store.insert({"type": "foo", "foo_path": "bar", "hashes": {"MD5": "beef"}})

        errors = store.validate()

        assert len(errors) == 1
        assert errors[0] == "hashvalue mismatch MD5 for bar"

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)
