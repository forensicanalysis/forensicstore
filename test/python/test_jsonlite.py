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

import pytest

import jsonlite

from fs import memoryfs


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


class TestJSONLite:

    def test_init_create(self, out_dir, data):
        store = jsonlite.connect(
            out_dir + "/init_create.jsonlite")
        store.close()

        assert store.remote_fs.__class__.__name__ == "OSFS"

        assert os.path.exists(out_dir + "/init_create.jsonlite/item.db")

        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_init_create_ref(self, out_dir, data):
        cwd = os.getcwd()
        os.chdir(out_dir)
        store = jsonlite.connect("init_create.jsonlite")
        store.close()
        os.chdir(cwd)

        assert store.remote_fs.__class__.__name__ == "OSFS"

        assert os.path.exists(out_dir + "/init_create.jsonlite/item.db")

        shutil.rmtree(out_dir)
        shutil.rmtree(data)

#    def test_init_create_memory(self, out_dir, data):
#        mem_fs = memoryfs.MemoryFS()
#        store = jsonlite.connect(mem_fs)
#        store.close()
#        assert store.remote_fs.__class__.__name__ == "MemoryFS"
#        shutil.rmtree(out_dir)
#        shutil.rmtree(data)

    def test_init_load(self, out_dir, data):
        store = jsonlite.connect(data + "/forensicstore/example1.forensicstore")
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_save(self, out_dir, data):
        store = jsonlite.connect(data + "/forensicstore/example1.forensicstore")
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_get(self, out_dir, data):
        store = jsonlite.connect(data + "/forensicstore/example1.forensicstore")
        first = store.get("process--920d7c41-0fef-4cf8-bce2-ead120f6b506")
        assert first == {
            "uid": "process--920d7c41-0fef-4cf8-bce2-ead120f6b506",
            "artifact": "IPTablesRules",
            "type": "process",
            "name": "iptables",
            "created": "2016-01-20T14:11:25.550Z",
            "cwd": "/root/",
            "arguments": [
                "-L",
                "-n",
                "-v"
            ],
            "command_line": "/sbin/iptables -L -n -v",
            "stdout_path": "IPTablesRules/stdout",
            "stderr_path": "IPTablesRules/stderr",
            "return_code": 0
        }
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_get_not_existing(self, out_dir, data):
        store = jsonlite.connect(
            data + "/non_existing.forensicstore")
        with pytest.raises(KeyError):
            store.get("0-process")
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_select(self, out_dir, data):
        store = jsonlite.connect(data + "/forensicstore/example1.forensicstore")
        assert len(list(store.select("file"))) == 2
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_all(self, out_dir, data):
        store = jsonlite.connect(data + "/forensicstore/example1.forensicstore")
        assert len(list(store.all())) == 7
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_insert(self, out_dir, data):
        store = jsonlite.connect(data + "/forensicstore/example1.forensicstore")
        assert len(list(store.all())) == 7
        store.insert(
            {"type": "foo", "uid": "foo--2cd66ab1-9b85-4110-8d77-4b6906819693"})
        assert len(list(store.all())) == 8
        assert store.get("foo--2cd66ab1-9b85-4110-8d77-4b6906819693") == {
            "type": "foo", "uid": "foo--2cd66ab1-9b85-4110-8d77-4b6906819693"}
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_insert_empty_list(self, out_dir, data):
        store = jsonlite.connect(data + "/forensicstore/example1.forensicstore")
        assert len(list(store.all())) == 7
        store.insert({"type": "foo", "list": [],
                      "uid": "foo--2cd66ab1-9b85-4110-8d77-4b6906819693"})
        assert len(list(store.all())) == 8
        assert store.get("foo--2cd66ab1-9b85-4110-8d77-4b6906819693") == {
            "type": "foo", "uid": "foo--2cd66ab1-9b85-4110-8d77-4b6906819693"}
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_update(self, out_dir, data):
        store = jsonlite.connect(data + "/forensicstore/example1.forensicstore")
        store.update(
            "process--920d7c41-0fef-4cf8-bce2-ead120f6b506", {"name": "foo"})
        assert len(list(store.all())) == 7

        first = store.get("process--920d7c41-0fef-4cf8-bce2-ead120f6b506")
        assert first == {
            "uid": "process--920d7c41-0fef-4cf8-bce2-ead120f6b506",
            "artifact": "IPTablesRules",
            "type": "process",
            "name": "foo",
            "created": "2016-01-20T14:11:25.550Z",
            "cwd": "/root/",
            "arguments": [
                "-L",
                "-n",
                "-v"
            ],
            "command_line": "/sbin/iptables -L -n -v",
            "stdout_path": "IPTablesRules/stdout",
            "stderr_path": "IPTablesRules/stderr",
            "return_code": 0
        }

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_update_type(self, out_dir, data):
        store = jsonlite.connect(data + "/forensicstore/example1.forensicstore")
        store.update("process--920d7c41-0fef-4cf8-bce2-ead120f6b506", {"type": "foo"})
        assert len(list(store.all())) == 7

        first = store.get("foo--920d7c41-0fef-4cf8-bce2-ead120f6b506")
        assert first == {
            "uid": "foo--920d7c41-0fef-4cf8-bce2-ead120f6b506",
            "artifact": "IPTablesRules",
            "type": "foo",
            "name": "iptables",
            "created": "2016-01-20T14:11:25.550Z",
            "cwd": "/root/",
            "arguments": [
                "-L",
                "-n",
                "-v"
            ],
            "command_line": "/sbin/iptables -L -n -v",
            "stdout_path": "IPTablesRules/stdout",
            "stderr_path": "IPTablesRules/stderr",
            "return_code": 0
        }

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_import_store(self, out_dir, data):
        import_store = jsonlite.connect(out_dir + "/tmp/tmp.jsonlite")
        with import_store.store_file("testfile.txt") as (path, io):
            io.write(123 * b'A')
            import_store.insert({"type": "foo", "export_path": path})
        import_store.close()

        store = jsonlite.connect(out_dir + "/amcache/amcache.jsonlite")
        with store.store_file("testfile.txt") as (path, io):
            io.write(123 * b'B')
            store.insert({"type": "foo", "export_path": path})

        store.import_jsonlite(out_dir + "/tmp/tmp.jsonlite")

        items = store.all()
        assert len(list(items)) == 2
        with open(out_dir + "/amcache/amcache.jsonlite/testfile.txt", 'rb') as io:
            assert io.read() == 123 * b'B'
        with open(out_dir + "/amcache/amcache.jsonlite/testfile_0.txt", 'rb') as io:
            assert io.read() == 123 * b'A'

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_insert_quotes(self, out_dir, data):
        store = jsonlite.connect(
            out_dir + "/quotes.jsonlite")

        item_id = store.insert({"type": "foo"})
        store.update(
            item_id, {"foo": '@"%ProgramFiles%\\Windows Journal\\Journal.exe",-3072'})

        assert store.get(item_id)[
                   "foo"] == '@"%ProgramFiles%\\Windows Journal\\Journal.exe",-3072'

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)
