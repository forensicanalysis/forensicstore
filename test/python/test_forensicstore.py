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

import datetime
import json
import os
import shutil
import tempfile

import pytest

import forensicstore

from .example_forensicstore import EXAMPLE_FORENSICSTORE


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


class TestForensicStore:

    def test_init_create(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/init_create.forensicstore")
        store.close()

        assert os.path.exists(out_dir + "/init_create.forensicstore/item.db")
        # print(out_dir + "/init_create.forensicstore/item.db") created empty table
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_process_item(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/iptables.forensicstore")
        cmd_date = datetime.datetime(2016, 1, 20, 14, 11, 25, 550000)
        cmd = store.add_process_item("IPTablesRules", "iptables", cmd_date, "/root/", ["-L", "-n", "-v"],
                                     "/sbin/iptables -L -n -v", 0, [])
        with store.add_process_item_stdout(cmd) as stdout, store.add_process_item_stderr(cmd) as stderr:
            stdout.write(b"foo")
            stderr.write(b"bar")

        items = store.all()
        first = list(items).pop()
        del first["uid"]
        assert first == EXAMPLE_FORENSICSTORE[0]

        with open(out_dir + "/iptables.forensicstore/IPTablesRules/stdout", 'rb') as io:
            assert io.read() == b"foo"
        with open(out_dir + "/iptables.forensicstore/IPTablesRules/stderr", 'rb') as io:
            assert io.read() == b"bar"
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_file_item(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/amcache.forensicstore")
        file_date = datetime.datetime(2014, 9, 11, 21, 50, 18, 301000)
        origin = {
            "path": "C:\\Windows\\appcompat\\Programs\\Amcache.hve",
            "volume": "2"
        }
        file = store.add_file_item("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin, [])
        with store.add_file_item_export(file) as export:
            export.write(123 * b'A')

        items = store.all()
        first = list(items).pop()
        del first["uid"]
        assert first == EXAMPLE_FORENSICSTORE[2]

        with open(out_dir + "/amcache.forensicstore/WindowsAMCacheHveFile/Amcache.hve", 'rb') as io:
            assert io.read() == 123 * b'A'
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_duplicate_file_item(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/amcache.forensicstore")
        file_date = datetime.datetime(2014, 9, 11, 21, 50, 18, 301000)
        origin = {
            "path": "C:\\Windows\\appcompat\\Programs\\Amcache.hve",
            "volume": "2"
        }
        file1 = store.add_file_item("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin, [])
        with store.add_file_item_export(file1) as export:
            export.write(123 * b'A')

        file2 = store.add_file_item("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin, [])
        with store.add_file_item_export(file2) as export:
            export.write(123 * b'B')

        file3 = store.add_file_item("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin, [])
        with store.add_file_item_export(file3, "Amcache_b.hve") as export:
            export.write(123 * b'C')

        file4 = store.add_file_item("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin, [])
        with store.add_file_item_export(file4, "Amcache_b.hve") as export:
            export.write(123 * b'D')

        first = store.get(file1)
        del first["uid"]
        assert first == EXAMPLE_FORENSICSTORE[2]

        with open(out_dir + "/amcache.forensicstore/WindowsAMCacheHveFile/Amcache.hve", 'rb') as io:
            assert io.read() == 123 * b'A'
        with open(out_dir + "/amcache.forensicstore/WindowsAMCacheHveFile/Amcache_0.hve", 'rb') as io:
            assert io.read() == 123 * b'B'
        with open(out_dir + "/amcache.forensicstore/WindowsAMCacheHveFile/Amcache_b.hve", 'rb') as io:
            assert io.read() == 123 * b'C'
        with open(out_dir + "/amcache.forensicstore/WindowsAMCacheHveFile/Amcache_b_0.hve", 'rb') as io:
            assert io.read() == 123 * b'D'
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_multi_write_file_item(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/amcache.forensicstore")
        file_date = datetime.datetime(2014, 9, 11, 21, 50, 18, 301000)
        origin = {
            "path": "C:\\Windows\\appcompat\\Programs\\Amcache.hve",
            "volume": "2"
        }
        file = store.add_file_item("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin, [])
        with store.add_file_item_export(file) as export:
            for _ in range(123):
                export.write(b'A')

        items = store.all()
        first = list(items).pop()

        del first["uid"]
        assert first == EXAMPLE_FORENSICSTORE[2]

        with open(out_dir + "/amcache.forensicstore/WindowsAMCacheHveFile/Amcache.hve", 'rb') as io:
            assert io.read() == 123 * b'A'

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_directory_item(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/program_files.forensicstore")
        dir_date = datetime.datetime(2014, 9, 11, 21, 50, 18, 301000)
        store.add_directory_item("WindowsEnvironmentVariableProgramFiles", "C:\\Program Files", dir_date, dir_date,
                                 dir_date, [])
        items = store.all()
        first = list(items).pop()
        del first["uid"]
        assert first == EXAMPLE_FORENSICSTORE[3]

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_registry_key_item(self, out_dir, data):
        store = forensicstore.connect(out_dir + "/codepage.forensicstore")
        key_date = datetime.datetime(2009, 7, 14, 4, 34, 14, 225000)
        key = store.add_registry_key_item("WindowsCodePage", key_date,
                                          "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Nls\\CodePage", [])
        store.add_registry_value_item(key, "REG_SZ", "1252".encode("utf-16"), "ACP")

        items = store.all()
        first = list(items).pop()
        del first["uid"]
        assert first == EXAMPLE_FORENSICSTORE[5]

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    # @pytest.mark.benchmark(group="get")
    # def test_bench_get(self, benchmark, out_dir, data):
    #     store = forensicstore.connect(data + "/valid/example1.forensicstore")
    #     for i in range(100):
    #         store.import_observed_data_file(data + "/json/example1.json")
    #     benchmark(store.get, "process", 0)
    #     shutil.rmtree(out_dir)
    #     shutil.rmtree(data)

    # @pytest.mark.benchmark(group="add")
    # def test_bench_add(self, benchmark, out_dir, data):
    #     store = forensicstore.connect(out_dir + "/benchmark1.forensicstore")
    #     for i in range(100):
    #         store.import_observed_data_file(data + "/json/example1.json")
    #     benchmark(store.add, {"type": "file", "name": "bar"})
    #     shutil.rmtree(out_dir)
    #     shutil.rmtree(data)
