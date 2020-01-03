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

"""
A ForensicStore is a database that can be used to store forensic items and files.

"""
from datetime import datetime
import json
import uuid
import os
from contextlib import contextmanager
from typing import Union

from fs import path

from jsonlite import JSONLite, open_fs_file


class ForensicStore(JSONLite):
    """
    ForensicStore is a class to database that can be used to store forensic items and files.

    :param str remote_url: Location of the database. Needs to be a path or a valid pyfilesystem2 url
    """

    def __init__(self, remote_url: str, read_only: bool = False):
        my_uuid = "{}--{}".format("observed-data", uuid.uuid4())
        current_date = datetime.utcnow().isoformat()[0:-3] + 'Z'
        self.metadata = {
            "last_observed": current_date,
            "type": "observed-data",
            "created": current_date,
            "first_observed": current_date,
            "modified": current_date,
            "id": my_uuid,
            "number_observed": 1
        }

        super().__init__(remote_url, discriminator="type", read_only=read_only)

        if self.new:
            current_dir = os.path.dirname(os.path.realpath(__file__))
            for schema_file in os.listdir(path.join(current_dir, "schemas")):
                with open(path.join(current_dir, "schemas", schema_file)) as schema_io:
                    schema = json.load(schema_io)
                    self._set_schema(schema["$id"], schema)

    def import_forensicstore(self, url: str):
        """
        Import ForensicStore file

        :param str url: Location of the observed data file. Needs to be a path or a valid pyfilesystem2 url
        """
        self.import_jsonlite(url)

    def import_stix(self, url: str):
        """
        Import Observed Data file

        :param str url: Location of the observed data file. Needs to be a path or a valid pyfilesystem2 url
        """
        fs, location = open_fs_file(url)
        with fs.open(location, 'r') as io:
            items = json.load(io)

            self.metadata = {k: v for k, v in items.items() if k != "items"}
            for item in items["objects"].values():
                self._import_file(fs, item)

    def export_stix(self, url):
        """
        Create a valid STIX 2.0 observed data object

        """
        meta = self.metadata
        meta["objects"] = {str(idx): item for idx, item in enumerate(self.all())}

        fs, filename = open_fs_file(url)
        with fs.open(filename, 'w+') as io:
            json.dump(meta, io)

    def add_process_item(self, artifact, name, created, cwd, arguments, command_line, return_code, errors) -> str:
        """
        Add a new STIX 2.0 Process Object

        :param str artifact: Artifact name (non STIX field)
        :param str name: Specifies the name of the process.
        :param created: Specifies the date/time at which the process was created.
        :type created: datetime or str
        :param str cwd: Specifies the current working directory of the process.
        :param [str] arguments: Specifies the list of arguments used in executing the process. Each argument MUST be
         captured separately as a string.
        :param str command_line: Specifies the full command line used in executing the process, including the process
         name (depending on the operating system).
        :param int return_code: Return code of the process (non STIX field)
        :param list errors: List of errors
        :return: ID if the inserted item
        :rtype: str
        """
        if isinstance(created, datetime):
            created = created.isoformat(timespec='milliseconds') + 'Z'

        return self.insert({
            "artifact": artifact,
            "type": "process",
            "name": name,
            "created": created,
            "cwd": cwd,
            "arguments": arguments,
            "command_line": command_line,
            "return_code": return_code,
            "errors": errors,
        })

    @contextmanager
    def add_process_item_stdout(self, item_id: str):
        """Creates a writeable context for the output on stdout of a process.

        :param str item_id: ID of the item
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        item = self.get(item_id)
        with self._add_file_field(item_id, item, "process", "stdout", "stdout_path") as the_file:
            yield the_file

    @contextmanager
    def add_process_item_stderr(self, item_id: str):
        """Creates a writeable context for the output on stderr of a process.

        :param str item_id: ID of the item
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        item = self.get(item_id)
        with self._add_file_field(item_id, item, "process", "stderr", "stderr_path") as the_file:
            yield the_file

    @contextmanager
    def add_process_item_wmi(self, item_id: str):
        """Creates a writeable context for the WMI output of a process.

        :param str item_id: ID of the item
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        item = self.get(item_id)
        with self._add_file_field(item_id, item, "process", "wmi", "wmi_path") as the_file:
            yield the_file

    def add_file_item(self, artifact, name, created, modified, accessed, origin, errors) -> str:
        """
        Add a new STIX 2.0 File Object

        :param str artifact: Artifact name (non STIX field)
        :param str name: Specifies the name of the file.
        :param created: Specifies the date/time the file was created.
        :type created: datetime or str
        :param modified: Specifies the date/time the file was last written to/modified.
        :type modified: datetime or str
        :param accessed: Specifies the date/time the file was last accessed.
        :type accessed: datetime or str
        :param dict origin: Origin of the file (non STIX field)
        :param list errors: List of errors
        :return: ID if the inserted item
        :rtype: str
        """
        if isinstance(created, datetime):
            created = created.isoformat(timespec='milliseconds') + 'Z'
        if isinstance(modified, datetime):
            modified = modified.isoformat()[0:-3] + 'Z'
        if isinstance(accessed, datetime):
            accessed = accessed.isoformat()[0:-3] + 'Z'

        return self.insert({
            "artifact": artifact,
            "type": "file",
            "name": name,
            "created": created,
            "modified": modified,
            "accessed": accessed,
            "origin": origin,
            "errors": errors,
        })

    @contextmanager
    def add_file_item_export(self, item_id: str, export_name=None):
        """
        Creates a writeable context for the contents of the file. Size and hash values are automatically
        calculated for the written data.

        :param str item_id: ID of the item
        :param str export_name: Optional export name
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        item = self.get(item_id)
        if export_name is None:
            export_name = item["name"]
        with self._add_file_field(item_id, item, "file", export_name, "export_path", "size", "hashes") as the_file:
            yield the_file

    def add_registry_key_item(self, artifact, modified, key, errors) -> str:
        """
        Add a new STIX 2.0 Windows Registry Key Object

        :param str artifact: Artifact name (non STIX field)
        :param modified: Specifies the last date/time that the registry key was modified.
        :type modified: datetime or str
        :param str key: Specifies the full registry key including the hive.
        :param list errors: List of errors
        :return: ID if the inserted item
        :rtype: str
        """
        if isinstance(modified, datetime):
            modified = modified.isoformat()[0:-3] + 'Z'

        return self.insert({
            "artifact": artifact,
            "type": "windows-registry-key",
            "modified": modified,
            "key": key,
            "errors": errors,
        })

    def add_registry_value_item(self, key_id: str, data_type: str, data: bytes, name: str):
        """
        Add a STIX 2.0 Windows Registry Value Type

        :param str key_id: Item ID of the parent windows registry key
        :param str data_type: Specifies the registry (REG_*) data type used in the registry value.
        :param bytes data: Specifies the data contained in the registry value.
        :param str name: Specifies the name of the registry value. For
            specifying the default value in a registry key, an empty string MUST be used.
        """
        values = self.get(key_id).get("values", [])
        if data_type in ("REG_SZ", "REG_EXPAND_SZ"):
            strdata = data.decode("utf-16")
        elif data_type in ("REG_DWORD", "REG_QWORD"):
            strdata = "%d" % int.from_bytes(data, "little")
        elif data_type == "MULTI_SZ":
            strdata = " ".join(data.decode("utf-16").split("\x00"))
        else:
            hexdata = data.hex()
            strdata = ' '.join(a+b for a, b in zip(hexdata[::2], hexdata[1::2]))

        values.append({"data_type": data_type, "data": strdata, "name": name})
        self.update(key_id, {"values": values})

    def add_directory_item(self, artifact: str, dir_path: str, created: Union[datetime, str],
                           modified: Union[datetime, str], accessed: Union[datetime, str], errors: [str]) -> str:
        """
        Add a new STIX 2.0 Directory Object

        :param str artifact: Artifact name (non STIX field)
        :param str dir_path: Specifies the path, as originally observed, to the directory on the file system.
        :param created: Specifies the date/time the file was created.
        :type created: datetime or str
        :param modified: Specifies the date/time the file was last written to/modified.
        :type modified: datetime or str
        :param accessed: Specifies the date/time the file was last accessed.
        :type accessed: datetime or str
        :param list errors: List of errors
        :return: ID if the inserted item
        :rtype: str
        """

        if isinstance(created, datetime):
            created = created.isoformat(timespec='milliseconds') + 'Z'
        if isinstance(modified, datetime):
            modified = modified.isoformat()[0:-3] + 'Z'
        if isinstance(accessed, datetime):
            accessed = accessed.isoformat()[0:-3] + 'Z'

        return self.insert({
            "artifact": artifact,
            "path": dir_path,
            "type": "directory",
            "created": created,
            "modified": modified,
            "accessed": accessed,
            "errors": errors,
        })

    @contextmanager
    def _add_file_field(self, item_id, item, item_type, export_name, field, size_field=None, hash_field=None):
        if item["type"] != item_type:
            raise TypeError("Must be a %s item" % item_type)

        file_path = path.join(item.get("artifact", "."), export_name)

        with self.store_file(file_path) as (new_path, the_file):
            yield the_file

            update = {field: new_path}
            if hash_field is not None:
                update[hash_field] = the_file.get_hashes()

        if size_field is not None:
            update[size_field] = self.remote_fs.getsize(new_path)

        self.update(item_id, update)


def connect(url: str, read_only: bool = False) -> ForensicStore:
    return ForensicStore(url, read_only)
