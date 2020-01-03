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

EXAMPLE_FORENSICSTORE = [
    {
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
    },
    {
        "artifact": "WindowsUserDownloadsDirectory",
        "type": "file",
        "hashes": {
            "MD5": "affeaffeaffeaffeaffeaffeaffeaffe",
            "SHA-1": "affeaffeaffeaffeaffeaffeaffeaffeaffeaffe"
        },
        "size": 123,
        "name": "foo.doc",
        "created": "2014-09-11T21:50:18.301Z",
        "modified": "2014-09-11T21:50:18.301Z",
        "accessed": "2014-09-11T21:50:18.301Z",
        "origin": {
            "path": "C:\\Users\\bob\\Downloads\\foo.doc",
            "volume": "2"
        },
    },
    {
        "artifact": "WindowsAMCacheHveFile",
        "type": "file",
        "hashes": {
            "MD5": "9b573b2e4c4b91558f6afd65262a6fb9",
            "SHA-1": "932567a1cfc045b729abdb52ed6c5c6acf59f369"
        },
        "size": 123,
        "name": "Amcache.hve",
        "created": "2014-09-11T21:50:18.301Z",
        "modified": "2014-09-11T21:50:18.301Z",
        "accessed": "2014-09-11T21:50:18.301Z",
        "origin": {
            "path": "C:\\Windows\\appcompat\\Programs\\Amcache.hve",
            "volume": "2"
        },
        "export_path": "WindowsAMCacheHveFile/Amcache.hve"
    },
    {
        "artifact": "WindowsEnvironmentVariableProgramFiles",
        "type": "directory",
        "path": "C:\\Program Files",
        "created": "2014-09-11T21:50:18.301Z",
        "modified": "2014-09-11T21:50:18.301Z",
        "accessed": "2014-09-11T21:50:18.301Z"
    },
    {
        "artifact": "WindowsRunKeys",
        "modified": "2013-11-19T22:46:05.668Z",
        "type": "windows-registry-key",
        "key": "HKEY_USERS\\S-1-5-21-7623811015-3361044348-030300820-1013\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    },
    {
        "artifact": "WindowsCodePage",
        "values": [
            {
                "data_type": "REG_SZ",
                "data": "1252",
                "name": "ACP"
            }
        ],
        "modified": "2009-07-14T04:34:14.225Z",
        "type": "windows-registry-key",
        "key": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Nls\\CodePage"
    },
    {
        "artifact": "WMILogicalDisks",
        "type": "process",
        "name": "powershell",
        "created": "2016-01-20T14:11:25.550Z",
        "cwd": "/root/",
        "arguments": [
            "gwmi",
            "-Query",
            "\"SELECT * FROM Win32_LogicalDisk\\\""
        ],
        "command_line": "powershell \"gwmi -Query \\\"SELECT * FROM Win32_LogicalDisk\\\"\"",
        "stdout_path": "WMILogicalDisks/stdout",
        "wmi_path": "WMILogicalDisks/wmi",
        "stderr_path": "WMILogicalDisks/stderr",
        "return_code": 0
    }
]
