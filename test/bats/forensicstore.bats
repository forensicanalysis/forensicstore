#!/usr/bin/env bats
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


setup() {
  TESTDIR=$BATS_TMPDIR/bats/$BATS_TEST_NUMBER
  mkdir -p $TESTDIR
}

teardown() {
  rm -rf $TESTDIR
}

@test "forensicstore create" {
  run forensicstore create $TESTDIR/init_create.forensicstore
  echo $output
  [ "$status" -eq 0 ]
  forensicstore validate $TESTDIR/init_create.forensicstore

  [ -f "$TESTDIR/init_create.forensicstore" ]
}

@test "forensicstore load not existing" {
    run forensicstore element get process--920d7c41-0fef-4cf8-bce2-ead120f6b506 $TESTDIR/not_existing.forensicstore
    [ "$status" -ne 0 ]
    skip "TODO: Fix error output"
    [ "$output" = "foo: no such file 'nonexistent_filename'" ]
}

@test "forensicstore get" {
    forensicstore element get process--920d7c41-0fef-4cf8-bce2-ead120f6b506 test/forensicstore/example1.forensicstore > $TESTDIR/a.json

    echo '{"id": "process--920d7c41-0fef-4cf8-bce2-ead120f6b506", "artifact": "IPTablesRules", "type": "process", "name": "iptables", "created_time": "2016-01-20T14:11:25.550Z", "cwd": "/root/", "command_line": "/sbin/iptables -L -n -v", "stdout_path": "IPTablesRules/stdout", "stderr_path": "IPTablesRules/stderr", "return_code": 0}' > $TESTDIR/b.json

    echo "a"
    run cat $TESTDIR/a.json
    echo $output

    echo "b"
    run cat $TESTDIR/b.json
    echo $output

    run diff <(jq -S . $TESTDIR/a.json) <(jq -S . $TESTDIR/b.json)
    echo $output
    [ "$status" -eq 0 ]
}

@test "forensicstore get non existing element" {
    run forensicstore element get process--16b02a2b-d1a1-4e79-aad6-2f2c1c286818 test/forensicstore/example1.forensicstore
    [ "$status" -ne 0 ]
    skip "TODO: Fix error output"
    [ "$output" = "foo: no such process '1337'" ]
}

@test "forensicstore select" {
    forensicstore element select file test/forensicstore/example1.forensicstore > $TESTDIR/all.json

    run jq '. | length' $TESTDIR/all.json
    [ "$output" = '2' ]
}

@test "forensicstore all" {
    forensicstore element all test/forensicstore/example1.forensicstore > $TESTDIR/all.json

    run jq '. | length' $TESTDIR/all.json
    [ "$output" = '7' ]
}

@test "forensicstore insert" {
    cp -R test/forensicstore/. $TESTDIR/
    run forensicstore element insert '{"type": "foo", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' $TESTDIR/example1.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    run forensicstore element all $TESTDIR/example1.forensicstore
    echo $output

    # 8 elements should be in the store now
    forensicstore element all $TESTDIR/example1.forensicstore > $TESTDIR/all.json
    run jq '. | length' $TESTDIR/all.json
    [ "$status" -eq 0 ]
    [ "$output" = '8' ]

    # verify inserted element with id
    forensicstore element get foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817 $TESTDIR/example1.forensicstore > $TESTDIR/a.json

    echo '{"type": "foo", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' > $TESTDIR/b.json

    run diff <(jq -S . $TESTDIR/a.json) <(jq -S . $TESTDIR/b.json)
    [ "$status" -eq 0 ]
}

@test "forensicstore insert new field" {
    cp -R test/forensicstore/. $TESTDIR/
    run forensicstore element insert '{"type": "foo", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' $TESTDIR/example1.forensicstore
    [ "$status" -eq 0 ]

    run forensicstore element insert '{"type": "foo", "foo": "bar", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286818"}' $TESTDIR/example1.forensicstore
    [ "$status" -eq 0 ]

    # 8 elements should be in the store now
    forensicstore element all $TESTDIR/example1.forensicstore > $TESTDIR/all.json
    run jq '. | length' $TESTDIR/all.json
    [ "$status" -eq 0 ]
    [ "$output" = '9' ]

    # verify inserted element with id 10
    forensicstore element get foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817 $TESTDIR/example1.forensicstore > $TESTDIR/a.json

    echo '{"type": "foo", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' > $TESTDIR/b.json

    run diff <(jq -S . $TESTDIR/a.json) <(jq -S . $TESTDIR/b.json)
    echo $output
    [ "$status" -eq 0 ]

    # verify inserted element with id 11
    forensicstore element get foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286818 $TESTDIR/example1.forensicstore > $TESTDIR/a.json

    echo '{"type": "foo", "foo": "bar", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286818"}' > $TESTDIR/b.json

    run diff <(jq -S . $TESTDIR/a.json) <(jq -S . $TESTDIR/b.json)
    [ "$status" -eq 0 ]
}

@test "forensicstore insert int 0" {
    cp -R test/forensicstore/. $TESTDIR/
    run forensicstore element insert '{"type": "foo", "size": 0, "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' $TESTDIR/example1.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    # 8 elements should be in the store now
    forensicstore element all $TESTDIR/example1.forensicstore > $TESTDIR/all.json
    run jq '. | length' $TESTDIR/all.json
    [ "$status" -eq 0 ]
    [ "$output" = '8' ]

    # verify inserted element with id 10
    forensicstore element get foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817 $TESTDIR/example1.forensicstore > $TESTDIR/a.json

    echo '{"type": "foo", "size": 0, "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' > $TESTDIR/b.json

    run diff <(jq -S . $TESTDIR/a.json) <(jq -S . $TESTDIR/b.json)
    [ "$status" -eq 0 ]
}

@test "forensicstore insert empty list" {
    cp -R test/forensicstore/. $TESTDIR/
    run forensicstore element insert '{"type": "foo", "list": [], "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' $TESTDIR/example1.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    # 8 elements should be in the store now
    forensicstore element all $TESTDIR/example1.forensicstore > $TESTDIR/all.json
    run jq '. | length' $TESTDIR/all.json
    [ "$status" -eq 0 ]
    [ "$output" = '8' ]

    # verify inserted element with id 10
    forensicstore element get foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817 $TESTDIR/example1.forensicstore > $TESTDIR/a.json

    echo '{"type": "foo", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' > $TESTDIR/b.json

    run diff <(jq -S . $TESTDIR/a.json) <(jq -S . $TESTDIR/b.json)
    [ "$status" -eq 0 ]
}

@test "forensicstore insert element with none value" {
    cp -R test/forensicstore/. $TESTDIR/
    run forensicstore element insert '{"type": "foo", "list": null, "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' $TESTDIR/example1.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    # 8 elements should be in the store now
    forensicstore element all $TESTDIR/example1.forensicstore > $TESTDIR/all.json
    run jq '. | length' $TESTDIR/all.json
    [ "$status" -eq 0 ]
    [ "$output" = '8' ]

    # verify inserted element with id 10
    forensicstore element get foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817 $TESTDIR/example1.forensicstore > $TESTDIR/a.json

    echo '{"type": "foo", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' > $TESTDIR/b.json

    run diff <(jq -S . $TESTDIR/a.json) <(jq -S . $TESTDIR/b.json)
    [ "$status" -eq 0 ]
}

@test "forensicstore insert element with empty value" {
    cp -R test/forensicstore/. $TESTDIR/
    run forensicstore element insert '{"type": "file", "name": "foo.txt", "created": "", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' $TESTDIR/example1.forensicstore
    echo $output
    [ "$status" -ne 0 ]
    skip "TODO: Fix error output"
    [ "$output" = "foo: invalid element" ]
}

# @test "forensicstore update" {
#     cp -R test/forensicstore/. $TESTDIR/
#     forensicstore element update process--920d7c41-0fef-4cf8-bce2-ead120f6b506 '{"name": "foo"}' $TESTDIR/example1.forensicstore

#     forensicstore element get process--920d7c41-0fef-4cf8-bce2-ead120f6b506 $TESTDIR/example1.forensicstore > $TESTDIR/a.json

#     echo '{"id": "process--920d7c41-0fef-4cf8-bce2-ead120f6b506", "artifact": "IPTablesRules", "type": "process", "name": "foo", "created_time": "2016-01-20T14:11:25.550Z", "cwd": "/root/", "command_line": "/sbin/iptables -L -n -v", "stdout_path": "IPTablesRules/stdout", "stderr_path": "IPTablesRules/stderr", "return_code": 0}' > $TESTDIR/b.json

#     run diff <(jq -S . $TESTDIR/a.json) <(jq -S . $TESTDIR/b.json)
#     [ "$status" -eq 0 ]
# }

# @test "forensicstore import forensicstore" {
#     mkdir $TESTDIR/1
#     forensicstore create $TESTDIR/1/tmp.forensicstore
#
#     echo 'aaa' > $TESTDIR/1/tmp.forensicstore/testfile.txt
#     forensicstore element insert '{"type": "foo", "export_path": "testfile.txt", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286817"}' $TESTDIR/1/tmp.forensicstore
#
#     mkdir $TESTDIR/2
#     forensicstore create $TESTDIR/2/tmp.forensicstore
#     echo 'bbb' > $TESTDIR/2/tmp.forensicstore/testfile.txt
#     forensicstore element insert '{"type": "foo", "export_path": "testfile.txt", "id": "foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286818"}' $TESTDIR/2/tmp.forensicstore
#
#     forensicstore import $TESTDIR/2/tmp.forensicstore $TESTDIR/1/tmp.forensicstore
#
#     run cat $TESTDIR/1/tmp.forensicstore/testfile.txt
#     echo $output
#     [ "$output" = "aaa" ]
#
#     run cat $TESTDIR/1/tmp.forensicstore/testfile_0.txt
#     echo $output
#     [ "$output" = "bbb" ]
# }

# @test "forensicstore insert quotes" {
#     forensicstore create $TESTDIR/quotes.forensicstore
#     forensicstore element insert '{"type": "foo"}' 10 $TESTDIR/quotes.forensicstore
#     forensicstore element update foo 10 '{"foo": "@\\"%ProgramFiles%\\\\Windows Journal\\\\Journal.exe\\",-3072"}' $TESTDIR/quotes.forensicstore

#     # verify inserted element with id 10
#     forensicstore element get foo 10 $TESTDIR/quotes.forensicstore > $TESTDIR/elem.json
#     run jq '.["foo"]' $TESTDIR/elem.json
#     [ "$status" -eq 0 ]
#     echo "asd"
#     echo $output
#     echo "asda"
#     [ "$output" = '@"%ProgramFiles%\\Windows Journal\\Journal.exe",-3072' ]
# }
