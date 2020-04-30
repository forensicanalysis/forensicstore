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
  # echo $TESTDIR
}

@test "forensicstore validate insert invalid element" {
    run forensicstore create $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    run forensicstore element insert '{"type": "file", "foo": "bar"}' $TESTDIR/tmp.forensicstore
    echo $output
    skip "TODO: Fix error output"
    [ "$output" = "foo: invalid element" ]
}

@test "forensicstore validate parent file" {
    run forensicstore create $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    run forensicstore element insert '{"type": "foo", "foo_path": "../bar"}' $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    forensicstore validate --no-fail $TESTDIR/tmp.forensicstore > $TESTDIR/tmp.json

    run cat $TESTDIR/tmp.json
    echo $output

    run jq '. | length' $TESTDIR/tmp.json
    echo $output
    [ "$output" = "1" ]

    run jq '.[0]' $TESTDIR/tmp.json
    echo $output
    [ "$output" = "\"'..' in ../bar\"" ]
}

@test "forensicstore validate missing file" {
    run forensicstore create $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    run forensicstore element insert '{"type": "foo", "foo_path": "bar"}' $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    forensicstore validate --no-fail $TESTDIR/tmp.forensicstore > $TESTDIR/tmp.json
    run jq '. | length' $TESTDIR/tmp.json
    echo $output
    [ "$output" = "1" ]

    run jq '.[0]' $TESTDIR/tmp.json
    echo $output
    [ "$output" = "\"missing files: ('/bar')\"" ]
}

@test "forensicstore validate additional file" {
    run forensicstore create $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    run touch $TESTDIR/tmp.forensicstore/bar
    echo $output
    [ "$status" -eq 0 ]

    forensicstore validate --no-fail $TESTDIR/tmp.forensicstore > $TESTDIR/tmp.json
    run jq '. | length' $TESTDIR/tmp.json
    echo $output
    [ "$output" = "1" ]

    run jq '.[0]' $TESTDIR/tmp.json
    echo $output
    [ "$output" = "\"additional files: ('/bar')\"" ]
}

@test "forensicstore validate wrong size" {
    run forensicstore create $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    run echo 'aaa' > $TESTDIR/tmp.forensicstore/bar
    echo $output
    [ "$status" -eq 0 ]

    run forensicstore element insert '{"type": "foo", "foo_path": "bar", "size": 2}' $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    forensicstore validate --no-fail $TESTDIR/tmp.forensicstore
    forensicstore validate --no-fail $TESTDIR/tmp.forensicstore > $TESTDIR/tmp.json

    run cat $TESTDIR/tmp.json
    echo $output
    [ "$status" -eq 0 ]

    run jq '. | length' $TESTDIR/tmp.json
    echo $output
    [ "$output" = "1" ]

    run jq '.[0]' $TESTDIR/tmp.json
    echo $output
    [[ "$output" == *"wrong size for bar"* ]]
}


@test "forensicstore validate wrong hash" {
    run forensicstore create $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    run echo 'aaa' > $TESTDIR/tmp.forensicstore/bar
    echo $output
    [ "$status" -eq 0 ]

    run forensicstore element insert '{"type": "foo", "foo_path": "bar", "hashes": {"MD5": "165565004ed5a3a4310615b7f68a9da9"}}' $TESTDIR/tmp.forensicstore
    echo $output
    [ "$status" -eq 0 ]

    forensicstore validate --no-fail $TESTDIR/tmp.forensicstore > $TESTDIR/tmp.json

    run cat $TESTDIR/tmp.json
    echo $output
    [ "$status" -eq 0 ]


    run jq '. | length' $TESTDIR/tmp.json
    echo $output
    [ "$output" = "1" ]

    run jq '.[0]' $TESTDIR/tmp.json
    echo $output
    [ "$output" = "\"hashvalue mismatch MD5 for bar\"" ]
}
