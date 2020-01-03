// Copyright (c) 2019 Siemens AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Author(s): Jonas Plum

// Package forensicstore implements the forensicstore command line tool with
// various subcommands that can be used to edit and handle forensicstores.
//     create    Create a forensicstore
//     import    Import another forensicstore or stix json
//     item      Edit the forensicstore (insert, get, select, all)
//     process   Process a workflow.yml
//     serve     Run a http(s) API and serve the forensicstore
//     ui        Start the forensicstore desktop app
//     validate  Validate forensicstores
//
// Usage
//
// Create a forensicstore
//     forensicstore create my.forensicstore
// Insert and fetch items
//     forensicstore item insert '{"type": "test", "foo": "bar"}' my.forensicstore
//     forensicstore item get foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286818 my.forensicstore > myitem.json
//     forensicstore item select foo my.forensicstore > foo_export.json
//     forensicstore item all my.forensicstore > export.json
// Process forensicstore
//     forensicstore process --workflow myreports.yml my.forensicstore
// Serve forensicstore
//     forensicstore serve --port=8080 my.forensicstore
//
//     curl -X POST -H "Content-Type: application/json" -d '{"type": "test", "foo": "bar"}' \
//       localhost:8080/
//
//     curl localhost:8080/foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286818
//
//     curl localhost:8080/foo
//
//     curl localhost:8080/?per_page=10&page=2
// Browse forensicstore
//     forensicstore ui
// Validate forensictore
//     forensicstore validate my.forensicstore
package main

import "github.com/forensicanalysis/forensicstore/cmd/forensicstore/subcommands"

//go:generate resources -declare -var=FS -package assets -output subcommands/process/assets/assets.go subcommands/process/script/* subcommands/process/script/templates/*

func main() {
	subcommands.Execute()
}
