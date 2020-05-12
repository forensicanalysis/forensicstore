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
//     element      Edit the forensicstore (insert, get, select, all)
//     process   Process a workflow.yml
//     validate  Validate forensicstores
//
// Usage
//
// Create a forensicstore
//     forensicstore create my.forensicstore
// Insert and fetch elements
//     forensicstore element insert '{"type": "test", "foo": "bar"}' my.forensicstore
//     forensicstore element get foo--16b02a2b-d1a1-4e79-aad6-2f2c1c286818 my.forensicstore > myelement.json
//     forensicstore element select foo my.forensicstore > foo_export.json
//     forensicstore element all my.forensicstore > export.json
// Process forensicstore
//     forensicstore process --workflow myreports.yml my.forensicstore
//
// Validate forensictore
//     forensicstore validate my.forensicstore
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/forensicanalysis/forensicstore/cmd"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "forensicstore",
		Short: "Handle forensicstore files",
	}
	rootCmd.AddCommand(cmd.Element(), cmd.Create(), cmd.Validate())
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
