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

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/forensicanalysis/forensicstore"
)

// Create is the forensicstore create commandline subcommand
func Create() *cobra.Command {
	return &cobra.Command{
		Use:   "create",
		Short: "Create a forensicstore",
		RunE: func(cmd *cobra.Command, args []string) error {
			storeName := cmd.Flags().Args()[0]
			store, err := forensicstore.New(storeName)
			if err != nil {
				return err
			}
			return store.Close()
		},
	}
}

// Element is the forensicstore element commandline subcommand
func Element() *cobra.Command {
	elementCommand := &cobra.Command{
		Use:   "element",
		Short: "Manipulate the forensicstore via the commandline",
		Args:  requireOneStore,
	}
	elementCommand.AddCommand(getCommand(), selectCommand(), allCommand(),
		insertCommand(), updateCommand())
	return elementCommand
}

// Validate is the forensicstore validate commandline subcommand
func Validate() *cobra.Command {
	var noFail bool
	validateCommand := &cobra.Command{
		Use:   "validate",
		Short: "Validate all elements",
		RunE: func(cmd *cobra.Command, args []string) error {
			storeName := cmd.Flags().Args()[0]

			store, err := forensicstore.New(storeName)
			if err != nil {
				fmt.Println(err)
				return err
			}
			defer store.Close()
			valErr, err := store.Validate()
			if err != nil {
				fmt.Println(err)
				return err
			}
			if len(valErr) > 0 {
				for i, v := range valErr {
					valErr[i] = strings.Replace(v, "\"", "\\\"", -1)
				}
				fmt.Printf("[\"%s\"]\n", strings.Join(valErr, "\", \""))
				if noFail {
					return nil
				}
				return err
			}
			return nil
		},
	}
	validateCommand.Flags().BoolVar(&noFail, "no-fail", false, "return exit code 0")
	return validateCommand
}

/*
func serveCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "serve",
		Aliases: []string{"server", "http"},
		Short:   "Run a http(s) API and serve the forensicstore",
		Args:    requireOneStore,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("serve called")
		},
	}
}

func uiCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "ui",
		Aliases: []string{"show"},
		Short:   "Start the forensicstore desktop app",
		Args:    requireOneStore,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("ui called")
		},
	}
}
*/

func requireOneStore(_ *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("requires exactly one store")
	}
	for _, arg := range args {
		if _, err := os.Stat(arg); os.IsNotExist(err) {
			return errors.Wrap(os.ErrNotExist, arg)
		}
	}
	return nil
}
