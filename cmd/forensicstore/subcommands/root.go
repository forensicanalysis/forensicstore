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

package subcommands

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"os"
)

// Execute is the entrypoint for the forensicstore commandline tool.
func Execute() {
	rootCmd := rootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func rootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "forensicstore",
		Short: "Handle forensicstore files",
	}
	rootCmd.AddCommand(itemCommand()) //, serveCommand(), uiCommand())
	return rootCmd
}

func itemCommand() *cobra.Command {
	itemCommand := &cobra.Command{
		Use:   "item",
		Short: "Manipulate the forensicstore via the commandline",
		Args:  requireOneStore,
	}
	itemCommand.AddCommand(
		createCommand(), getCommand(), selectCommand(), allCommand(),
		insertCommand(), updateCommand(), importCommand(), validateCommand(),
	)
	return itemCommand
}

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
