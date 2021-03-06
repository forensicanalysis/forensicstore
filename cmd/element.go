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

	"github.com/spf13/cobra"

	"github.com/forensicanalysis/forensicstore"
)

func getCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get <id> <forensicstore>",
		Short: "Retrieve a single element",
		Args:  cobra.ExactArgs(2), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			id := cmd.Flags().Args()[0]
			storeName := cmd.Flags().Args()[1]
			store, teardown, err := forensicstore.Open(storeName)
			if err != nil {
				return err
			}
			defer teardown()
			elements, err := store.Get(id)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", elements)
			return nil
		},
	}
}

func selectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "select <type> <forensicstore>",
		Short: "Retrieve a list of all elements of a specific type",
		Args:  cobra.ExactArgs(2), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			elementType := cmd.Flags().Args()[0]
			storeName := cmd.Flags().Args()[1]
			store, teardown, err := forensicstore.Open(storeName)
			if err != nil {
				return err
			}
			defer teardown()
			elements, err := store.Select([]map[string]string{{"type": elementType}})
			if err != nil {
				return err
			}
			printElements(elements)
			return nil
		},
	}
}

func allCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "all <forensicstore>",
		Short: "Retrieve all elements",
		Args:  cobra.ExactArgs(1), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			storeName := cmd.Flags().Args()[0]
			store, teardown, err := forensicstore.Open(storeName)
			if err != nil {
				return err
			}
			defer teardown()
			elements, err := store.All()
			if err != nil {
				return err
			}
			printElements(elements)
			return nil
		},
	}
}

func insertCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "insert <json> <forensicstore>",
		Short: "Insert an element",
		Args:  cobra.ExactArgs(2), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonData := cmd.Flags().Args()[0]
			storeName := cmd.Flags().Args()[1]
			store, teardown, err := forensicstore.Open(storeName)
			if err != nil {
				fmt.Println(err)
				return err
			}
			defer teardown()

			elementID, err := store.Insert([]byte(jsonData))
			if err != nil {
				fmt.Println(err)
				return err
			}
			fmt.Printf("%s\n", elementID)
			return nil
		},
	}
}

func printElements(elements []forensicstore.JSONElement) {
	fmt.Print("[")
	for i, element := range elements {
		if i != 0 {
			fmt.Print(",")
		}
		fmt.Print(string(element))
	}
	fmt.Print("]")
}
