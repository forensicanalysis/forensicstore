package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/forensicanalysis/forensicstore/cmd"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sqlargo",
		Short: "Use sqlite as an archive",
	}
	rootCmd.AddCommand(cmd.Pack(), cmd.Unpack(), cmd.Ls())
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
