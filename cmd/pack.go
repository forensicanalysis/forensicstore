package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/forensicanalysis/forensicstore/sqlitefs"
	"github.com/forensicanalysis/fslib/aferotools/copy"
)

func Pack() *cobra.Command {
	return &cobra.Command{
		Use:   "pack <forensicstore> <file>...",
		Short: "Add files to the sqlite archive",
		Args:  cobra.MinimumNArgs(2), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			srcFS := afero.NewOsFs()
			destFS, err := sqlitefs.New(args[0])
			if err != nil {
				return err
			}
			defer destFS.Close()

			for _, arg := range args[1:] {
				fmt.Println("pack", filepath.ToSlash(arg))
				err = copy.Item(srcFS, destFS, arg, filepath.ToSlash(arg))
				if err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func Unpack() *cobra.Command {
	return &cobra.Command{
		Use:   "unpack <forensicstore>",
		Short: "Extract files from the sqlite archive",
		Args:  cobra.ExactArgs(1), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			srcFS, err := sqlitefs.New(args[0])
			if err != nil {
				return err
			}
			defer srcFS.Close()
			destFS := afero.NewOsFs()

			return afero.Walk(srcFS, "/", func(path string, info os.FileInfo, err error) error {
				if info == nil || info.IsDir() {
					return nil
				}
				fmt.Println("unpack", filepath.ToSlash(path[1:]))
				return copy.Item(srcFS, destFS, filepath.ToSlash(path), filepath.ToSlash(path[1:]))
			})
		},
	}
}

func Ls() *cobra.Command {
	return &cobra.Command{
		Use:   "ls <forensicstore>",
		Short: "List files in the sqlite archive",
		Args:  cobra.ExactArgs(1), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := sqlitefs.New(args[0])
			if err != nil {
				return err
			}
			defer fs.Close()

			return afero.Walk(fs, "/", func(path string, info os.FileInfo, err error) error {
				fmt.Println(filepath.ToSlash(path))
				return nil
			})
		},
	}
}
