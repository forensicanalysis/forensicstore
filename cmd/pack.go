// Copyright (c) 2020 Siemens AG
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
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"

	"github.com/forensicanalysis/forensicstore"
	"github.com/forensicanalysis/forensicstore/sqlitefs"
	"github.com/forensicanalysis/fslib/aferotools/copy"
	"github.com/forensicanalysis/fslib/forensicfs/glob"
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

func first(s string, n int) string {
	if len(s) < n {
		n = len(s)
	}
	return s[:n]
}

func last(s string, n int) string {
	if len(s) < n {
		n = len(s)
	}
	return s[len(s)-n:]
}

func splitExt(filePath string) (nameOnly, ext string) {
	ext = path.Ext(filePath)
	nameOnly = filePath[:len(filePath)-len(ext)-1]
	return nameOnly, ext
}

func normalizeFilePath(filePath string) string {
	maxLength := 64
	maxSegmentLength := 4
	filePath = strings.TrimLeft(filePath, "/")
	pathSegments := strings.Split(filePath, "/")
	normalizedFilePath := strings.Join(pathSegments, "_")

	// get first 4 letters of every directory, while longer than maxLength
	for i := 0; i < len(pathSegments)-1 && len(normalizedFilePath) > maxLength; i++ {
		pathSegments[i] = first(pathSegments[i], maxSegmentLength)
		normalizedFilePath = strings.Join(pathSegments, "_")
	}

	if len(normalizedFilePath) > maxLength {
		// if still to long get first maxSegmentLength letters of filename + extension
		nameOnly, ext := splitExt(pathSegments[len(pathSegments)-1])
		pathSegments[len(pathSegments)-1] = first(nameOnly, maxSegmentLength) + ext
		normalizedFilePath = strings.Join(pathSegments, "_")
	}

	return last(normalizedFilePath, maxLength)
}

// artifact := map[string]string{}
// query := `SELECT
// 	name,
// 	json_extract(json, '$.artifact') AS artifact
// FROM
// 	sqlar
// LEFT JOIN elements
// 	ON (sqlar.name = "/"||json_extract(elements.json, '$.export_path'))
// WHERE
// 	sqlar.data IS NOT NULL
// 	AND artifact IS NOT NULL`

func Unpack() *cobra.Command {
	var prefix bool
	var mode, pattern string
	unpackCmd := &cobra.Command{
		Use:   "unpack <forensicstore>",
		Short: "Extract files from the sqlite archive",
		Args:  cobra.ExactArgs(1), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			store, srcFS, teardown, err := setupSource(prefix, args)
			if err != nil {
				return err
			}
			defer teardown()

			destFS := afero.NewOsFs()

			return afero.Walk(srcFS, "/", func(srcPath string, info os.FileInfo, err error) error {
				if err != nil {
					log.Println(err)
					return err
				}
				if info == nil || info.IsDir() {
					return nil
				}

				fullPath := filepath.ToSlash(srcPath)
				if pattern != "" {
					match, err := glob.Match("**100/"+pattern, fullPath)
					if err != nil {
						return err
					}
					if !match {
						return nil
					}
				}

				dest, err := destinationPath(fullPath, mode, store)
				if err != nil {
					return err
				}

				fmt.Printf("unpack '%s' to '%s'\n", fullPath, dest)
				return copy.Item(srcFS, destFS, fullPath, dest)
			})
		},
	}

	usage := `define the export filename and folder structure. can be one of:
folder (e.g. 'C/Users/user/AppData/Local/Google/Chrome/User Data/Default/Extensions/xx/1.11_1/example.json')
compact (e.g. 'C_User_user_AppD_Loca_Goog_Chro_User_Defa_Exte_xx_1.11_exam.json')
basename (e.g. 'example.json')
`
	unpackCmd.Flags().StringVar(&mode, "mode", "compact", usage)
	usage = `create a folder for every artifact (e.g. 'ChromeExtensions/example.json')`
	unpackCmd.Flags().BoolVar(&prefix, "prefix-artifact", true, usage)
	unpackCmd.Flags().StringVar(&pattern, "match", "", "only unpack files matching the pattern")

	return unpackCmd
}

func setupSource(prefix bool, args []string) (*forensicstore.ForensicStore, afero.Fs, func() error, error) {
	if prefix {
		s, teardown, err := forensicstore.Open(args[0])
		if err != nil {
			return nil, nil, nil, err
		}
		return s, s.Fs, teardown, nil
	}
	srcFS, err := sqlitefs.New(args[0])
	if err != nil {
		return nil, nil, nil, err
	}
	return nil, srcFS, srcFS.Close, err
}

func destinationPath(fullPath string, mode string, store *forensicstore.ForensicStore) (string, error) {
	var dest string
	switch mode {
	case "basename":
		dest = path.Base(fullPath)
	case "folder":
		dest = fullPath[1:]
	case "compact":
		fallthrough
	default:
		dest = normalizeFilePath(fullPath)
	}

	if store != nil {
		artifactName, err := artifactByPath(store, fullPath)
		if err != nil {
			return "", err
		}
		dest = path.Join(artifactName, dest)
	}
	return dest, nil
}

func artifactByPath(store *forensicstore.ForensicStore, srcPath string) (string, error) {
	elements, err := store.Select([]map[string]string{
		{"export_path": strings.TrimLeft(srcPath, "/")},
		{"stdout_path": strings.TrimLeft(srcPath, "/")},
		{"stderr_path": strings.TrimLeft(srcPath, "/")},
	})
	if err != nil {
		return "", err
	}
	if len(elements) > 0 {
		artifact := gjson.GetBytes(elements[0], "artifact")
		if artifact.Exists() {
			return artifact.String(), nil
		}
	}
	return "", nil
}

func Ls() *cobra.Command {
	var pattern string
	lsCmd := &cobra.Command{
		Use:   "ls <forensicstore>",
		Short: "List files in the sqlite archive",
		Args:  cobra.ExactArgs(1), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := sqlitefs.New(args[0])
			if err != nil {
				return err
			}
			defer fs.Close()

			pattern = "**100/" + pattern
			return afero.Walk(fs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				path = filepath.ToSlash(path)

				if pattern != "" {
					match, err := glob.Match(pattern, path)
					if err != nil {
						return err
					}
					if !match {
						return nil
					}
				}
				fmt.Println(path)
				return nil
			})
		},
	}
	lsCmd.Flags().StringVar(&pattern, "match", "", "only unpack files matching the pattern")
	return lsCmd
}
