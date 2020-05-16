package cmd

import (
	"fmt"
	"io"
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
	var mode string
	unpackCmd := &cobra.Command{
		Use:   "unpack <forensicstore>",
		Short: "Extract files from the sqlite archive",
		Args:  cobra.ExactArgs(1), //nolint:gomnd
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			var srcFS afero.Fs
			var store *forensicstore.ForensicStore
			if prefix {
				s, teardown, err := forensicstore.Open(args[0])
				if err != nil {
					return err
				}
				store = s
				srcFS = s.Fs
				defer teardown()
			} else {
				srcFS, err = sqlitefs.New(args[0])
				if err != nil {
					return err
				}
				defer srcFS.(io.Closer).Close()
			}

			destFS := afero.NewOsFs()

			return afero.Walk(srcFS, "/", func(srcPath string, info os.FileInfo, err error) error {
				if err != nil {
					log.Println(err)
				}
				if err != nil || info == nil || info.IsDir() {
					return nil
				}

				fullPath := filepath.ToSlash(srcPath)
				dest, err := destinationPath(fullPath, mode, prefix, store)
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
	usage = `create a folder for every artifact (e.g. 'ChromeExtensions/example.json')
`
	unpackCmd.Flags().BoolVar(&prefix, "prefix-artifact", true, usage)

	return unpackCmd
}

func destinationPath(fullPath string, mode string, prefix bool, store *forensicstore.ForensicStore) (string, error) {
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

	if prefix {
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
