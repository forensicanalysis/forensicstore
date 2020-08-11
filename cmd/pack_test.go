package cmd

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestPack(t *testing.T) {
	dir, storePath := setup(t)
	defer os.RemoveAll(dir)

	tests := []struct {
		name string
	}{
		{"pack"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ioutil.WriteFile(filepath.Join(dir, "test.file"), []byte("foobar"), os.ModePerm); err != nil {
				t.Fatal(err)
			}

			if err := os.Chdir(dir); err != nil {
				t.Fatal(err)
			}

			packCmd := Pack()
			if err := packCmd.RunE(packCmd, []string{storePath, filepath.Join(dir, "test.file")}); err != nil {
				t.Fatal(err)
			}

			if err := os.Remove(filepath.Join(dir, "test.file")); err != nil {
				t.Fatal(err)
			}

			unpackCmd := Unpack()
			unpackCmd.Flags().Set("mode", "basename")
			unpackCmd.Flags().Set("prefix-artifact", "false")
			if err := unpackCmd.RunE(unpackCmd, []string{storePath}); err != nil {
				t.Fatal(err)
			}

			b, err := ioutil.ReadFile(filepath.Join(dir, "test.file"))
			if err != nil {
				t.Fatal(err)
			}

			if string(b) != "foobar" {
				t.Fatal("not equal")
			}
		})
	}
}
