/*
 * Copyright (c) 2020 Siemens AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Author(s): Jonas Plum
 */

package sqlitefs

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
)

func setup(t *testing.T) string {
	name := strings.ReplaceAll(t.Name(), "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	dir, err := ioutil.TempDir("", name)
	if err != nil {
		t.Fatal(err)
	}

	return dir
}

func cleanup(t *testing.T, directories ...string) {
	for _, directory := range directories {
		err := os.RemoveAll(directory)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func dummyFS(t *testing.T, dir string) (*FS, error) {
	// create database
	fs, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}

	// create file
	err = afero.WriteFile(fs, "/myfile1.txt", []byte(strings.Repeat("test", 1000)), 0666)
	if err != nil {
		t.Fatal(err)
	}

	// create directories
	err = fs.MkdirAll("/dir/subdir", 0666)
	if err != nil {
		t.Fatal(err)
	}

	// create 2. file
	err = afero.WriteFile(fs, "/dir/subdir/myfile2.txt", []byte("test2"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	return fs, err
}

func TestFS_Chmod(t *testing.T) {
	type args struct {
		name string
		mode os.FileMode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"set mode", args{name: "/myfile1.txt", mode: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			if err := fs.Chmod(tt.args.name, tt.args.mode); (err != nil) != tt.wantErr {
				t.Fatalf("Chmod() error = %v, wantErr %v", err, tt.wantErr)
			}

			info, err := fs.Stat(tt.args.name)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode() != tt.args.mode {
				t.Errorf("Chmod() error = got %v, want %v", info.Mode(), tt.args.mode)
			}
		})
	}
}

func TestFS_Chtimes(t *testing.T) {
	myTime := time.Now()

	type args struct {
		name  string
		atime time.Time
		mtime time.Time
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"set time", args{name: "/myfile1.txt", atime: myTime, mtime: myTime}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			if err := fs.Chtimes(tt.args.name, tt.args.atime, tt.args.mtime); (err != nil) != tt.wantErr {
				t.Errorf("Chtimes() error = %v, wantErr %v", err, tt.wantErr)
			}

			info, err := fs.Stat(tt.args.name)
			if err != nil {
				t.Fatal(err)
			}
			if info.ModTime().Unix() != tt.args.mtime.Unix() {
				t.Errorf("Chtimes() error = got %v, want %v", info.ModTime(), tt.args.mtime)
			}
		})
	}
}

func TestFS_Create(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"create file", args{"/f3.txt"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			got, err := fs.Create(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			exists, err := afero.Exists(fs, tt.args.name)
			if err != nil {
				t.Fatal(err)
			}

			if !exists {
				t.Fatal("file was not created")
			}

			err = got.Close()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFS_Mkdir(t *testing.T) {
	type args struct {
		name string
		perm os.FileMode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"mkdir", args{"/mydir", 0700}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			if err := fs.Mkdir(tt.args.name, tt.args.perm); (err != nil) != tt.wantErr {
				t.Errorf("Mkdir() error = %v, wantErr %v", err, tt.wantErr)
			}

			exists, err := afero.Exists(fs, tt.args.name)
			if err != nil {
				t.Fatal(err)
			}

			if !exists {
				t.Fatal("file was not created")
			}
		})
	}
}

func TestFS_MkdirAll(t *testing.T) {
	type args struct {
		p    string
		perm os.FileMode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"parent, child", args{"/foo/bar", 0700}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			if err := fs.MkdirAll(tt.args.p, tt.args.perm); (err != nil) != tt.wantErr {
				t.Errorf("MkdirAll() error = %v, wantErr %v", err, tt.wantErr)
			}

			parent, _ := path.Split(tt.args.p)
			exists, err := afero.Exists(fs, parent)
			if err != nil {
				t.Fatal(err)
			}
			if !exists {
				t.Fatalf("parent %s was not created", parent)
			}

			exists, err = afero.Exists(fs, tt.args.p)
			if err != nil {
				t.Fatal(err)
			}
			if !exists {
				t.Fatal("p was not created")
			}
		})
	}
}

func TestFS_Name(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"name", "SQLiteFS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			if got := fs.Name(); got != tt.want {
				t.Errorf("Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFS_Open(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"open", args{"/myfile1.txt"}, []byte(strings.Repeat("test", 1000)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			got, err := fs.Open(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			defer got.Close()

			b, err := afero.ReadAll(got)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(b, tt.want) {
				t.Errorf("Open() got = %v, want %v", b, tt.want)
			}
		})
	}
}

func TestFS_OpenFile(t *testing.T) {
	type args struct {
		name string
		flag int
		perm os.FileMode
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"open", args{"/myfile1.txt", 0, 0755}, []byte(strings.Repeat("test", 1000)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			got, err := fs.OpenFile(tt.args.name, tt.args.flag, tt.args.perm)
			if (err != nil) != tt.wantErr {
				t.Errorf("OpenFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			defer got.Close()

			b, err := afero.ReadAll(got)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(b, tt.want) {
				t.Errorf("OpenFile() got = %v, want %v", b, tt.want)
			}
		})
	}
}

func TestFS_Remove(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"remove", args{"/myfile1.txt"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			if err := fs.Remove(tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("Remove() error = %v, wantErr %v", err, tt.wantErr)
			}

			exists, err := afero.Exists(fs, tt.args.name)
			if err != nil {
				t.Fatal(err)
			}

			if exists {
				t.Fatal("file still exists")
			}
		})
	}
}

func TestFS_RemoveAll(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"removeall", args{"/dir"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			if err := fs.RemoveAll(tt.args.path); (err != nil) != tt.wantErr {
				t.Errorf("RemoveAll() error = %v, wantErr %v", err, tt.wantErr)
			}

			exists, err := afero.Exists(fs, tt.args.path)
			if err != nil {
				t.Fatal(err)
			}

			if exists {
				t.Fatal("file still exists")
			}
		})
	}
}

func TestFS_Rename(t *testing.T) {
	type args struct {
		oldname string
		newname string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"rename", args{"/myfile1.txt", "2.txt"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			if err := fs.Rename(tt.args.oldname, tt.args.newname); (err != nil) != tt.wantErr {
				t.Errorf("Rename() error = %v, wantErr %v", err, tt.wantErr)
			}

			exists, err := afero.Exists(fs, tt.args.oldname)
			if err != nil {
				t.Fatal(err)
			}

			if exists {
				t.Fatal("file still exists")
			}

			exists, err = afero.Exists(fs, tt.args.newname)
			if err != nil {
				t.Fatal(err)
			}

			if !exists {
				t.Fatal("file does not exist")
			}
		})
	}
}

func TestFS_Stat(t *testing.T) {
	info := Info{
		name:  "myfile1.txt",
		sz:    4000,
		mode:  0666,
		mtime: time.Time{},
		dir:   false,
	}
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    *Info
		wantErr bool
	}{
		{"stat", args{"/myfile1.txt"}, &info, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			got, err := fs.Stat(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("Stat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got.(*Info).mtime = time.Time{}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Stat() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileInfo_IsDir(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"dir", args{"/dir"}, true},
		{"file", args{"/myfile1.txt"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			i, err := fs.Stat(tt.args.name)
			if err != nil {
				t.Fatal(err)
			}

			if got := i.IsDir(); got != tt.want {
				t.Errorf("IsDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileInfo_ModTime(t *testing.T) {
	mytime := time.Now()

	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want time.Time
	}{
		{"/dir", args{"/dir"}, mytime},
		{"file", args{"/myfile1.txt"}, mytime},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			fs.Chtimes(tt.args.name, mytime, mytime)

			i, err := fs.Stat(tt.args.name)
			if err != nil {
				t.Fatal(err)
			}

			if got := i.ModTime(); !reflect.DeepEqual(got.Unix(), tt.want.Unix()) {
				t.Errorf("ModTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileInfo_Mode(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want os.FileMode
	}{
		{"/dir", args{"/dir"}, 0666},
		{"file", args{"/myfile1.txt"}, 0666},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			i, err := fs.Stat(tt.args.name)
			if err != nil {
				t.Fatal(err)
			}

			if got := i.Mode(); got != tt.want {
				t.Errorf("Mode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileInfo_Name(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
	}{
		{"dir", args{"/dir"}},
		{"file", args{"/myfile1.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			i, err := fs.Stat(tt.args.name)
			if err != nil {
				t.Fatal(err)
			}

			if got := i.Name(); got != path.Base(tt.args.name) {
				t.Errorf("Name() = %v, want %v", got, path.Base(tt.args.name))
			}
		})
	}
}

func TestFileInfo_Size(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{"dir", args{"/dir"}, 0},
		{"file", args{"/myfile1.txt"}, 4000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			i, err := fs.Stat(tt.args.name)
			if err != nil {
				t.Fatal(err)
			}

			if got := i.Size(); got != tt.want {
				t.Errorf("Size() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileInfo_Sys(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{"dir", args{"/dir"}, nil},
		{"file", args{"/myfile1.txt"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := setup(t)
			defer cleanup(t, tempDir)
			fs, err := dummyFS(t, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			i, err := fs.Stat(tt.args.name)
			if err != nil {
				t.Fatal(err)
			}

			if got := i.Sys(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sys() = %v, want %v", got, tt.want)
			}
		})
	}
}
