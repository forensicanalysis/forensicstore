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

package goforensicstore

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/fatih/structs"
	"github.com/forensicanalysis/forensicstore/gostore"
)

var exampleStore = "/example1.forensicstore"

func setup(t *testing.T) string {
	dir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	input, err := ioutil.ReadFile("../test/forensicstore/example1.forensicstore/item.db")
	if err != nil {
		t.Fatal(err)
	}
	err = os.MkdirAll(dir+exampleStore, 0755)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(dir+exampleStore+"/item.db", input, 0644); err != nil {
		t.Fatal(err)
	}
	return dir + "/"
}

func teardown(t *testing.T) {
	files, err := ioutil.ReadDir(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range files {
		if strings.HasPrefix(f.Name(), t.Name()) {
			os.Remove(f.Name())
		}
	}
}

func TestForensicStore_InsertStruct(t *testing.T) {
	testDir := setup(t)
	defer teardown(t)

	myfile := NewFile()
	myfile.Name = "test.txt"

	myfile2 := struct {
		Type string
		Name int
	}{"file", 1}

	myfile3 := File{Type: "file"}

	type args struct {
		item interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{myfile}, false},
		{"wrong schema", args{myfile2}, true},
		{"empty file item", args{myfile3}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewJSONLite(testDir + exampleStore)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.InsertStruct(tt.args.item)
			if (err != nil) != tt.wantErr {
				t.Errorf("InsertStruct() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNew(t *testing.T) {
	tempDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		remoteURL string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"NewJSONLite", args{tempDir}, false},
		{"Wrong URL", args{"foo\x00bar"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJSONLite(tt.args.remoteURL)
			defer os.Remove(tt.args.remoteURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJSONLite() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_lower(t *testing.T) {
	type args struct {
		f interface{}
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{"Map", args{map[string]interface{}{"A": "B"}}, map[string]interface{}{"a": "B"}},
		{"List", args{[]interface{}{"A", "B"}}, []interface{}{"A", "B"}},
		{"Hash", args{map[string]interface{}{"MD5": "B"}}, map[string]interface{}{"MD5": "B"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lower(tt.args.f); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("lower() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isEmptyValue(t *testing.T) {
	var emptyInterface *int
	type args struct {
		v reflect.Value
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"List", args{reflect.ValueOf([]string{})}, true},
		{"Interface", args{reflect.ValueOf(emptyInterface)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEmptyValue(tt.args.v); got != tt.want {
				t.Errorf("isEmptyValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInsert(t *testing.T) {
	tempDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}

	var itemA map[string]interface{}
	itemA = gostore.Item{
		"accessed": "2020-01-30T08:44:59.558Z",
		"artifact": "WindowsDeviceSetup",
		"attributes": map[string]interface{}{
			"accessed": "2020-01-30T08:44:59.558Z",
			"changed":  "2019-08-28T11:34:06.643Z",
			"created":  "2019-03-19T10:49:31.871Z",
			"modified": "2019-08-28T11:34:06.643Z",
		},
		"created":     "2019-03-19T10:49:31.871Z",
		"export_path": "WindowsDeviceSetup/setupapi.dev.log",
		"hashes": map[string]interface{}{
			"MD5":   "6a2a8628bc16039ae82e0df591886115",
			"SHA-1": "0672fc8a0eae6996b46e25e2cf7867a0f414a9e7",
		},
		"id":       "file--72901201-8558-403a-80f2-9c0645c519f0",
		"modified": "2019-08-28T11:34:06.643Z",
		"name":     "setupapi.dev.log",
		"origin":   map[string]interface{}{"path": "/C/Windows/inf/setupapi.dev.log"},
		"size":     float64(340854),
		"type":     "file",
	}

	fileB := NewFile()
	fileB.Name = "foo.txt"
	fileB.Size = 340854

	itemB := structs.Map(fileB)
	itemB = lower(itemB).(map[string]interface{})

	fmt.Printf("%#v %s\n", itemA, reflect.TypeOf(itemA["size"]))
	fmt.Printf("%#v %s\n", itemB, reflect.TypeOf(itemB["size"]))

	type args struct {
		remoteURL string
		item      gostore.Item // *File //
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Insert valid item A", args{tempDir, itemA}, false},
		{"Insert valid item B", args{tempDir, itemB}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewJSONLite(tt.args.remoteURL)
			defer os.Remove(tt.args.remoteURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJSONLite() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			_, err = store.Insert(tt.args.item)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
