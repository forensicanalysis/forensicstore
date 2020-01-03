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
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
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

	myfile := File{
		Name: "test",
		Type: "file",
	}

	type fields struct {
		Items []interface{}
	}
	type args struct {
		item interface{}
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{"Insert Struct", fields{}, args{myfile}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewJSONLite(testDir + exampleStore)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.InsertStruct(tt.args.item)
			if err != nil {
				t.Fatal(err)
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
